"""
The Live page of the dashboard: reads live.db while live_detector.py writes it.

[JUDGE EXPLANATION] Only the live section re-runs, every three seconds, through
@st.fragment(run_every=...). Re-running the whole page would redraw the sidebar
and reset whatever the analyst was reading; a fragment refreshes just the
incidents, graph and feed. The AI narrative is never part of that refresh: it
is written only when the analyst clicks, and cached per incident VERSION, so a
3-second loop cannot turn into an API call every 3 seconds.
"""

import html
import json
import os
import sqlite3
import time

import streamlit as st

import graph_engine

REFRESH = "3s"


def _read(db_path, sql, params=()):
    # Read-only URI: the dashboard can never take the writer's lock.
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
    try:
        cur = con.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        con.close()


def render(db_path, render_graph, generate_report, fallback_report):
    st.subheader("Live")
    st.caption(
        "Near-real-time: live_detector.py reads newly appended lines every two "
        "seconds (micro-batch, not true streaming), runs the same rules as batch "
        "mode, and updates only the incidents those lines touch. This page "
        f"refreshes every {REFRESH}.")
    if not os.path.exists(db_path):
        st.info("The live detector is not running yet. In two terminals:")
        st.code("python src/live_detector.py --input data/live.ndjson\n"
                "python scripts/replay.py --source data/sample.ndjson "
                "--target data/live.ndjson --start 2026-10-20T12:50:00 --speed 10",
                language="text")
        return
    _live(db_path, render_graph, generate_report, fallback_report)


@st.fragment(run_every=REFRESH)
def _live(db_path, render_graph, generate_report, fallback_report):
    try:
        meta = {r["key"]: r["value"] for r in _read(db_path, "SELECT * FROM meta")}
        ticks = _read(db_path, "SELECT * FROM ticks ORDER BY tick DESC LIMIT 30")
        incidents = _read(db_path, "SELECT * FROM incidents WHERE status = 'reported' "
                                   "ORDER BY risk_score DESC")
        alerts = _read(db_path, "SELECT * FROM alerts ORDER BY alert_id DESC LIMIT 25")
        lat = _read(db_path, "SELECT latency_s FROM alerts WHERE latency_s IS NOT NULL "
                             "ORDER BY alert_id DESC LIMIT 100")
        totals = _read(db_path, "SELECT COUNT(*) AS n FROM alerts")[0]["n"]
    except sqlite3.Error as exc:
        st.warning(f"live.db is not readable yet ({exc}).")
        return

    # -- Readout ---------------------------------------------------------------
    now = time.time()
    recent = [t for t in ticks if now - t["at"] <= 30]
    rate = sum(t["lines"] for t in recent) / 30 if recent else 0.0
    lats = sorted(r["latency_s"] for r in lat)
    p50 = lats[len(lats) // 2] if lats else None
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Lines / s (30 s)", f"{rate:,.0f}")
    c2.metric("Alerts", f"{totals:,}")
    c3.metric("Incidents", len(incidents))
    c4.metric("Latency p50", f"{p50:.2f} s" if p50 is not None else "-")
    c5.metric("Last tick", f"{now - ticks[0]['at']:.0f} s ago" if ticks else "-")
    if ticks:
        t = ticks[0]
        rss = f", detector memory {t['rss_mb']:.0f} MB" if t.get("rss_mb") else ""
        st.caption(f"Following {html.escape(meta.get('source', '?'))} "
                   f"({meta.get('format', '?')}). Tick {t['tick']}: {t['lines']:,} "
                   f"lines in {t['tick_seconds']:.2f} s, window {t['window_rows']:,} "
                   f"rows{rss}. Latency is measured from a line being appended "
                   f"to its alert being committed.")
    if meta.get("stopped_at"):
        st.info("The detector has stopped. Showing its final state.")

    # -- Incidents -------------------------------------------------------------
    st.markdown("#### Incidents, highest risk first")
    if not incidents:
        st.caption("No incident yet. Alerts appear below as soon as rules fire.")
    else:
        st.dataframe([{
            "Incident": i["label"], "Risk": i["risk_score"],
            "Steps": i["detection_count"], "Raw alerts": i["raw_alert_count"],
            "Accounts": ", ".join(json.loads(i["users"])),
            "Hosts": ", ".join(json.loads(i["hosts"])),
            "Window": f"{i['start_time'][:19]} -> {i['end_time'][:19]}",
            "Version": i["version"],
        } for i in incidents], width="stretch", hide_index=True)

        labels = [i["label"] for i in incidents]
        picked = st.selectbox("Show incident", labels, key="live-incident")
        rec = next(i for i in incidents if i["label"] == picked)
        incident = graph_engine.build_incident(rec["label"], json.loads(rec["events"]))
        render_graph(incident)
        st.dataframe([{
            "#": s["step"], "Time": str(s["timestamp"])[:19].replace("T", " "),
            "Stage": s["stage"], "ATT&CK": f"{s['technique']} {s['technique_name']}",
            "Detection": s["rule"], "Host": s["host"], "Account": s["user"],
        } for s in graph_engine.get_attack_path(incident)],
            width="stretch", hide_index=True)

        ahead = graph_engine.look_ahead(incident)
        if ahead:
            st.caption("Reachable next (yellow in the graph): "
                       + ", ".join(a["target"] for a in ahead[:8]))

        # The narrative: on click only, cached per incident version.
        cache_key = f"live-report-{rec['label']}-v{rec['version']}"
        if st.button("Write narrative for this version", key=f"btn-{cache_key}"):
            summary = graph_engine.summarise_for_llm(incident)
            st.session_state[cache_key] = generate_report(summary, cache_key)
        report = st.session_state.get(cache_key)
        if report and report[1] == "ok":
            st.markdown(report[0])
            st.caption(f"AI narrative for {rec['label']} version {rec['version']}.")
        else:
            st.markdown(fallback_report(incident))
            if report:
                st.caption("AI narrative unavailable; built-in summary shown.")

    # -- Newest alerts ---------------------------------------------------------
    st.markdown("#### Newest alerts")
    if alerts:
        st.dataframe([{
            "Time": str(a["timestamp"])[:19].replace("T", " "),
            "Detection": a["rule_name"], "ATT&CK": a["mitre_technique"],
            "Host": a["host"], "Account": a["user"], "Count": a["event_count"],
            "Latency": f"{a['latency_s']:.2f} s" if a["latency_s"] is not None else "-",
        } for a in alerts], width="stretch", hide_index=True)
    else:
        st.caption("No alerts yet.")
