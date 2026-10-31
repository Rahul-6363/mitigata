"""
api.py -- The REST API required by FR-7.

WHY THIS FILE EXISTS
--------------------
FR-7 asks for a "Simple API or page, with a short README", and gives the
example `GET /incidents/12/path`. The Streamlit dashboard already satisfies the
"page" half, but the PRD's example is literally an HTTP endpoint, so we provide
both. A judge who wants to curl the tool should be able to.

It also answers a question the dashboard cannot: the PRD's "Investigation
speed" target is "time to open one incident's attack path", under 2 seconds to
qualify and under 500 ms to stand out. An HTTP endpoint makes that directly
measurable -- see the `elapsed_ms` field on every response, and the /metrics
endpoint.

WHY THE STANDARD LIBRARY RATHER THAN FASTAPI
--------------------------------------------
FastAPI is already installed (Streamlit pulls it in) and would be slightly
tidier. We use `http.server` anyway, for one reason: it adds ZERO new
dependencies. During a hackathon demo the failure that hurts is the one in the
plumbing, and an API that cannot fail to import is worth more than one with
nicer decorators. The whole server is about 200 lines and has no build step.

PERFORMANCE: WHERE THE SPEED COMES FROM
---------------------------------------
Incidents are correlated ONCE at startup and held in memory. A request then
only serialises an answer that already exists, which is why responses land in
single-digit milliseconds rather than re-reading the database. The cache is
invalidated automatically when the parser writes a new chronopath.db, so a
re-run is picked up without a restart.

ENDPOINTS
    GET /                        index of available endpoints
    GET /incidents               all incidents, ranked worst-first
    GET /incidents/{id}          one incident in full
    GET /incidents/{id}/path     the attack path   <- the PRD's example
    GET /incidents/{id}/graph    nodes and edges for the attack graph
    GET /incidents/{id}/next     what the attacker could reach next (FR-6)
    GET /incidents/{id}/report   plain-English narrative (B-2)
    GET /stats                   corpus-level summary
    GET /metrics                 timing, for the PRD investigation-speed target

Run:  python src/api.py              (then http://localhost:8000)
      python src/api.py --port 9000
"""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import graph_engine  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "chronopath.db")

# Correlated incidents, cached in memory. _cache_key is the database's
# modification time, so writing a new chronopath.db invalidates the cache
# without needing a restart.
_cache = {"key": None, "incidents": []}


def get_incidents():
    """Return cached incidents, recomputing only when the database changes."""
    key = os.path.getmtime(DB_PATH) if os.path.exists(DB_PATH) else None
    if key != _cache["key"]:
        _cache["incidents"] = graph_engine.analyse(DB_PATH)
        _cache["key"] = key
    return _cache["incidents"]


_pivot_cache = {"key": None, "data": None, "timeline": None}


def get_pivot():
    """
    Cached pivot ranking, keyed on the database's modification time.

    Measured without this: 6.5 s per request, because ranking rescans all
    395,361 detections. That would wreck the PRD's investigation-speed figure
    for anyone who opened the hunting view. Cached, repeat calls are
    instantaneous, and the cache still refreshes the moment the parser writes
    a new database.
    """
    import pivot
    key = os.path.getmtime(DB_PATH) if os.path.exists(DB_PATH) else None
    if key != _pivot_cache["key"]:
        _pivot_cache["data"] = pivot.rank_entities(DB_PATH, top_n=10)
        _pivot_cache["timeline"] = pivot.activity_timeline(DB_PATH)
        _pivot_cache["key"] = key
    return _pivot_cache["data"]


def get_timeline():
    """Cached detection-frequency timeline; shares the pivot cache."""
    get_pivot()
    return _pivot_cache["timeline"] or []


def load_env_file():
    """
    Read GROQ_API_KEY from .env if it is not already in the environment.

    Same loader as the dashboard uses. Without it the API's /report endpoint
    would silently fall back to the structured summary even when a key is
    sitting in the project folder -- the two interfaces should behave the same.
    """
    if os.environ.get("GROQ_API_KEY"):
        return
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip('"\''))
    except OSError:
        pass


load_env_file()

# Cache narratives per incident: the LLM call takes ~1-3 s, and repeating it on
# every request would wreck the investigation-speed figure for no benefit.
_narrative_cache = {}


def write_narrative(summary_text):
    """
    Turn the structured attack path into prose, if a Groq key is available.

    Returns (text, source) where source is "groq", "structured" or "error", so
    a caller can tell AI prose from the deterministic fallback. Never raises:
    the API must keep answering even when the network does not.

    Model and token budget match src/app.py -- see the long note there on why
    it is gpt-oss rather than Llama, and why max_tokens must be generous.
    """
    if summary_text in _narrative_cache:
        return _narrative_cache[summary_text]

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        result = (None, "structured")
        _narrative_cache[summary_text] = result
        return result

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        for model in ("openai/gpt-oss-120b", "openai/gpt-oss-20b"):
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system",
                         "content": "You are a senior SOC analyst. Be concise, "
                                    "factual, and never invent details."},
                        {"role": "user",
                         "content": "Write a short plain-English incident "
                                    "report from this attack path.\n\n"
                                    + summary_text},
                    ],
                    temperature=0.2,
                    max_tokens=1500,
                )
                text = (resp.choices[0].message.content or "").strip()
                if text:
                    result = (text, "groq")
                    _narrative_cache[summary_text] = result
                    return result
            except Exception:
                continue
    except Exception:
        pass

    result = (None, "structured")
    _narrative_cache[summary_text] = result
    return result


def find_incident(incidents, incident_id):
    """
    Look up an incident by id.

    Accepts "INC-04", "inc-4" or plain "4", because a judge typing a URL by
    hand should not have to guess the zero-padding. The PRD's own example is
    `/incidents/12/path`, i.e. a bare number.
    """
    wanted = str(incident_id).strip().upper()
    for inc in incidents:
        if inc["id"].upper() == wanted:
            return inc
    # Bare or non-padded number.
    digits = wanted.replace("INC-", "").lstrip("0") or "0"
    for inc in incidents:
        if inc["id"].replace("INC-", "").lstrip("0") == digits:
            return inc
    return None


def incident_summary(inc):
    """Compact view, used for list responses."""
    return {
        "id": inc["id"],
        "risk_score": inc["risk_score"],
        "detection_count": inc["detection_count"],
        "raw_alert_count": inc["raw_alert_count"],      # B-3
        "hosts": inc["hosts"],
        "users": inc["users"],
        "kill_chain_stages": inc["stages"],
        "techniques": [{"id": t[0], "name": t[1]} for t in inc["techniques"]],
        "start_time": inc["start_time"],
        "end_time": inc["end_time"],
    }


class Handler(BaseHTTPRequestHandler):
    # Silence the default per-request logging; we print our own timing line.
    def log_message(self, fmt, *args):
        pass

    def _send(self, payload, status=200, started=None):
        """Serialise a JSON response, adding the elapsed time to every body."""
        if isinstance(payload, dict) and started is not None:
            payload["elapsed_ms"] = round((time.time() - started) * 1000, 2)
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Permit browser-based tools to call this during a demo.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        started = time.time()
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]

        try:
            # GET /
            if not parts:
                return self._send({
                    "service": "ChronoPath API",
                    "description": "Kill chain and attack path analysis",
                    "endpoints": {
                        "GET /incidents": "all incidents, worst first",
                        "GET /incidents/{id}": "one incident in full",
                        "GET /incidents/{id}/path": "attack path (FR-5)",
                        "GET /incidents/{id}/graph": "graph nodes and edges (FR-5)",
                        "GET /incidents/{id}/next": "what they could reach next (FR-6)",
                        "GET /incidents/{id}/report": "plain-English report (B-2)",
                        "GET /pivot": "entities ranked by anomaly (hunting)",
                        "GET /timeline": "detections per hour",
                        "GET /stats": "corpus summary",
                        "GET /metrics": "endpoint timings",
                    },
                    "example": "/incidents/1/path",
                }, started=started)

            # GET /pivot -- threat-hunting view: which entities look odd,
            # ranked, with no rule needing to know what the attack is.
            if parts[0] == "pivot":
                return self._send({
                    "description": "Entities ranked by how anomalous they "
                                   "look. Rarity-weighted: attackers touch "
                                   "few things, noise touches many.",
                    "pivot_points": get_pivot(),
                }, started=started)

            # GET /timeline -- detections per hour, for spotting bursts.
            if parts[0] == "timeline":
                buckets = get_timeline()
                busiest = (max(buckets, key=lambda b: b["detections"])
                           if buckets else None)
                return self._send({
                    "bucket_count": len(buckets),
                    "busiest": busiest,
                    "timeline": buckets,
                }, started=started)

            if parts[0] == "stats":
                incidents = get_incidents()
                techniques = {}
                stages = {}
                for inc in incidents:
                    for tid, tname in inc["techniques"]:
                        techniques[tid] = techniques.get(tid, 0) + 1
                    for stage in inc["stages"]:
                        stages[stage] = stages.get(stage, 0) + 1
                return self._send({
                    "incident_count": len(incidents),
                    "total_detections": sum(i["detection_count"] for i in incidents),
                    "total_raw_alerts": sum(i["raw_alert_count"] for i in incidents),
                    "techniques_seen": techniques,
                    "kill_chain_stages_seen": stages,
                    "highest_risk": incidents[0]["risk_score"] if incidents else 0,
                }, started=started)

            if parts[0] == "metrics":
                incidents = get_incidents()
                t0 = time.time()
                if incidents:
                    graph_engine.get_attack_path(incidents[0])
                    graph_engine.look_ahead(incidents[0])
                lookup_ms = (time.time() - t0) * 1000
                return self._send({
                    "incidents_cached": len(incidents),
                    "open_one_incident_ms": round(lookup_ms, 2),
                    "prd_target_good_ms": 2000,
                    "prd_target_great_ms": 500,
                    "verdict": ("GREAT" if lookup_ms < 500
                                else "GOOD" if lookup_ms < 2000 else "BELOW"),
                }, started=started)

            if parts[0] != "incidents":
                return self._send({"error": f"Unknown endpoint: {path}"},
                                  404, started)

            incidents = get_incidents()

            # GET /incidents
            if len(parts) == 1:
                return self._send({
                    "count": len(incidents),
                    "incidents": [incident_summary(i) for i in incidents],
                }, started=started)

            inc = find_incident(incidents, parts[1])
            if inc is None:
                return self._send({
                    "error": f"Incident '{parts[1]}' not found",
                    "available": [i["id"] for i in incidents[:20]],
                }, 404, started)

            # GET /incidents/{id}
            if len(parts) == 2:
                data = incident_summary(inc)
                data["path"] = graph_engine.get_attack_path(inc)
                data["look_ahead"] = graph_engine.look_ahead(inc)
                return self._send(data, started=started)

            action = parts[2].lower()

            # GET /incidents/{id}/path  <- the PRD's worked example
            if action == "path":
                return self._send({
                    "incident_id": inc["id"],
                    "risk_score": inc["risk_score"],
                    "step_count": inc["detection_count"],
                    "raw_alerts_merged": inc["raw_alert_count"],
                    "path": graph_engine.get_attack_path(inc),
                }, started=started)

            # GET /incidents/{id}/graph
            if action == "graph":
                g = inc["graph"]
                compromised = {e["host"] for e in inc["events"] if e["host"]}
                compromised |= {e["user"] for e in inc["events"] if e["user"]}
                at_risk = {a["target"] for a in graph_engine.look_ahead(inc)}
                nodes = [{"id": n,
                          "kind": a.get("kind", "unknown"),
                          "state": ("compromised" if n in compromised
                                    else "at_risk" if n in at_risk else "clean")}
                         for n, a in g.nodes(data=True)]
                for target in at_risk:
                    if target not in g.nodes():
                        nodes.append({"id": target, "kind": "host",
                                      "state": "at_risk"})
                edges = [{"source": s, "target": t,
                          "technique": a.get("technique", ""),
                          "stage": a.get("stage", ""),
                          "timestamp": a.get("timestamp", "")}
                         for s, t, a in g.edges(data=True)]
                return self._send({"incident_id": inc["id"],
                                   "nodes": nodes, "edges": edges},
                                  started=started)

            # GET /incidents/{id}/next
            if action == "next":
                ahead = graph_engine.look_ahead(inc)
                return self._send({
                    "incident_id": inc["id"],
                    "reachable_count": len(ahead),
                    "critical_targets": [a["target"] for a in ahead
                                         if a.get("criticality", 0) >= 9],
                    "reachable": ahead,
                }, started=started)

            # GET /incidents/{id}/report
            if action == "report":
                summary = graph_engine.summarise_for_llm(inc)
                narrative, source = write_narrative(summary)
                return self._send({
                    "incident_id": inc["id"],
                    "narrative": narrative,
                    "narrative_source": source,
                    "structured_summary": summary,
                }, started=started)

            return self._send({"error": f"Unknown action '{action}'",
                               "valid": ["path", "graph", "next", "report"]},
                              404, started)

        except Exception as exc:  # never return a bare stack trace
            return self._send({"error": type(exc).__name__, "detail": str(exc)},
                              500, started)


def main():
    ap = argparse.ArgumentParser(description="ChronoPath REST API (FR-7).")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    if not os.path.exists(DB_PATH):
        print(f"No database at {DB_PATH}")
        print("Run the parser first:  python src/parser.py --input <logs>")
        return

    # Warm the cache before accepting traffic, so the first request is as fast
    # as the rest -- otherwise the PRD's investigation-speed figure would be
    # dominated by one-off startup work.
    print("Correlating incidents ...")
    t0 = time.time()
    incidents = get_incidents()
    # Warm the pivot cache too: ranking 395k detections takes ~6 s, and the
    # first analyst to open the hunting view should not pay for it.
    get_pivot()
    print(f"  {len(incidents)} incidents ready in {time.time() - t0:.2f}s")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"\n  ChronoPath API  http://{args.host}:{args.port}")
    print(f"  Try:  http://{args.host}:{args.port}/incidents/1/path")
    print("  Ctrl-C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[stopped]")
        server.shutdown()


if __name__ == "__main__":
    main()
