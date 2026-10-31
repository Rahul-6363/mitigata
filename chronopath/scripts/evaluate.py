"""
evaluate.py -- Grade the detector against the planted attack (ground truth).

WHY THIS FILE EXISTS
--------------------
The PRD does not score opinions, it scores numbers:

    Detection rate     share of planted steps found      >70% good, >90% great
    Correct labels     share with the right ATT&CK ID    >60% good, >85% great
    Attack path        rebuilt with right steps in order  half / all
    False alarms       incidents that are not real        <30% good, <10% great

Without this file we would be guessing at all four. With it we can tune a rule,
re-run, and see immediately whether we improved or broke something. It also
produces the figures to quote to judges, which carry far more weight than
"it seems to work well".

HOW SCORING WORKS
-----------------
A planted step counts as DETECTED if a reported incident contains a detection
by the same account within MATCH_WINDOW_MINUTES of the step, and as LABELLED if
that detection also carries the same ATT&CK technique. A small window rather
than an exact timestamp, because aggregate rules report the start of a burst.

An earlier version matched on host alone. On the FortiGate data every planted
step is on the same firewall, so ANY detection on that address "found" every
step: a planted login that was never reported scored as detected.

Run:  python scripts/evaluate.py
"""

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import graph_engine  # noqa: E402

MATCH_WINDOW_MINUTES = 30


def load_truth(path="data/ground_truth.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _matches(step, det):
    """Same actor (account, else host) and close in time."""
    if step.get("user"):
        if str(det["user"] or "").lower() != step["user"].lower():
            return False
    elif det["host"] != step["host"]:
        return False
    a, b = _ts(step["timestamp"]), _ts(det["timestamp"])
    return a is not None and b is not None and \
        abs((a - b).total_seconds()) <= MATCH_WINDOW_MINUTES * 60


def evaluate(db_path="chronopath.db", truth_path="data/ground_truth.json"):
    truth = load_truth(truth_path)
    planted = truth["steps"]

    incidents = graph_engine.analyse(db_path)
    detections = []
    for inc in incidents:
        for ev in inc["events"]:
            detections.append({
                "technique": ev["mitre_technique"],
                "host": ev["host"],
                "user": ev["user"],
                "timestamp": ev["timestamp"],
                "stage": ev["kill_chain_stage"],
                "incident": inc["id"],
            })

    # --- Detection + labelling -------------------------------------------
    found, labelled, missed = 0, 0, []
    for step in planted:
        hits = [d for d in detections if _matches(step, d)]
        technique_hits = [d for d in hits if d["technique"] == step["technique"]]
        who = step.get("user") or step["host"]
        if technique_hits:
            found += 1
            labelled += 1
        elif hits:
            found += 1
            got = sorted({d["technique"] for d in hits})
            missed.append(f"{step['technique']} by {who} (labelled {', '.join(got)})")
        else:
            missed.append(f"{step['technique']} by {who} (not in any incident)")

    total = len(planted)
    detection_rate = found / total * 100 if total else 0
    label_rate = labelled / found * 100 if found else 0

    # --- Attack path reconstruction --------------------------------------
    # The planted attack should come back as ONE incident, with its steps in
    # chronological order. Fragmenting it across incidents means we failed to
    # connect the story, which is the core of the problem statement.
    #
    # WE SEARCH ALL INCIDENTS, not just the top-ranked one. The PRD measures
    # whether "planted attacks [are] rebuilt with the right steps in the right
    # order" -- that is a question about reconstruction, not about ranking.
    # Ranking is scored separately by the false-alarm rate. An earlier version
    # of this check only looked at incidents[0] and so reported a correctly
    # rebuilt attack as a failure merely because noisier groups outscored it.
    # We report the rank alongside, since a low rank is still worth knowing.
    #
    # Each planted step must be matched (actor, time, technique) inside the
    # SAME incident, and the matched detections must follow the planted order.
    # Other detections in the incident are context and do not break the order;
    # an earlier check failed a correct path whenever background alerts of the
    # same technique appeared earlier in the incident.
    path_ok = False
    path_rank = None
    for position, inc in enumerate(incidents, start=1):
        order = []
        for step in planted:
            times = [_ts(e["timestamp"]) for e in inc["events"]
                     if e["mitre_technique"] == step["technique"]
                     and _matches(step, {"user": e["user"], "host": e["host"],
                                         "timestamp": e["timestamp"]})]
            if not times:
                break
            want_ts = _ts(step["timestamp"])
            order.append(min(times, key=lambda t: abs((t - want_ts).total_seconds())))
        if len(order) == len(planted) and order == sorted(order):
            path_ok = True
            path_rank = position
            break

    # --- False alarms ------------------------------------------------------
    # Any incident other than the one containing the planted attack is, by
    # construction, a false positive -- the generator planted exactly one attack.
    real_ids = {d["incident"] for d in detections
                if any(_matches(s, d) for s in planted)}
    false_count = len(incidents) - len(real_ids)
    false_rate = false_count / len(incidents) * 100 if incidents else 0

    def grade(value, good, great, lower_is_better=False):
        if lower_is_better:
            if value < great: return "GREAT"
            if value < good:  return "GOOD"
        else:
            if value > great: return "GREAT"
            if value > good:  return "GOOD"
        return "BELOW"

    print("\n" + "=" * 66)
    print("  ChronoPath accuracy vs planted ground truth")
    print("=" * 66)
    print(f"  Planted attack steps      {total}")
    print(f"  Incidents produced        {len(incidents)}")
    print("-" * 66)
    print(f"  Detection rate            {detection_rate:5.1f}%   "
          f"[{grade(detection_rate, 70, 90)}]   target >70 good / >90 great")
    print(f"  Correct ATT&CK labels     {label_rate:5.1f}%   "
          f"[{grade(label_rate, 60, 85)}]   target >60 good / >85 great")
    rank_note = f" (ranked #{path_rank})" if path_rank else ""
    print(f"  Attack path rebuilt       {'YES' if path_ok else 'NO':>5}   "
          f"[{'GREAT' if path_ok else 'BELOW'}]   target: all of them{rank_note}")
    print(f"  False alarm rate          {false_rate:5.1f}%   "
          f"[{grade(false_rate, 30, 10, lower_is_better=True)}]   "
          f"target <30 good / <10 great")
    print("=" * 66)

    if missed:
        print("\n  Missed or mislabelled:")
        for m in missed:
            print(f"    - {m}")
    print()

    return {
        "detection_rate": detection_rate,
        "label_rate": label_rate,
        "path_rebuilt": path_ok,
        "false_alarm_rate": false_rate,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="chronopath.db")
    ap.add_argument("--truth", default="data/ground_truth.json")
    args = ap.parse_args()
    if not os.path.exists(args.truth):
        raise SystemExit("No ground truth. Run scripts/generate_sample.py first.")
    evaluate(args.db, args.truth)
