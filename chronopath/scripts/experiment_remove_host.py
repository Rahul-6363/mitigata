"""
experiment_remove_host.py -- Prove the gap layer works (ChronoPath 2.0, Task 6).

WHY THIS EXPERIMENT EXISTS
--------------------------
Every claim in the 2.0 layer is about absence: "we cannot see X", "this link is
unresolved", "request Y". Claims about absence are the easiest kind to make and
the hardest to check, because the evidence for them is by definition missing.
A reviewer has no way to tell a gap ledger that genuinely tracks what is
missing from one that emits plausible-sounding gaps regardless.

So this builds a case where the right answer is known in advance. Take the EDR
data set, whose eight-step attack 1.x reconstructs perfectly as one incident
ranked #1. Delete one host from the input. Re-run. Then ask two questions:

    1. Does the tool still claim to see what it can no longer see?   (It must not.)
    2. Does it NAME the hole, or go quiet about it?                  (It must name it.)

That is a falsifiable test of the whole premise of 2.0, and it is the test a
judge or a reviewer should ask for.

WHY SRV-DC-01 IS THE HOST TO REMOVE
-----------------------------------
The planted attack runs across three machines:

    steps 1-3   WS-FIN-012    macro execution, C2 beacon, autorun persistence
    steps 4-6   SRV-DC-01     brute force, account creation, service-account logon
    steps 7-8   SRV-FILE-01   exfiltration, mass file encryption

SRV-DC-01 holds the middle, and more importantly it holds the IDENTITY PIVOT:
step 5 is `rkumar` creating `svc_helpdesk`, and step 6 onwards is
`svc_helpdesk` acting. That one record is what carries the chain from the
workstation phase to the file-server phase -- without it, the attacker's
arrival as rkumar and their exfiltration as svc_helpdesk are two unrelated
people. Removing the domain controller therefore does not just shorten the
attack, it severs it, which is the most demanding case for the gap layer.

Removing a first or last host would be a weaker test: the chain would simply
be shorter at one end, and nothing would have to be inferred across the hole.

HOW THE FILE IS REDUCED
-----------------------
Streamed line by line, never loaded. The EDR input is 346 MB of NDJSON, which
would fit in memory -- but the same experiment on the 6.54 GB FortiGate file
would not, and an experiment script that only works on the small input is not
much of an experiment.

Run:  python scripts/experiment_remove_host.py
"""

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import duckdb  # noqa: E402

import graph_engine  # noqa: E402
from chronopath2 import gaps, link_evidence  # noqa: E402

# The host to remove, and why. Chosen deliberately rather than at random -- see
# the module notes. Overridable from the command line so the experiment can be
# repeated for any host.
DEFAULT_REMOVE_HOST = "SRV-DC-01"


def pick_middle_host(truth):
    """
    Choose a host that holds a middle step of the attack.

    Prefers a host that carries an account-creation step, because that is the
    identity pivot -- removing it severs the chain rather than merely
    shortening it, which is the harder test.
    """
    steps = truth.get("steps") or []
    if not steps:
        return DEFAULT_REMOVE_HOST
    middle = steps[1:-1] or steps
    pivot = [s for s in middle
             if str(s.get("technique", "")).startswith("T1136")]
    if pivot:
        return pivot[0]["host"]
    return middle[len(middle) // 2]["host"]


def reduce_input(src_path, out_path, host):
    """
    Write a copy of the input with every record for `host` removed.

    Streamed, one line at a time, so this works on a 6.54 GB file as readily as
    on a 346 MB one. The host match is a substring test on the raw line before
    any JSON parsing: parsing 400,000 objects to filter them would dominate the
    runtime, and a line that mentions the host at all is one we want gone.

    Counting is strict -- `removed` is the number of lines dropped, and the
    verification step below re-reads the output to confirm none survived. A
    filter that silently let records through would invalidate the whole
    experiment, so it is checked rather than trusted.
    """
    kept = removed = 0
    with open(src_path, "r", encoding="utf-8", errors="replace") as fin, \
            open(out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            if host in line:
                removed += 1
                continue
            fout.write(line)
            kept += 1
    return kept, removed


def verify_absent(path, host, limit=None):
    """
    Confirm no record for the removed host survived.

    This is the "nothing was invented" half of the acceptance criterion, and it
    is checked against the FILE rather than inferred from the filter, because
    the filter is the thing under test.
    """
    hits = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            if host in line:
                hits += 1
    return hits


def run(cmd, cwd):
    """Run a pipeline step, surfacing failure rather than continuing quietly."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout[-2000:])
        print(result.stderr[-2000:])
        raise SystemExit(f"Step failed: {' '.join(cmd)}")
    return result.stdout


def describe(db_path, label):
    """Summarise what the pipeline produced from one database."""
    incidents = graph_engine.analyse(db_path)
    out = {"label": label, "incident_count": len(incidents), "incidents": []}
    for inc in incidents:
        out["incidents"].append({
            "id": inc["id"],
            "risk": inc["risk_score"],
            "detections": inc["detection_count"],
            "techniques": [t[0] for t in inc["techniques"]],
            "stages": inc["stages"],
            "hosts": inc["hosts"],
            "users": inc["users"],
            "start": inc["start_time"],
            "end": inc["end_time"],
        })
    return out, incidents


def steps_found(incidents, truth, window_minutes=30):
    """
    Which planted steps appear in the output, by (account, technique, time).

    The same matching rule scripts/evaluate.py uses, so the before/after
    comparison is on the project's own measure rather than a looser one
    invented for the experiment.
    """
    from datetime import datetime

    def _ts(v):
        try:
            return datetime.fromisoformat(
                str(v).replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            return None

    detections = []
    for inc in incidents:
        for e in inc["events"]:
            detections.append((inc["id"], e["mitre_technique"],
                               str(e.get("user") or "").lower(),
                               _ts(e["timestamp"])))

    found = []
    for s in truth.get("steps", []):
        want_ts = _ts(s["timestamp"])
        want_user = str(s.get("user") or "").lower()
        hit = None
        for inc_id, tech, user, ts in detections:
            if tech != s["technique"] or ts is None or want_ts is None:
                continue
            if want_user and user != want_user:
                continue
            if abs((ts - want_ts).total_seconds()) <= window_minutes * 60:
                hit = inc_id
                break
        found.append({"step": s.get("step"), "technique": s["technique"],
                      "host": s.get("host"), "user": s.get("user"),
                      "incident": hit})
    return found


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    py = sys.executable

    ap = argparse.ArgumentParser(
        description="Remove one host from the EDR input and measure the effect.")
    ap.add_argument("--input", default=os.path.join(root, "data", "edr_ready.json"))
    ap.add_argument("--truth", default=os.path.join(root, "data", "ground_truth.json"))
    ap.add_argument("--baseline-db", default=os.path.join(root, "edr.db"))
    ap.add_argument("--reduced-db", default=os.path.join(root, "edr_removed.db"))
    ap.add_argument("--reduced-input", default=None)
    ap.add_argument("--host", default=None,
                    help="Host to remove (default: a middle step's host)")
    ap.add_argument("--keep-reduced-input", action="store_true",
                    help="Keep the reduced copy instead of deleting it")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        raise SystemExit(f"No such input: {args.input}")
    with open(args.truth, "r", encoding="utf-8") as f:
        truth = json.load(f)

    host = args.host or pick_middle_host(truth)
    reduced_input = args.reduced_input or os.path.join(
        root, "data", f"edr_without_{host}.json")

    print("\n" + "=" * 70)
    print("  ChronoPath 2.0 -- controlled experiment: remove a host")
    print("=" * 70)
    print(f"  input         {args.input}")
    print(f"  removing      {host}")
    planted_here = [s for s in truth["steps"] if s.get("host") == host]
    print(f"  which holds   {len(planted_here)} planted step(s): "
          f"{', '.join(str(s['step']) for s in planted_here)} "
          f"({', '.join(s['technique'] for s in planted_here)})")

    # --- Baseline, from the untouched data -------------------------------
    print("\n  [1/5] baseline (full data) ...", flush=True)
    base_summary, base_incidents = describe(args.baseline_db, "1.x full data")
    base_steps = steps_found(base_incidents, truth)
    base_hit = sum(1 for s in base_steps if s["incident"])
    print(f"        {base_summary['incident_count']} incident(s), "
          f"{base_hit}/{len(base_steps)} planted steps found")

    # --- Reduce the input -------------------------------------------------
    print(f"\n  [2/5] writing reduced copy without {host} ...", flush=True)
    t0 = time.time()
    kept, removed = reduce_input(args.input, reduced_input, host)
    print(f"        kept {kept:,} lines, removed {removed:,} "
          f"({time.time() - t0:.1f}s)")
    survivors = verify_absent(reduced_input, host)
    print(f"        verification: {survivors} record(s) for {host} remain "
          f"in the reduced input")

    # --- Re-run the pipeline ---------------------------------------------
    print(f"\n  [3/5] parsing reduced copy into "
          f"{os.path.basename(args.reduced_db)} ...", flush=True)
    if os.path.exists(args.reduced_db):
        os.remove(args.reduced_db)
    run([py, os.path.join(root, "src", "parser.py"),
         "--input", reduced_input, "--db", args.reduced_db], cwd=root)

    print("  [4/5] building the 2.0 evidence layer on the reduced data ...",
          flush=True)
    run([py, os.path.join(here, "run_cp2.py"),
         "--db", args.reduced_db, "--input", reduced_input], cwd=root)

    # --- Compare ----------------------------------------------------------
    print("\n  [5/5] comparing ...", flush=True)
    red_summary, red_incidents = describe(args.reduced_db, "reduced data")
    red_steps = steps_found(red_incidents, truth)
    red_hit = sum(1 for s in red_steps if s["incident"])

    con = duckdb.connect(args.reduced_db, read_only=True)
    try:
        ledger = gaps.get_gaps(con)
        links = con.execute(
            "SELECT grade, COUNT(*) FROM cp2_links GROUP BY 1").fetchall()
        rejected = con.execute(
            "SELECT COUNT(*) FROM cp2_rejected_links").fetchone()[0]
    finally:
        con.close()

    # Did the removed host leak into the output anywhere? This is the
    # "nothing invented" check, run against the database rather than the file.
    con = duckdb.connect(args.reduced_db, read_only=True)
    try:
        leaked = con.execute(
            "SELECT COUNT(*) FROM suspicious_events "
            "WHERE host = ? OR message LIKE ?", [host, f"%{host}%"]).fetchone()[0]
    finally:
        con.close()

    print("\n" + "-" * 70)
    print(f"  {'':34}{'FULL DATA':>14}{'WITHOUT ' + host:>20}")
    print("-" * 70)
    print(f"  {'incidents reported':34}{base_summary['incident_count']:>14}"
          f"{red_summary['incident_count']:>20}")
    print(f"  {'planted steps found':34}"
          f"{str(base_hit) + '/' + str(len(base_steps)):>14}"
          f"{str(red_hit) + '/' + str(len(red_steps)):>20}")
    base_top = base_summary["incidents"][0] if base_summary["incidents"] else {}
    red_top = red_summary["incidents"][0] if red_summary["incidents"] else {}
    print(f"  {'top incident risk':34}{base_top.get('risk', 0):>14.1f}"
          f"{red_top.get('risk', 0):>20.1f}")
    print(f"  {'hosts in top incident':34}"
          f"{len(base_top.get('hosts', [])):>14}"
          f"{len(red_top.get('hosts', [])):>20}")
    print(f"  {'stages in top incident':34}"
          f"{len(base_top.get('stages', [])):>14}"
          f"{len(red_top.get('stages', [])):>20}")
    print("-" * 70)

    print("\n  Per-step outcome (which incident each planted step landed in):")
    for b, r in zip(base_steps, red_steps):
        marker = "  " if b["incident"] == r["incident"] else " *"
        print(f"  {marker} step {b['step']}  {b['technique']:12} "
              f"{str(b['host']):14} full={str(b['incident'] or 'MISSING'):9} "
              f"reduced={str(r['incident'] or 'MISSING')}")

    print(f"\n  Gap ledger on the reduced data: {len(ledger)} gap(s)")
    by_class = {}
    for g in ledger:
        by_class[g["classification"]] = by_class.get(g["classification"], 0) + 1
    for name, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
        print(f"      {n:>3}  {name}")

    # Which gaps cover the hole the removal created.
    #
    # Note what we do NOT expect: a gap naming SRV-DC-01. The tool never saw
    # that host, and inventing its name would be fabrication. What it CAN do --
    # and must -- is notice the consequence: accounts now act with no recorded
    # origin, because the records explaining them left with the host. So the
    # check is for gaps covering the orphaned entities, not for the hostname.
    orphaned = {s["user"] for s in truth.get("steps", [])
                if s.get("host") == host and s.get("user")}
    covering = [g for g in ledger
                if any(u and u.lower() in (g.get("asset_or_entity") or "").lower()
                       for u in orphaned)
                or host in (g.get("asset_or_entity") or "")
                or host in (g.get("basis") or "")]
    print(f"\n  Gaps covering what {host} took with it "
          f"(entities {', '.join(sorted(orphaned)) or 'n/a'}): {len(covering)}")
    for g in covering[:3]:
        print(f"      - {g['gap_id']} [{g['classification']}] "
              f"entity={g['asset_or_entity']}")
        print(f"        {(g['basis'] or '')[:160]}")
        print(f"        REQUEST: {(g['evidence_request'] or '')[:160]}")
    host_gaps = covering

    print(f"\n  Link grades on the reduced data: "
          f"{', '.join(f'{g}={n}' for g, n in links) or 'none'}"
          f"   rejected={rejected}")

    # THE DECISIVE COMPARISON: which gaps are NEW because of the removal.
    #
    # A ledger that lists the same gaps either way proves nothing -- it would
    # mean the gaps are boilerplate. The ones that appear only on the reduced
    # data are the ones genuinely caused by the missing host, and they are the
    # evidence that this layer tracks reality rather than emitting plausible
    # text.
    base_con = duckdb.connect(args.baseline_db, read_only=True)
    try:
        base_ledger = gaps.get_gaps(base_con)
    finally:
        base_con.close()

    def signature(g):
        """Compare by what the gap is ABOUT, not by its generated id."""
        return (g["classification"], g["telemetry"],
                (g.get("asset_or_entity") or "").lower())

    base_sigs = {signature(g) for g in base_ledger}
    new_gaps = [g for g in ledger if signature(g) not in base_sigs]

    print(f"\n  Gaps present ONLY on the reduced data: {len(new_gaps)}")
    if not new_gaps:
        print("      (none -- the ledger did not react to the removal)")
    for g in new_gaps:
        print(f"      + {g['gap_id']} [{g['classification']}] "
              f"entity={g['asset_or_entity']}")
        print(f"        {(g['impact'] or '')[:170]}")

    print(f"\n  NOTHING INVENTED CHECK")
    print(f"      records for {host} in the reduced input : {survivors}")
    print(f"      records for {host} in the output database: {leaked}")
    verdict = ("PASS -- the removed host appears nowhere"
               if survivors == 0 and leaked == 0
               else "FAIL -- the removed host leaked into the output")
    print(f"      {verdict}")

    if not args.keep_reduced_input and os.path.exists(reduced_input):
        os.remove(reduced_input)
        print(f"\n  (reduced input deleted; pass --keep-reduced-input to keep it)")

    print()
    return {
        "host": host, "removed_lines": removed, "kept_lines": kept,
        "survivors": survivors, "leaked": leaked,
        "baseline": base_summary, "reduced": red_summary,
        "baseline_steps": base_steps, "reduced_steps": red_steps,
        "gaps": len(ledger), "host_gaps": len(host_gaps),
    }


if __name__ == "__main__":
    main()
