"""
run_cp2.py -- Build the whole ChronoPath 2.0 evidence layer in one command.

WHY THIS SCRIPT EXISTS
----------------------
The five 2.0 modules have a required order, and getting it wrong produces
quietly degraded output rather than an error:

    1. streams     must run first -- blind_window reads its volume table, and
                   gaps reads its fingerprint for parse counts and file range.
    2. enrichment  must precede link_evidence, or the identity pivot cannot be
                   recognised (the created account name lives only in the raw
                   log line, not in the detections table).
    3. link_evidence
    4. blind_window and gaps -- both write cp2_gaps, so gaps must preserve the
                   blind-window rows rather than clearing the table.
    5. respond     reads the gap ledger to produce its evidence requests.

Encoding that order once, here, means neither the dashboard nor a demo has to
remember it. It also makes the layer reproducible: one command, from a 1.x
database to a fully populated 2.0 one.

Streams is skipped unless --input is given, because it is the only step that
needs a second pass over the source log. Everything else works from the
detections already in the database, which is why the whole layer runs in
seconds on a 6.54 GB investigation.

Usage:
    python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log
    python scripts/run_cp2.py --db edr.db --input data/edr_ready.json
    python scripts/run_cp2.py --db firex.db          # skip the coverage pass
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import duckdb  # noqa: E402

import fortigate_adapter  # noqa: E402
import graph_engine  # noqa: E402
import parser as cp_parser  # noqa: E402
from chronopath2 import blind_window, gaps, link_evidence, respond, streams  # noqa: E402


def main():
    ap = argparse.ArgumentParser(
        description="Build the ChronoPath 2.0 evidence and gap layer.")
    ap.add_argument("--db", default="chronopath.db")
    ap.add_argument("--input", default=None,
                    help="Source log. Needed for the coverage pass and for "
                         "raw-line evidence; everything else works without it.")
    ap.add_argument("--memory-limit", default="6GB")
    ap.add_argument("--skip-coverage", action="store_true",
                    help="Reuse an existing coverage pass instead of rescanning")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        raise SystemExit(f"No such database: {args.db}. Run src/parser.py first.")

    print(f"\n  ChronoPath 2.0 -- evidence and gap layer")
    print(f"  db     {args.db}")
    print(f"  source {args.input or '(not supplied)'}")

    # Correlate BEFORE opening our own connection.
    #
    # graph_engine.analyse() opens the database read-only, and DuckDB refuses a
    # second connection to the same file under a different configuration -- so
    # holding a read-write handle here while calling it fails outright. Running
    # it first costs nothing and keeps the engine untouched, which ground rule 1
    # requires anyway.
    t0 = time.time()
    incidents = graph_engine.analyse(args.db)
    correlate_s = time.time() - t0
    if not incidents:
        print("\n  No incidents to analyse. Nothing to do.\n")
        return

    con = duckdb.connect(args.db)
    cp_parser.configure_connection(con, memory_limit=args.memory_limit)
    totals = {}

    try:
        print(f"\n  [1/6] correlated      {len(incidents)} incidents"
              f"{'':12}{correlate_s:>6.1f}s")

        # --- 2. Telemetry coverage and provenance (Task 1) ----------------
        if args.input and streams.has_current_record(
                con, args.input, os.path.basename(args.input)):
            # The parser records coverage during its detection scan, so the
            # usual path reads nothing here.
            n = con.execute(
                "SELECT streams_found, total_rows FROM cp2_source_fingerprint "
                "WHERE source = ?", [os.path.basename(args.input)]).fetchone()
            print(f"  [2/6] coverage        {n[0]} streams, {n[1]:,} events"
                  f"  (recorded in the detection scan)")
            totals["streams"] = n[0]
        elif args.input and not args.skip_coverage:
            t0 = time.time()
            log_format = cp_parser.detect_format(args.input)
            # Coverage reads only timestamp and type/subtype, so FortiGate gets
            # a lean reader that skips the other ~25 field regexes.
            if log_format == "fortigate":
                src = fortigate_adapter.fortigate_volume_expr(args.input)
            else:
                src = cp_parser.source_expr(args.input, log_format)
            fp = streams.record_source(
                con, args.input, os.path.basename(args.input), log_format, src)
            print(f"  [2/6] coverage        {fp['streams']} streams, "
                  f"{fp['total_rows']:,} events{'':2}{time.time() - t0:>6.1f}s")
            totals["streams"] = fp["streams"]
        else:
            print("  [2/6] coverage        skipped (no --input)")

        # --- 3. Attach raw log lines (needed by Task 3) -------------------
        #
        # Only FortiGate needs this. Its `message` column holds the generic
        # logdesc ("Object attribute configured") while the account name sits
        # in `msg` on the raw line, so the identity pivot is unrecognisable
        # without a fetch. ECS and flat JSON already carry the command line in
        # `message`, so enrichment correctly finds nothing to add -- and 0 is
        # reported as "not needed" rather than as a bare zero that reads
        # like a failure.
        if args.input:
            t0 = time.time()
            fmt = cp_parser.detect_format(args.input)
            if fmt == "fortigate":
                filled = link_evidence.enrich_from_source(args.input, incidents)
                print(f"  [3/6] raw evidence    {filled} detections enriched"
                      f"{'':5}{time.time() - t0:>6.1f}s")
            else:
                print(f"  [3/6] raw evidence    not needed for {fmt} "
                      f"(message already carries it)")
        else:
            print("  [3/6] raw evidence    skipped (no --input)")

        # --- 4. Link evidence, rejections, separation (Task 3) ------------
        t0 = time.time()
        links, rejected, separation = link_evidence.analyse(con, incidents)
        print(f"  [4/6] link evidence   {len(links)} links, "
              f"{len(rejected)} rejected{'':5}{time.time() - t0:>6.1f}s")
        totals.update(links=len(links), rejected=len(rejected),
                      separation=len(separation))

        # --- 5. Blind windows, then the gap ledger (Tasks 2 and 4) --------
        # Order matters: gaps.analyse preserves blind-window rows, so the
        # blind-window check must have written them first.
        t0 = time.time()
        bw = blind_window.analyse(con, incidents,
                                  parse_ts=graph_engine._parse_ts)
        gap_rows = gaps.analyse(con, incidents)
        ledger = gaps.get_gaps(con)
        print(f"  [5/6] gap ledger      {len(ledger)} gaps "
              f"({len(bw)} blind-window){'':4}{time.time() - t0:>6.1f}s")
        totals.update(gaps=len(ledger), blind_windows=len(bw))

        # --- 6. Respond-now (Task 5) --------------------------------------
        t0 = time.time()
        by_incident = {}
        for g in ledger:
            by_incident.setdefault(g["incident_id"], []).append(g)
        panels = respond.analyse(con, incidents, gaps_by_incident=by_incident,
                                 parse_ts=graph_engine._parse_ts)
        n_ind = sum(len(p["indicators"]) for p in panels.values())
        n_act = sum(len(p["actions"]) for p in panels.values())
        print(f"  [6/6] respond-now     {n_ind} indicators, {n_act} actions"
              f"{'':3}{time.time() - t0:>6.1f}s")
        totals.update(indicators=n_ind, actions=n_act)

        # --- Summary -------------------------------------------------------
        print("\n  " + "-" * 60)
        for inc in incidents:
            inc_gaps = by_incident.get(inc["id"], [])
            inc_links = [l for l in links if l["incident_id"] == inc["id"]]
            hard = sum(1 for l in inc_links if l["grade"] == "HARD")
            print(f"  {inc['id']}  risk {inc['risk_score']:>5.1f}  "
                  f"{inc['detection_count']:>3} detections  "
                  f"{len(inc_links):>2} links ({hard} HARD)  "
                  f"{len(inc_gaps)} gaps")

        classes = {}
        for g in ledger:
            classes[g["classification"]] = classes.get(g["classification"], 0) + 1
        print("\n  gap ledger by classification:")
        for name, n in sorted(classes.items(), key=lambda kv: -kv[1]):
            print(f"    {n:>3}  {name}")

        print(f"\n  2.0 tables written into {args.db}. "
              f"Open the dashboard with:  streamlit run src/app.py\n")
    finally:
        con.close()


if __name__ == "__main__":
    main()
