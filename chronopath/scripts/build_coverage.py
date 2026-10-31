"""
build_coverage.py -- Run ChronoPath 2.0 Task 1 over an input file.

WHY THIS IS A SEPARATE SCRIPT RATHER THAN PART OF THE PARSER
------------------------------------------------------------
Ground rule 1 of the 2.0 build brief: do not change detection behaviour. The
detection parser is measured at 100% detection / 100% correct labels on the
organisers' data, and the safest way to keep it that way is not to edit it.

Coverage is also a different kind of work with a different failure mode. The
detector may legitimately find nothing; coverage analysis finding nothing means
the input was unreadable. Keeping them apart means a coverage failure can never
take the detector down with it, and either can be re-run without the other.

It is also a second full scan of the file, which costs real time on 6.54 GB --
so it must be the analyst's choice when to pay for it, not an unavoidable tax
on every parse. The measured cost is recorded in docs/results_2.0.md.

Usage:
    python scripts/build_coverage.py --input D:/firex-10G.log --db firex.db
    python scripts/build_coverage.py --input data/edr_ready.json --db edr.db
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import duckdb  # noqa: E402

import parser as cp_parser  # noqa: E402
from chronopath2 import streams  # noqa: E402


def human(n):
    """Byte counts an analyst can read at a glance."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def main():
    ap = argparse.ArgumentParser(
        description="Build ChronoPath 2.0 telemetry coverage and fingerprint.")
    ap.add_argument("--input", required=True, help="Log file to profile")
    ap.add_argument("--db", default="chronopath.db", help="DuckDB file to write")
    ap.add_argument("--source-name", default=None,
                    help="Name for this source (default: the file's basename)")
    ap.add_argument("--memory-limit", default="6GB",
                    help="DuckDB memory cap (same as the parser)")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        raise SystemExit(f"No such input file: {args.input}")

    source_name = args.source_name or os.path.basename(args.input)
    log_format = cp_parser.detect_format(args.input)
    src = cp_parser.source_expr(args.input, log_format)

    print(f"\n  input    {args.input}  ({human(os.path.getsize(args.input))})")
    print(f"  format   {log_format}  (auto-detected)")
    print(f"  source   {source_name}")
    print(f"  db       {args.db}")

    con = duckdb.connect(args.db)
    # The same memory cap and spill directory the detector uses. Coverage reads
    # the identical 6.54 GB file, so it needs the identical discipline: cap the
    # heap and let DuckDB spill to disk rather than be killed by the OS.
    cp_parser.configure_connection(con, memory_limit=args.memory_limit)

    try:
        t0 = time.time()
        print("\n  scanning for per-stream hourly volume ...", flush=True)
        fp = streams.record_source(con, args.input, source_name,
                                   log_format, src)
        elapsed = time.time() - t0

        print(f"\n  streams found       {fp['streams']}")
        print(f"  volume rows         {fp.get('volume_rows', 0):,}")
        print(f"  events counted      {fp['total_rows']:,}")
        print(f"  time range          {fp['earliest']}  ->  {fp['latest']}")
        print(f"  sha256              {fp['sha256'][:32]}...")
        print(f"  timestamp field     {fp['format']}")
        if fp["bad_timestamp_rows"]:
            print(f"  unparseable ts      {fp['bad_timestamp_rows']:,}"
                  "   (raises a PARSE_FAILURE gap)")
        print(f"\n  clock check: {fp['clock_note']}")

        rows = streams.stream_summary(con, source_name)
        if rows:
            print(f"\n  {'stream':22} {'events':>12} {'share':>8} "
                  f"{'hours':>7}")
            print("  " + "-" * 52)
            for r in rows:
                print(f"  {r['stream']:22} {r['events']:>12,} "
                      f"{r['share_pct']:>7.2f}% {r['active_hours']:>7}")

        print(f"\n  coverage pass took {elapsed:.1f}s\n")
    finally:
        con.close()


if __name__ == "__main__":
    main()
