"""
replay.py -- play an existing log into a growing file, as if it were live.

WHY THIS FILE EXISTS
--------------------
Live mode needs a log that is being written to. Nobody has a production SOC
feed at a hackathon, so this replays a recorded one: lines are appended to the
target file at the pace their own timestamps dictate, sped up by --speed. A
day of logs at --speed 60 plays in 24 minutes; the attack in data/sample.ndjson
plays in about a minute with --start 2026-10-20T12:50:00 --speed 10.

Each JSON line is stamped with "_appended_at" (wall-clock seconds) as it is
written, so live mode can measure latency from the moment a line appeared to
the moment its alert was committed -- not just its own processing time.

    python scripts/replay.py --source data/sample.ndjson --target data/live.ndjson \\
        --start 2026-10-20T12:50:00 --speed 10

Works on the output of edr_log_generator.py too (ECS "@timestamp").
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime

TS_RE = re.compile(r'"@?timestamp"\s*:\s*"([^"]+)"')
FG_RE = re.compile(r"date=(\S+) time=(\S+)")
APPEND_FIELD = "_appended_at"


def event_time(line):
    m = TS_RE.search(line)
    text = m.group(1) if m else None
    if text is None:
        m = FG_RE.search(line)
        text = f"{m.group(1)}T{m.group(2)}" if m else None
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def stamp(line, now):
    """Add the append time to a JSON object line; other formats pass unchanged."""
    s = line.rstrip()
    if s.endswith("}"):
        return f'{s[:-1]}, "{APPEND_FIELD}": {now:.6f}}}'
    return s


def replay(source, target, speed=10.0, start=None, limit=None, max_gap=5.0,
           truncate=True, quiet=False):
    """Returns (lines written, seconds taken). speed 0 = as fast as possible."""
    if truncate:
        open(target, "w").close()
    start_dt = datetime.fromisoformat(start) if start else None
    written, began = 0, time.time()
    base_ev, base_wall, shift = None, None, 0.0
    last_report = began
    pending = []
    with open(source, encoding="utf-8", errors="replace") as src, \
            open(target, "a", encoding="utf-8", newline="\n") as out:
        for line in src:
            if not line.strip():
                continue
            ev = event_time(line)
            if start_dt and (ev is None or ev < start_dt):
                continue
            if speed and ev is not None:
                if base_ev is None:
                    base_ev, base_wall = ev, time.time()
                due = base_wall + (ev - base_ev).total_seconds() / speed - shift
                wait = due - time.time()
                if wait > max_gap:
                    # A quiet stretch in the source would freeze the demo; cap it.
                    shift += wait - max_gap
                    wait = max_gap
                if wait > 0:
                    if pending:
                        out.write("".join(pending))
                        out.flush()
                        pending = []
                    time.sleep(wait)
            pending.append(stamp(line, time.time()) + "\n")
            written += 1
            if len(pending) >= 500 or not speed:
                out.write("".join(pending))
                out.flush()
                pending = []
            if limit and written >= limit:
                break
            if not quiet and time.time() - last_report >= 5:
                last_report = time.time()
                print(f"  {written:,} lines  (event time {ev})", flush=True)
        if pending:
            out.write("".join(pending))
            out.flush()
    return written, time.time() - began


def main():
    ap = argparse.ArgumentParser(description="Replay a log into a growing file.")
    ap.add_argument("--source", required=True, help="Recorded log to replay")
    ap.add_argument("--target", required=True, help="File live_detector.py follows")
    ap.add_argument("--speed", type=float, default=10.0,
                    help="Time multiplier; 10 = ten times real time, 0 = no waiting")
    ap.add_argument("--start", default=None,
                    help="Skip events before this time, e.g. 2026-10-20T12:50:00")
    ap.add_argument("--limit", type=int, default=None, help="Stop after N lines")
    ap.add_argument("--max-gap", type=float, default=5.0,
                    help="Longest real pause between lines, in seconds")
    ap.add_argument("--append", action="store_true",
                    help="Append to the target instead of starting it empty")
    args = ap.parse_args()
    if not os.path.exists(args.source):
        sys.exit(f"No such file: {args.source}")
    print(f"Replaying {args.source} -> {args.target} at {args.speed:g}x")
    n, secs = replay(args.source, args.target, args.speed, args.start, args.limit,
                     args.max_gap, truncate=not args.append)
    print(f"Done: {n:,} lines in {secs:.1f}s")


if __name__ == "__main__":
    main()
