"""
run_demo.py -- One command that runs the whole pipeline end to end.

WHY THIS FILE EXISTS
--------------------
The PRD says judges must be able to start the project by following the README.
Four separate commands is four chances to mistype something while people are
watching. This runs the lot: generate data, detect, correlate, score accuracy.

It is also the fastest way to check nothing is broken after changing a rule.

Run:  python run_demo.py
      python run_demo.py --skip-generate     (keep existing logs)
      python run_demo.py --size-mb 200       (bigger data set)
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

# Windows consoles still default to a legacy code page (cp1252), which turns any
# non-ASCII character into a mojibake '?'. Force UTF-8 so output is readable on
# the demo machine. Harmless everywhere else.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def step(number, title):
    # flush=True matters here: this process and its children write to the same
    # console, and without flushing, Python's buffered output appears AFTER the
    # child's output, scrambling the order of the whole run.
    print("\n" + "=" * 70, flush=True)
    print(f"  STEP {number}: {title}", flush=True)
    print("=" * 70, flush=True)


def run(cmd):
    """Run a child command, streaming its output, and stop if it fails."""
    sys.stdout.flush()
    result = subprocess.run([sys.executable] + cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"\n!! Failed: {' '.join(cmd)}", flush=True)
        sys.exit(result.returncode)


def main():
    ap = argparse.ArgumentParser(description="Run the full ChronoPath pipeline.")
    ap.add_argument("--size-mb", type=float, default=50)
    ap.add_argument("--skip-generate", action="store_true")
    ap.add_argument("--input", default="data/sample.ndjson")
    args = ap.parse_args()

    print("\n  ChronoPath - full pipeline")

    if not args.skip_generate:
        step(1, "Generate logs with a planted attack")
        run(["scripts/generate_sample.py", "--size-mb", str(args.size_mb),
             "--out", args.input])
    else:
        step(1, "Using existing logs (skipped generation)")

    step(2, "Stream logs and detect suspicious events")
    run(["src/parser.py", "--input", args.input])

    step(3, "Correlate detections into attack paths")
    run(["src/graph_engine.py"])

    step(4, "Score accuracy against ground truth")
    truth = os.path.join(ROOT, "data", "ground_truth_flat.json")
    if os.path.exists(truth):
        run(["scripts/evaluate.py"])
    else:
        print("  (no ground truth file; skipping accuracy check)")

    print("\n" + "=" * 70)
    print("  Done. Launch the dashboard with:")
    print("      streamlit run src/app.py")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
