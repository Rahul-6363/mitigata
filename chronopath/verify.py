"""
verify.py -- One command that checks the whole of ChronoPath.

WHY THIS FILE EXISTS
--------------------
Testing this project meant remembering five commands, in order, with the right
`--db` and `--truth` pairings. Getting a pairing wrong produces the single most
alarming and misleading failure available here: 0% detection with 100% false
alarms, as though the detector were broken, when in fact it is being graded
against a different data set's answer key.

So the pairings live here instead of in someone's memory. One command, and it
either says PASS or tells you exactly which part failed and what to run.

It also checks its own prerequisites first and SKIPS what it cannot run rather
than failing. That matters on a demo machine: the 6.5 GB source log may not be
present, and almost everything still works without it. A verifier that cannot
tell "broken" from "not applicable here" is worse than no verifier.

WHAT IT RUNS
    1. Syntax check on every Python file         (fast, catches a bad edit)
    2. Rule files load, and the enabled/disabled split is as expected
    3. The test suite                            (16 tests, incl. regression gate)
    4. Accuracy vs ground truth, FortiGate + EDR (the PRD's four metrics)
    5. Independent validation                    (the non-circular numbers)

Run:  python verify.py
      python verify.py --quick     (skip the independent validation)
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

# Each input needs its database AND its truth file paired correctly. This is
# the mapping that was previously easy to get wrong by hand.
DATASETS = [
    {
        "name": "FortiGate (the organisers' real 6.5 GB file)",
        "db": "firex.db",
        "truth": "data/ground_truth_firex.json",
        "expect": {"detections": 373239, "incidents": 5,
                   "detection_rate": 100.0, "label_rate": 100.0,
                   "false_alarm_rate": 0.0, "path_rebuilt": False},
        "path_note": ("NO is correct here: the eight planted steps were carried "
                      "out by five accounts from five different addresses that "
                      "share no linking attribute, so they are five incidents."),
    },
    {
        "name": "EDR / ECS (the organisers' generator)",
        "db": "edr.db",
        "truth": "data/ground_truth_edr.json",
        "expect": {"detections": 26119, "incidents": 1,
                   "detection_rate": 100.0, "label_rate": 100.0,
                   "false_alarm_rate": 0.0, "path_rebuilt": True},
        "path_note": None,
    },
]

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[0m")


def c(colour, text):
    """Colour only when the terminal will render it."""
    if os.name == "nt" and not os.environ.get("WT_SESSION"):
        # Classic conhost often shows the escape codes literally. Plain text
        # is better than visible garbage in a demo.
        return text
    return f"{colour}{text}{RESET}"


class Results:
    def __init__(self):
        self.passed, self.failed, self.skipped = [], [], []

    def ok(self, name, detail=""):
        self.passed.append(name)
        print(f"  {c(GREEN, '[PASS]')} {name}" + (f"  {c(DIM, detail)}" if detail else ""))

    def bad(self, name, detail="", fix=""):
        self.failed.append((name, detail, fix))
        print(f"  {c(RED, '[FAIL]')} {name}")
        if detail:
            print(f"         {detail}")
        if fix:
            print(f"         {c(YELLOW, 'fix: ' + fix)}")

    def skip(self, name, why, fix=""):
        self.skipped.append((name, why))
        print(f"  {c(YELLOW, '[SKIP]')} {name}  {c(DIM, why)}")
        if fix:
            print(f"         {c(DIM, 'to enable: ' + fix)}")


def _first_int(text):
    """
    First integer in a line, commas tolerated.

    Written after the obvious `.split()[-1]` crashed: the report line reads
    "UNMAPPED, a real miss   0   (signature names a real threat)", so the last
    token is "threat)" rather than the number. Taking the first integer is
    robust to any trailing parenthetical.
    """
    import re as _re
    m = _re.search(r"(\d[\d,]*)", text)
    return int(m.group(1).replace(",", "")) if m else None


def run(args, timeout=1800):
    """Run a subcommand and return (ok, combined output)."""
    try:
        p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    except OSError as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# 1. Syntax
# ---------------------------------------------------------------------------

def check_syntax(r):
    import ast
    print("\n1. Python syntax")
    files, bad = [], []
    for sub in ("src", "src/chronopath2", "scripts", "tests"):
        d = os.path.join(ROOT, sub)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if name.endswith(".py"):
                files.append(os.path.join(sub, name))
    for rel in files + ["verify.py", "run_demo.py"]:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                ast.parse(f.read())
        except SyntaxError as exc:
            bad.append(f"{rel}:{exc.lineno} {exc.msg}")
    if bad:
        r.bad(f"{len(bad)} file(s) failed to parse", "; ".join(bad[:3]))
    else:
        r.ok(f"all {len(files) + 1} Python files parse")


# ---------------------------------------------------------------------------
# 2. Rule files
# ---------------------------------------------------------------------------

def check_rules(r):
    print("\n2. Detection rules (config-driven -- PRD bonus B-4)")
    try:
        import yaml
    except ImportError:
        r.skip("rule files", "PyYAML not installed",
               "pip install -r requirements.txt")
        return
    expected = {"rules.yaml": 8, "rules_ecs.yaml": 10, "rules_fortigate.yaml": 14}
    for name, want in expected.items():
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            r.bad(f"{name} missing")
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rules = data.get("rules") or []
            on = [x for x in rules if x.get("enabled", True)]
            off = [x for x in rules if not x.get("enabled", True)]
        except Exception as exc:  # noqa: BLE001
            r.bad(f"{name} failed to load", str(exc))
            continue
        detail = f"{len(rules)} rules, {len(on)} enabled"
        if off:
            detail += f", {len(off)} documented-but-off"
        if len(rules) == want:
            r.ok(name, detail)
        else:
            r.bad(name, f"{len(rules)} rules, expected {want}")


# ---------------------------------------------------------------------------
# 3. Test suite
# ---------------------------------------------------------------------------

def check_tests(r):
    print("\n3. Test suite (includes the regression gate)")
    for name, label in (("test_chronopath2.py", "test suite"),
                        ("test_elliot.py", "investigator tests"),
                        ("test_live.py", "live mode tests")):
        _run_test_file(r, name, label)


def _run_test_file(r, name, label):
    path = os.path.join(ROOT, "tests", name)
    if not os.path.exists(path):
        r.bad(f"tests/{name} missing")
        return
    ok, out = run([PY, path])
    last = [l for l in out.strip().splitlines() if l.strip()]
    summary = last[-1].strip() if last else "no output"
    skipped = out.count("SKIP:")
    if ok and "passed" in summary:
        detail = summary
        if skipped:
            detail += f"  ({skipped} skipped -- see below)"
        r.ok(label, detail)
        for line in out.splitlines():
            if "SKIP:" in line:
                print(f"         {c(DIM, line.strip())}")
    else:
        fails = [l.strip() for l in out.splitlines() if "- test_" in l]
        r.bad(label, summary + ("  " + "; ".join(fails[:2]) if fails else ""),
              f"python tests/{name}   (for the full output)")


# ---------------------------------------------------------------------------
# 4. Accuracy vs ground truth
# ---------------------------------------------------------------------------

def parse_metrics(out):
    """Pull the four PRD numbers out of evaluate.py's report."""
    got = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Detection rate"):
            got["detection_rate"] = float(s.split("%")[0].split()[-1])
        elif s.startswith("Correct ATT&CK labels"):
            got["label_rate"] = float(s.split("%")[0].split()[-1])
        elif s.startswith("False alarm rate"):
            got["false_alarm_rate"] = float(s.split("%")[0].split()[-1])
        elif s.startswith("Attack path rebuilt"):
            got["path_rebuilt"] = "YES" in s
        elif s.startswith("Incidents produced"):
            got["incidents"] = int(s.split()[-1])
    return got


def check_accuracy(r):
    print("\n4. Accuracy vs ground truth")
    try:
        import duckdb
    except ImportError:
        r.skip("accuracy", "duckdb not installed",
               "pip install -r requirements.txt")
        return

    for ds in DATASETS:
        db = os.path.join(ROOT, ds["db"])
        truth = os.path.join(ROOT, ds["truth"])
        label = ds["name"]

        if not os.path.exists(db):
            r.skip(label, f"{ds['db']} not built",
                   f"python src/parser.py --input <log> --db {ds['db']}")
            continue
        if not os.path.exists(truth):
            r.skip(label, f"{ds['truth']} missing",
                   "see SETUP.md section 8, the answer-key trap")
            continue

        # Detection count straight from the database -- the regression gate.
        try:
            con = duckdb.connect(db, read_only=True)
            n = con.execute("SELECT COUNT(*) FROM suspicious_events").fetchone()[0]
            con.close()
        except Exception as exc:  # noqa: BLE001
            r.bad(label, f"cannot read {ds['db']}: {exc}")
            continue

        ok, out = run([PY, os.path.join(ROOT, "scripts", "evaluate.py"),
                       "--db", db, "--truth", truth])
        if not ok:
            r.bad(label, (out.strip().splitlines() or ["failed"])[-1])
            continue

        got = parse_metrics(out)
        want = ds["expect"]
        problems = []
        if n != want["detections"]:
            problems.append(f"{n:,} detections, expected {want['detections']:,}")
        for key, fmt in (("incidents", "{}"), ("detection_rate", "{}%"),
                         ("label_rate", "{}%"), ("false_alarm_rate", "{}%")):
            if key in got and got[key] != want[key]:
                problems.append(f"{key} {fmt.format(got[key])}, "
                                f"expected {fmt.format(want[key])}")
        if "path_rebuilt" in got and got["path_rebuilt"] != want["path_rebuilt"]:
            problems.append(f"path rebuilt {'YES' if got['path_rebuilt'] else 'NO'},"
                            f" expected {'YES' if want['path_rebuilt'] else 'NO'}")

        detail = (f"{n:,} detections -> {got.get('incidents', '?')} incidents, "
                  f"{got.get('detection_rate', '?')}% detection, "
                  f"{got.get('label_rate', '?')}% labels, "
                  f"{got.get('false_alarm_rate', '?')}% false alarms")
        if problems:
            r.bad(label, "; ".join(problems),
                  "docs/baseline_before_2.0.md has the expected numbers and why")
        else:
            r.ok(label, detail)
            if ds["path_note"]:
                print(f"         {c(DIM, 'path rebuilt: ' + ds['path_note'])}")


# ---------------------------------------------------------------------------
# 5. Independent validation -- the numbers that are not circular
# ---------------------------------------------------------------------------

def check_independent(r, source_log):
    print("\n5. Independent validation (accuracy we did not grade ourselves)")
    script = os.path.join(ROOT, "scripts", "validate_independent.py")
    db = os.path.join(ROOT, "firex.db")
    if not os.path.exists(script):
        r.skip("independent validation", "script missing")
        return
    if not os.path.exists(db):
        r.skip("independent validation", "firex.db not built")
        return

    args = [PY, script, "--db", db, "--skip-scan"]
    if source_log:
        args += ["--input", source_log]
    ok, out = run(args)
    if not ok:
        r.bad("independent validation",
              (out.strip().splitlines() or ["failed"])[-1])
        return

    precision = holdout = None
    disagree = miss = None
    for line in out.splitlines():
        s = line.strip()
        if "LABEL PRECISION" in s:
            precision = s.split(":")[-1].strip()
        elif "% of all detections come from techniques outside" in s:
            holdout = s.split("%")[0].strip()
        elif s.startswith("disagree"):
            disagree = _first_int(s)
        elif s.startswith("UNMAPPED, a real miss"):
            # The line ends in a parenthetical, so the LAST token is a word.
            # Pull the first integer instead -- the count.
            miss = _first_int(s)

    problems = []
    if disagree not in (0, None):
        problems.append(f"{disagree:,} detections contradict the vendor's "
                        f"own signature name")
    if miss not in (0, None):
        problems.append(f"{miss:,} real threats left UNMAPPED")
    if problems:
        r.bad("label precision vs vendor signatures", "; ".join(problems),
              "docs/ACCURACY.md section 2B explains this check")
    else:
        r.ok("label precision vs vendor signatures",
             f"{precision or 'n/a'} (0 disagreements, 0 real threats missed)")
    if holdout:
        r.ok("hold-out detection",
             f"{holdout}% of detections from techniques outside our answer key")

    if not source_log:
        r.skip("input byte accounting", "source log not found",
               "python verify.py --log <path-to-firex-10G.log>")


# ---------------------------------------------------------------------------

def find_source_log(explicit=None):
    """Locate the organisers' log, if it is on this machine."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for candidate in ("D:/firex-10G.log", "D:/mitigata/firex-10G.log",
                      os.path.join(ROOT, "firex-10G.log"),
                      os.path.join(ROOT, "data", "firex-10G.log")):
        if os.path.exists(candidate):
            return candidate
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Verify the whole of ChronoPath in one command.")
    ap.add_argument("--quick", action="store_true",
                    help="Skip the independent validation")
    ap.add_argument("--log", default=None,
                    help="Path to firex-10G.log, if it is not auto-found")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    source_log = find_source_log(args.log)

    print("=" * 70)
    print("  ChronoPath -- verification")
    print("=" * 70)
    print(f"  project    {ROOT}")
    print(f"  python     {sys.version.split()[0]}")
    print(f"  source log {source_log or '(not found -- most checks still run)'}")

    r = Results()
    check_syntax(r)
    check_rules(r)
    check_tests(r)
    check_accuracy(r)
    if args.quick:
        print("\n5. Independent validation")
        r.skip("independent validation", "--quick given")
    else:
        check_independent(r, source_log)

    print("\n" + "=" * 70)
    total = len(r.passed) + len(r.failed)
    if r.failed:
        print(f"  {c(RED, 'FAILED')} -- {len(r.failed)} of {total} checks failed")
        for name, detail, fix in r.failed:
            print(f"    - {name}: {detail}")
        print("\n  Nothing here is a mystery: each line above names the file")
        print("  that holds the expected value and why it is that value.")
    else:
        print(f"  {c(GREEN, 'ALL CHECKS PASSED')} -- {len(r.passed)} of {total}")
    if r.skipped:
        print(f"\n  {len(r.skipped)} skipped (not failures -- "
              f"a prerequisite is absent):")
        for name, why in r.skipped:
            print(f"    - {name}: {why}")
    print("=" * 70 + "\n")
    return 1 if r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
