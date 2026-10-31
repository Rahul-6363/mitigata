"""
test_live.py -- Tests for live mode (src/live_detector.py, scripts/replay.py).

Live mode is only worth having if it reaches the same conclusions as batch
mode, sooner. So the tests check the mechanics that could make it diverge:

  1. Tailing returns only complete lines; a half-written line is carried over.
  2. A truncated or rotated file is re-read from the start.
  3. The rolling window evicts old events, so memory does not grow.
  4. An aggregate burst alerts once, then updates -- it does not re-fire
     every tick.
  5. Incremental correlation gives the same incidents as batch mode.
  6. Memory stays flat over a long replay.

Run:  python tests/test_live.py
"""

import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import graph_engine  # noqa: E402
import parser as cp_parser  # noqa: E402
import live_detector as live  # noqa: E402

TMP = tempfile.mkdtemp(prefix="cp-live-test-")
RULES = cp_parser.load_rules(os.path.join(ROOT, "rules.yaml"))


def _skip(reason):
    print(f"    SKIP: {reason}")
    return True


def _event(ts, **kw):
    e = {"timestamp": ts.isoformat(), "host": "WS-01", "user": "alice",
         "event_id": 4624, "src_ip": "10.0.0.5", "dest_ip": "", "status": "success",
         "process": "", "bytes_out": 0, "message": ""}
    e.update(kw)
    return json.dumps(e)


# --------------------------------------------------------------------------
def test_tailer_returns_only_complete_lines():
    path = os.path.join(TMP, "tail.ndjson")
    t = live.Tailer(path)
    assert t.read() == [], "a missing file should read as empty"
    with open(path, "w", encoding="utf-8") as f:
        f.write('{"a": 1}\n{"b": 2}\n{"c": 3')     # third line half-written
    assert t.read() == ['{"a": 1}', '{"b": 2}']
    with open(path, "a", encoding="utf-8") as f:
        f.write('}\n{"d": 4}\n')
    assert t.read() == ['{"c": 3}', '{"d": 4}'], "the partial line was not completed"
    assert t.read() == [], "nothing new, nothing returned"
    print("    complete lines only; a half-written line is finished on the next tick")


def test_tailer_resets_on_truncation():
    path = os.path.join(TMP, "trunc.ndjson")
    with open(path, "w", encoding="utf-8") as f:
        f.write('{"a": 1}\n{"b": 2}\n')
    t = live.Tailer(path)
    assert len(t.read()) == 2
    with open(path, "w", encoding="utf-8") as f:   # truncate and rewrite, shorter
        f.write('{"z": 9}\n')
    assert t.read() == ['{"z": 9}'], "truncated file was not re-read from byte 0"
    assert t.resets == 1
    print("    a file smaller than our offset is re-read from the start")


def test_window_evicts_old_events():
    eng = live.LiveRules(RULES, "flat", window_minutes=10, scratch_dir=TMP)
    t0 = datetime(2026, 10, 20, 8, 0, 0)
    eng.process([_event(t0 + timedelta(minutes=m)) for m in range(5)])
    assert eng.window_rows() == 5
    evicted_total = 0
    for step in range(1, 7):     # one hour later in 10-minute steps
        _, _, ev = eng.process([_event(t0 + timedelta(minutes=10 * step + m))
                                for m in range(5)])
        evicted_total += ev
    assert eng.window_rows() <= 15, f"window holds {eng.window_rows()} rows"
    assert evicted_total >= 20, f"only {evicted_total} evicted"
    print(f"    10-minute window keeps {eng.window_rows()} recent rows, "
          f"evicted {evicted_total}")


def test_aggregate_alerts_once_per_burst():
    eng = live.LiveRules(RULES, "flat", scratch_dir=TMP)
    t0 = datetime(2026, 10, 20, 9, 0, 0)
    fails = [_event(t0 + timedelta(seconds=5 * i), event_id=4625, status="failed",
                    user="bob") for i in range(60)]
    fired = []
    for i in range(0, 60, 10):           # the burst arrives over six ticks
        new, updated, _ = eng.process(fails[i:i + 10])
        fired += [a for a in new if a["rule_name"] == "Brute Force Login Attempts"]
    assert len(fired) == 1, f"burst fired {len(fired)} alerts, expected 1"
    alert = eng.alerts[fired[0]["alert_id"]]
    assert alert["event_count"] == 60, f"count not updated: {alert['event_count']}"
    # A second, separate burst an hour later is a new alert.
    later = [_event(t0 + timedelta(hours=1, seconds=5 * i), event_id=4625,
                    status="failed", user="bob") for i in range(30)]
    new, _, _ = eng.process(later)
    assert sum(a["rule_name"] == "Brute Force Login Attempts" for a in new) == 1
    print("    one alert per burst, updated to its full count (60); a later burst is new")


def _run_live(path, log_format, rules, chunk=4000):
    """Feed a file to live mode `chunk` lines per tick, as the detector would."""
    eng = live.LiveRules(rules, log_format, scratch_dir=TMP)
    corr = live.LiveCorrelator()
    with open(path, encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]
    for i in range(0, len(lines), chunk):
        new, updated, _ = eng.process(lines[i:i + chunk])
        corr.update(new, updated)
    return eng, corr


def _incident_key(inc):
    return (tuple(sorted((str(e["timestamp"]), e["rule_name"], str(e["host"]),
                          str(e["user"])) for e in inc["events"])),
            tuple(sorted({e["mitre_technique"] for e in inc["events"]})))


def _compare_with_batch(path, log_format, rules_name):
    db = os.path.join(TMP, f"batch-{log_format}.db")
    rules_path = os.path.join(ROOT, rules_name)
    import contextlib, io  # noqa: E401
    with contextlib.redirect_stdout(io.StringIO()):
        cp_parser.run(path, rules_path, db, "2GB", log_format)
    batch = graph_engine.analyse(db)
    eng, corr = _run_live(path, log_format, cp_parser.load_rules(rules_path))
    live_inc = corr.reported()
    b = sorted(_incident_key(i) for i in batch)
    l = sorted(_incident_key(i) for i in live_inc)
    assert len(batch) == len(live_inc), \
        f"batch has {len(batch)} incident(s), live has {len(live_inc)}"
    assert b == l, "live incidents differ from batch incidents"
    risk_b = sorted(i["risk_score"] for i in batch)
    risk_l = sorted(i["risk_score"] for i in live_inc)
    return batch, live_inc, corr, risk_b, risk_l


def test_incremental_graph_matches_batch_on_sample():
    path = os.path.join(ROOT, "data", "sample.ndjson")
    if not os.path.exists(path) and _skip("data/sample.ndjson missing"):
        return
    batch, live_inc, corr, rb, rl = _compare_with_batch(path, "flat", "rules.yaml")
    labels = sorted({e["mitre_technique"] for i in live_inc for e in i["events"]})
    print(f"    {len(live_inc)} incident(s), identical detections and ATT&CK labels "
          f"({', '.join(labels)}); risk batch {rb} vs live {rl}")


def test_incremental_graph_matches_batch_with_ambient_noise():
    gen = os.path.join(os.path.dirname(ROOT), "edr_log_generator.py")
    if not os.path.exists(gen) and _skip("edr_log_generator.py not found"):
        return
    import subprocess
    raw, ready = os.path.join(TMP, "raw.json"), os.path.join(TMP, "edr.json")
    subprocess.run([sys.executable, gen, "--count", "30000", "--rate", "0",
                    "--alert-ratio", "0.05", "--output", "file", "--file", raw,
                    "--seed", "7"], check=True, capture_output=True)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "prepare_edr.py"),
                    "--input", raw, "--output", ready, "--seed", "7"],
                   check=True, capture_output=True, cwd=TMP)
    batch, live_inc, corr, rb, rl = _compare_with_batch(ready, "ecs", "rules_ecs.yaml")
    assert corr.ambient, "this data was meant to exercise ambient techniques"
    print(f"    {len(live_inc)} incident(s) identical with {len(corr.ambient)} ambient "
          f"technique(s); {corr.rebuilds} full rebuild(s); risk batch {rb} vs live {rl}")


def test_memory_stays_flat_over_a_long_replay():
    try:
        import psutil
    except ImportError:
        _skip("psutil not installed")
        return
    import random
    rnd = random.Random(1)
    eng = live.LiveRules(RULES, "flat", scratch_dir=TMP)
    corr = live.LiveCorrelator()
    t0 = datetime(2026, 10, 1, 0, 0, 0)
    proc = psutil.Process()
    samples, windows = [], []
    # 48 hours of background noise, 2,000 lines per simulated tick of 5 minutes:
    # 1.15 million lines in all -- far more than the window may ever hold.
    for tick in range(576):
        base = t0 + timedelta(minutes=5 * tick)
        lines = [_event(base + timedelta(seconds=rnd.random() * 300),
                        host=f"WS-{rnd.randrange(300):03d}",
                        user=f"user{rnd.randrange(500):03d}")
                 for _ in range(2000)]
        new, updated, _ = eng.process(lines)
        corr.update(new, updated)
        windows.append(eng.window_rows())
        if tick % 48 == 47:
            samples.append(proc.memory_info().rss / 1e6)
    window_cap = 2000 * (live.LIVE_WINDOW_MINUTES // 5 + 1)
    assert max(windows) <= window_cap, f"window grew to {max(windows)} rows"
    growth = samples[-1] - samples[1]
    assert growth < 60, f"RSS grew {growth:.0f} MB between hour 8 and hour 48"
    print(f"    1,152,000 lines over 48 h of event time: window peaked at "
          f"{max(windows):,} rows (cap {window_cap:,}); RSS {samples[1]:.0f} MB at "
          f"8 h -> {samples[-1]:.0f} MB at 48 h")


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"\nChronoPath live mode -- {len(tests)} test(s)\n" + "=" * 62)
    failed = []
    for fn in tests:
        print(f"\n  {fn.__name__}")
        try:
            fn()
        except AssertionError as exc:
            print(f"    FAIL: {exc}")
            failed.append((fn.__name__, exc))
        except Exception as exc:  # noqa: BLE001
            print(f"    ERROR: {type(exc).__name__}: {exc}")
            failed.append((fn.__name__, exc))
    shutil.rmtree(TMP, ignore_errors=True)
    print("\n" + "=" * 62)
    if failed:
        print(f"  {len(failed)} of {len(tests)} failed:")
        for name, exc in failed:
            print(f"    - {name}: {exc}")
        return 1
    print(f"  all {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
