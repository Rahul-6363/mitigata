"""
test_inferred.py -- Tests for the inferred-schema adapter (src/inferred_adapter.py).

The adapter's promise: a log whose layout is scrambled -- keys renamed, keys
reordered, no keys at all, timestamps rewritten -- produces the SAME detections
and the SAME kill chain as the original file. And when a field the rules need
is missing, the run says so loudly instead of returning a silent zero.

Each test builds a scrambled copy of one of the two samples, runs the real
parser on it, and compares against the original file run through its own
adapter:

  a) keys renamed with aliases (and one fuzzy name)
  b) key order shuffled
  c) headerless CSV with shuffled column order
  d) timestamps rewritten as epoch milliseconds
  e) one rule-critical field dropped -> a warning naming it, not a crash

plus: the four existing formats are still detected exactly as before.

Run:  python tests/test_inferred.py
"""

import contextlib
import csv
import io
import json
import os
import random
import re
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.chdir(ROOT)                      # rule files are resolved from the project root

import duckdb  # noqa: E402

import graph_engine  # noqa: E402
import inferred_adapter  # noqa: E402
import parser as cp_parser  # noqa: E402

FLAT = os.path.join(ROOT, "data", "sample.ndjson")
APPLOG = os.path.join(ROOT, "sample1.log")
WORK = tempfile.mkdtemp(prefix="inferred-test-")
RNG = random.Random(7)


def _skip(reason):
    print(f"    SKIP: {reason}")
    return True


# --------------------------------------------------------------------------
# Running the pipeline
# --------------------------------------------------------------------------
_ORIGINALS = {}


def _run(path, log_format=None):
    """(outcome, stderr) for one parser run on `path`."""
    db = os.path.join(WORK, os.path.basename(path) + ".db")
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        cp_parser.run(path, db_path=db, memory_limit="2GB", log_format=log_format)
    con = duckdb.connect(db, read_only=True)
    rows = con.execute("SELECT rule_name, kill_chain_stage FROM suspicious_events").fetchall()
    con.close()
    incidents = graph_engine.analyse(db)
    path_ = [[(s["stage"], s["technique"], s["rule"]) for s in graph_engine.get_attack_path(i)]
             for i in incidents]
    return {"count": len(rows), "by_rule": Counter(rows), "paths": path_}, err.getvalue()


def _original(path):
    if path not in _ORIGINALS:
        _ORIGINALS[path] = _run(path)[0]
    return _ORIGINALS[path]


def _same(name, original, got):
    assert got["count"] == original["count"], \
        f"{name}: {got['count']} detections, original {original['count']}"
    assert got["by_rule"] == original["by_rule"], \
        f"{name}: detections differ by rule: {got['by_rule']} vs {original['by_rule']}"
    assert got["paths"] == original["paths"], \
        f"{name}: kill chain differs:\n  {got['paths']}\n  vs {original['paths']}"


def _mapping_line(path):
    m = inferred_adapter.detect_inferred(path)
    return ", ".join(f"{f}<-{v['source'] if not isinstance(v['source'], (list, tuple)) else '+'.join(v['source'])}"
                     for f, v in m["fields"].items()) + f"  (confidence {m['confidence']:.2f})"


# --------------------------------------------------------------------------
# Scrambling
# --------------------------------------------------------------------------
FLAT_RENAMES = {"timestamp": "@t", "host": "hostname", "user": "user_nm",
                "event_id": "evt_id", "src_ip": "sip", "dest_ip": "dst",
                "status": "outcome", "process": "proc_name",
                "bytes_out": "bytes_sent", "message": "msg"}
APPLOG_RENAMES = {"event_id": "EventID", "src_ip": "client_ip", "user": "uname",
                  "action": "operation", "status": "result", "msg": "description",
                  "bytes": "byte_count", "change": "modification"}

_APPLOG_LINE = re.compile(r"^(\S+ \S+) (\S+) \[([^\]]*)\] (.*)$")
_PAIR = re.compile(r'([A-Za-z_]\w*)=("[^"]*"|\S+)')


def _flat_records():
    with open(FLAT, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _applog_records():
    """(timestamp text, level, component, [(key, raw value)]) per line."""
    with open(APPLOG, encoding="utf-8") as f:
        for line in f:
            m = _APPLOG_LINE.match(line.rstrip("\n"))
            if m:
                yield m.group(1), m.group(2), m.group(3), _PAIR.findall(m.group(4))


def _write(name, lines):
    path = os.path.join(WORK, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            f.write(line + "\n")
    return path


def _epoch_ms(text):
    # Naive timestamps are read as UTC, the same way the adapter writes them back.
    dt = datetime.fromisoformat(text.replace(" ", "T")).replace(tzinfo=timezone.utc)
    return int(round(dt.timestamp() * 1000))


def flat_variant(kind):
    out = []
    order = list(FLAT_RENAMES)
    RNG.shuffle(order)
    for r in _flat_records():
        if kind == "renamed":
            out.append(json.dumps({FLAT_RENAMES[k]: v for k, v in r.items()}))
        elif kind == "shuffled":
            keys = list(r)
            RNG.shuffle(keys)
            out.append(json.dumps({k: r[k] for k in keys}))
        elif kind == "csv":
            buf = io.StringIO()
            csv.writer(buf, lineterminator="").writerow([r[k] for k in order])
            out.append(buf.getvalue())
        elif kind == "epoch":
            out.append(json.dumps({**r, "timestamp": _epoch_ms(r["timestamp"])}))
        elif kind == "dropped":
            out.append(json.dumps({FLAT_RENAMES[k]: v for k, v in r.items() if k != "dest_ip"}))
    return _write(f"flat_{kind}.{'csv' if kind == 'csv' else 'ndjson'}", out)


def applog_variant(kind):
    recs = list(_applog_records())
    out = []
    if kind == "csv":
        keys = list(dict.fromkeys(k for *_, pairs in recs for k, _ in pairs))
        cols = ["timestamp", "level", "component"] + keys
        RNG.shuffle(cols)
        for ts, level, comp, pairs in recs:
            row = {"timestamp": ts, "level": level, "component": comp,
                   **{k: v.strip('"') for k, v in pairs}}
            buf = io.StringIO()
            csv.writer(buf, lineterminator="").writerow([row.get(c, "") for c in cols])
            out.append(buf.getvalue())
        return _write("applog_csv.csv", out)
    for ts, level, comp, pairs in recs:
        if kind == "renamed":
            pairs = [(APPLOG_RENAMES.get(k, k), v) for k, v in pairs]
        elif kind == "shuffled":
            pairs = pairs[:]
            RNG.shuffle(pairs)
        elif kind == "epoch":
            ts = str(_epoch_ms(ts))
        elif kind == "dropped":
            pairs = [(APPLOG_RENAMES.get(k, k), v) for k, v in pairs if k != "change"]
        out.append(f"{ts} {level} [{comp}] " + " ".join(f"{k}={v}" for k, v in pairs))
    return _write(f"applog_{kind}.log", out)


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
def test_existing_formats_unchanged():
    expected = {FLAT: "flat", APPLOG: "applog"}
    for name, fmt in (("firex-30G.log", "fortigate"), ("firex-10G.log", "fortigate")):
        if os.path.exists(os.path.join(ROOT, name)):
            expected[os.path.join(ROOT, name)] = fmt
    ecs = _write("ecs.ndjson", [json.dumps({"@timestamp": "2026-10-20T08:00:00Z",
                                            "event": {"kind": "event"},
                                            "host": {"name": "WS-01"}})])
    expected[ecs] = "ecs"
    for path, fmt in expected.items():
        got = cp_parser.detect_format(path)
        assert got == fmt, f"{os.path.basename(path)} detected as {got}, expected {fmt}"
    print(f"    {len(expected)} file(s) of the existing formats detected exactly as before")


def _variant_test(make, original_path, kind, expect_format):
    if not os.path.exists(original_path) and _skip(f"{original_path} missing"):
        return
    path = make(kind)
    fmt = cp_parser.detect_format(path)
    assert fmt == expect_format, f"{os.path.basename(path)} detected as {fmt}"
    got, err = _run(path)
    _same(os.path.basename(path), _original(original_path), got)
    if fmt == "inferred":
        assert "INFERRED SCHEMA" in err, "the mapping was not printed to stderr"
        assert "WARNING" not in err, f"unexpected warning:\n{err}"
        print(f"    {os.path.basename(path)}: {_mapping_line(path)}")
    else:
        # Still a known format; also prove the inferred reader agrees.
        _same(os.path.basename(path) + " (forced inferred)",
              _original(original_path), _run(path, "inferred")[0])
        print(f"    {os.path.basename(path)}: detected as {fmt}; forced inferred "
              f"also matches -- {_mapping_line(path)}")
    o = _original(original_path)
    print(f"      {got['count']} detections, {len(got['paths'])} incident(s), "
          f"same as the original ({o['count']})")


def test_a_renamed_keys_flat():
    _variant_test(flat_variant, FLAT, "renamed", "inferred")


def test_a_renamed_keys_applog():
    _variant_test(applog_variant, APPLOG, "renamed", "inferred")


def test_b_shuffled_keys_flat():
    _variant_test(flat_variant, FLAT, "shuffled", "flat")


def test_b_shuffled_keys_applog():
    _variant_test(applog_variant, APPLOG, "shuffled", "applog")


def test_c_headerless_csv_flat():
    _variant_test(flat_variant, FLAT, "csv", "inferred")


def test_c_headerless_csv_applog():
    _variant_test(applog_variant, APPLOG, "csv", "inferred")


def test_d_epoch_ms_flat():
    _variant_test(flat_variant, FLAT, "epoch", "inferred")


def test_d_epoch_ms_applog():
    _variant_test(applog_variant, APPLOG, "epoch", "inferred")


def _dropped_test(make, original_path, field, rule):
    path = make("dropped")
    got, err = _run(path)               # must not raise
    assert "WARNING" in err and field in err and rule in err, \
        f"no warning naming {field} / {rule}:\n{err}"
    o = _original(original_path)
    assert got["count"] < o["count"], "dropping a rule field should cost detections"
    print(f"    {os.path.basename(path)}: warned that {field} is missing "
          f"(needed by '{rule}'); {got['count']} of {o['count']} detections, no crash")


def test_e_dropped_field_flat():
    _dropped_test(flat_variant, FLAT, "dest_ip", "Large Outbound Data Transfer")


def test_e_dropped_field_applog():
    _dropped_test(applog_variant, APPLOG, "app_change", "Security Monitoring Disabled")


def test_unreadable_layout_declines():
    path = _write("noise.txt", ["lorem ipsum dolor", "sit amet consectetur", "adipiscing elit"])
    assert inferred_adapter.detect_inferred(path) is None
    assert cp_parser.detect_format(path) == "flat"
    print(f"    no timestamp column -> declined ({inferred_adapter.why_not(path)}); "
          f"falls back to flat as before")


def test_sql_escaping():
    # A key with quotes in its name must not break or inject into the SQL.
    rec = {"ts": "2026-10-20T08:00:00", "src'ip\"x": "10.0.0.1", "sip": "10.0.0.2",
           "host": "WS-01", "user": "bob"}
    path = _write("quotes.ndjson", [json.dumps(rec)] * 3)
    m = inferred_adapter.detect_inferred(path)
    m["fields"]["dest_ip"] = {"source": "src'ip\"x", "score": 1.0, "how": "test"}
    con = duckdb.connect()
    row = con.execute(f"SELECT src_ip, dest_ip FROM "
                      f"{inferred_adapter.inferred_source_expr(path, m)}").fetchone()
    assert row == ("10.0.0.2", "10.0.0.1"), row
    print("    quotes in key names are escaped in the generated SQL")


# --------------------------------------------------------------------------
def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"\nInferred schema adapter -- {len(tests)} test(s)\n" + "=" * 62)
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
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n" + "=" * 62)
    if failed:
        print(f"  {len(failed)} of {len(tests)} failed:")
        for name, exc in failed:
            print(f"    - {name}: {str(exc)[:300]}")
        return 1
    print(f"  all {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
