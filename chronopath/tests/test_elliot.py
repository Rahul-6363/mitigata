"""
test_elliot.py -- Tests for the investigator (src/elliot).

The investigator's value rests on one promise: it never states something the
data does not show. So most of these tests attack that promise directly:

  1. Every citation in every output exists in the evidence pack.
  2. No deterministic output mentions a timestamp or address that is not in
     the evidence pack.
  3. The validator rejects a fabricated model answer -- unknown citation,
     invented timestamp, invented address, a claimed action.
  4. Nothing claims an action was performed; recommendations stay recommendations.
  5. Predictions are labelled as predictions.
  6. A theory is abandoned when contradictory evidence appears, and only then.
  7. Memory: completed work is not suggested again, unless its evidence changed.
  8. Every standard question is answered with no language model at all.

Tests 1, 2, 4, 5 and 8 run against every ChronoPath database in the project
folder; 3, 6 and 7 use built-in data and always run.

Run:  python tests/test_elliot.py
"""

import glob
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import graph_engine  # noqa: E402
from elliot import QUESTIONS, Investigator  # noqa: E402
from elliot import analysts, evidence, hypotheses  # noqa: E402
from elliot.engine import ACTION_CLAIM, CITE_RE, validate  # noqa: E402
from elliot.memory import Memory  # noqa: E402

MEMORY = tempfile.mkdtemp(prefix="elliot-test-")


def _skip(reason):
    print(f"    SKIP: {reason}")
    return True


def _databases(max_rows=600_000):
    """Every project database small enough to correlate quickly in a test."""
    import duckdb
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "*.db"))):
        try:
            con = duckdb.connect(path, read_only=True)
            n = con.execute("SELECT COUNT(*) FROM suspicious_events").fetchone()[0]
            con.close()
        except Exception:  # noqa: BLE001
            continue
        if 0 < n <= max_rows:
            out.append(path)
    return out


_CACHE = {}


def _investigations():
    """(db, Investigator, answers) for the top incidents of each database."""
    if "all" in _CACHE:
        return _CACHE["all"]
    runs = []
    for db in _databases():
        for inc in graph_engine.analyse(db)[:3]:
            inv = Investigator(db, inc, memory_root=MEMORY, use_llm=False)
            answers = [inv.ask(q) for q in QUESTIONS]
            runs.append((os.path.basename(db), inv, answers))
    _CACHE["all"] = runs
    return runs


def _texts(inv, answers):
    """Every piece of text the investigator produced, with what it cites."""
    b = inv.brief()
    for f in b["findings"]:
        yield " ".join(str(f[k]) for k in analysts.SECTIONS), f["cites"]
    for h in b["hypotheses"]:
        for x in h["supports"] + h["challenges"]:
            yield x["text"], x["cites"]
        for r in h["self_review"]:
            yield r["answer"], r["cites"]
    for m in b["next_moves"]:
        yield m["action"] + " " + m["reason"], m["cites"]
    for a in answers:
        yield a["headline"], []
        for s in a["sections"]:
            yield " ".join(str(s.get(k, "")) for k in analysts.SECTIONS), s.get("cites", [])


# --------------------------------------------------------------------------
def test_every_citation_exists():
    runs = _investigations()
    if not runs and _skip("no ChronoPath database in the project folder"):
        return
    checked = 0
    for db, inv, answers in runs:
        allowed = set(inv.pack.items) | {h.id for h in inv.hypotheses}
        for text, cites in _texts(inv, answers):
            inline = {c.strip() for g in CITE_RE.findall(text) for c in g.split(",")}
            bad = (set(cites) | inline) - allowed
            assert not bad, f"{db} {inv.incident['id']}: cites {sorted(bad)} -- not in the pack"
            checked += len(cites) + len(inline)
    print(f"    {checked} citation(s) across {len(runs)} incident(s), all exist")


def test_no_invented_timestamps_or_addresses():
    runs = _investigations()
    if not runs and _skip("no ChronoPath database in the project folder"):
        return
    for db, inv, answers in runs:
        for text, _ in _texts(inv, answers):
            problems = [p for p in validate(text, inv.pack, inv.hypotheses)
                        if "timestamp" in p or "address" in p or "cites" in p]
            assert not problems, f"{db} {inv.incident['id']}: {problems[0]} in: {text[:160]}"
    print(f"    every timestamp and address quoted exists in the evidence")


def test_validator_rejects_fabrication():
    inc = _synthetic_incident(evasion=True, external=True)
    pack = evidence.build("does-not-exist.db", inc)
    good = ("Observation: the account was created at 2026-10-28T06:13:50 [E1]. "
            "Reasoning: x. Connection: from 8.8.8.8 [E2]. Hypothesis: y. "
            "Counterargument: z. Unknowns: w. Next move: request the logs.")
    assert validate(good, pack) == [], validate(good, pack)
    bad = ("Observation: I have checked the server [E9]. Reasoning: at "
           "1999-01-01T00:00:00 from 203.0.113.250. Connection: -. Hypothesis: -. "
           "Counterargument: -. Unknowns: -. Next move: -.")
    problems = " | ".join(validate(bad, pack))
    for expected in ("E9", "1999-01-01", "203.0.113.250", "claims an action"):
        assert expected in problems, f"validator missed {expected!r}: {problems}"
    print("    unknown citation, invented timestamp, invented address and a "
          "claimed action are all rejected")


def test_no_claimed_actions():
    runs = _investigations()
    if not runs and _skip("no ChronoPath database in the project folder"):
        return
    for db, inv, answers in runs:
        for text, _ in _texts(inv, answers):
            m = ACTION_CLAIM.search(text)
            assert not m, f"{db}: claims an action -- '{m.group(0)}' in: {text[:160]}"
        for m in inv.next_moves():
            assert m["label"] == "RECOMMENDATION"
    print("    nothing claims to have been done; moves are labelled recommendations")


def test_keys_are_unique():
    # The dashboard keys a button on each finding and each move; a repeated key
    # crashed the page (an account in two identity-pivot links).
    runs = _investigations()
    if not runs and _skip("no ChronoPath database in the project folder"):
        return
    for db, inv, _ in runs:
        f_keys = [f.key for f in inv.findings]
        m_keys = [m["key"] for m in inv.next_moves()]
        assert len(f_keys) == len(set(f_keys)), f"{db}: duplicate finding key"
        assert len(m_keys) == len(set(m_keys)), f"{db}: duplicate move key"
    print("    every finding and every next move has a unique key")


def test_predictions_are_labelled():
    runs = _investigations()
    if not runs and _skip("no ChronoPath database in the project folder"):
        return
    for db, inv, _ in runs:
        a = inv.ask("What would an attacker likely have done next?")
        for s in a["sections"]:
            assert s["labels"]["hypothesis"] == "PREDICTION", "prediction not labelled"
            assert "not observed" in s["hypothesis"].lower() or "nothing in the data" \
                in s["hypothesis"].lower(), "prediction not marked as unobserved"
        for item in inv.pack.of("P"):
            assert item.label == "PREDICTION"
    print("    projected attacker moves are labelled PREDICTION and unobserved")


def test_theory_abandoned_only_on_contradiction():
    # Logging disabled and an external admin login: routine work is contradicted.
    pack = evidence.build("does-not-exist.db", _synthetic_incident(evasion=True, external=True))
    hs = {h.id: h for h in hypotheses.generate(pack, analysts.observe(pack))}
    assert hs["H3"].status == "abandoned", f"H3 is {hs['H3'].status}"
    assert "Two strong contradictions" in hs["H3"].status_reason
    # Without that evidence, the same theory must stay open.
    pack = evidence.build("does-not-exist.db", _synthetic_incident(evasion=False, external=False))
    hs = {h.id: h for h in hypotheses.generate(pack, analysts.observe(pack))}
    assert hs["H3"].status != "abandoned", "abandoned with no contradicting evidence"
    print("    'routine administration' is abandoned with evidence against it, "
          "and kept open without")


def test_memory_suppresses_done_work_until_evidence_changes():
    root = tempfile.mkdtemp(prefix="elliot-mem-")
    try:
        inc = _synthetic_incident(evasion=True, external=True)
        mem = Memory("x.db", inc, root=root)
        assert mem.offer("move:a", "do a", "fp1") == "new"
        assert mem.resolve("move:a", "done")
        mem.save()
        mem = Memory("x.db", inc, root=root)          # a later session
        assert mem.offer("move:a", "do a", "fp1") is None, "completed work suggested again"
        assert mem.offer("move:a", "do a", "fp2") == "revisit", "changed evidence not revisited"
        mem.set_verdict("H2", "rejected", "owner on leave")
        mem.save()
        mem = Memory("x.db", inc, root=root)
        assert mem.verdict("H2") == "rejected"
        assert any("Rejected H2" in d["text"] for d in mem.data["decisions"])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("    done work stays done; changed evidence brings it back; verdicts persist")


def test_every_question_answered_without_a_model():
    runs = _investigations()
    if not runs and _skip("no ChronoPath database in the project folder"):
        return
    for db, inv, answers in runs:
        for q, a in zip(QUESTIONS, answers):
            assert a["intent"] == QUESTIONS[q], f"{q!r} routed to {a['intent']}"
            assert a["narrative"] is None and a["headline"], f"{db}: no answer to {q!r}"
    print(f"    all {len(QUESTIONS)} questions answered deterministically on "
          f"{len(runs)} incident(s)")


# --------------------------------------------------------------------------
def _synthetic_incident(evasion, external):
    def ev(ts, rule, tech, stage, user, src="10.0.0.5", sev=8, outcome="observed"):
        return {"timestamp": ts, "host": "fw-01", "user": user, "event_id": 0,
                "src_ip": src, "dest_ip": "", "status": "", "process": "",
                "bytes_out": 0, "message": rule, "rule_name": rule,
                "mitre_technique": tech, "mitre_name": tech, "kill_chain_stage": stage,
                "severity": sev, "event_count": 1, "outcome": outcome}
    events = [
        ev("2026-10-28T06:13:50", "Firewall Admin Account Created", "T1136",
           "Persistence", "alice"),
        ev("2026-10-28T06:19:01", "Admin Login Successful from External IP"
           if external else "Admin Login Successful", "T1078", "Initial Access", "bob",
           src="8.8.8.8" if external else "10.0.0.5"),
    ]
    if evasion:
        events.append(ev("2026-10-28T06:24:37", "Firewall Logging Disabled", "T1562",
                         "Defense Evasion", "alice", sev=10))
    inc = graph_engine.build_incident("INC-T1", events)
    return inc


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"\nElliot investigator -- {len(tests)} test(s)\n" + "=" * 62)
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
    shutil.rmtree(MEMORY, ignore_errors=True)
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
