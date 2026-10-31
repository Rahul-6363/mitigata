"""
test_chronopath2.py -- Tests for the ChronoPath 2.0 evidence and gap layer.

WHY THESE TESTS AND NOT OTHERS
------------------------------
2.0 makes claims about absence and about the quality of evidence. Those are
exactly the claims that rot quietly: a gap ledger that drifts into emitting
boilerplate still looks right, and a link grader that starts calling everything
HARD still produces a full Evidence tab. Neither failure announces itself.

So these tests target the properties that must hold for the output to mean
anything, rather than aiming at line coverage:

  1. Every link in a reported incident has a grade and a non-empty reason.
     An ungraded link is worse than no link -- it looks like evidence.
  2. Rejected infrastructure and placeholder values never appear as accepted
     links. This is the filter that keeps the false-alarm rate at 0%.
  3. Gap classifications come only from the closed vocabulary, and every gap
     carries a basis. A gap without a basis is an opinion.
  4. No gap claims deletion or tampering without a positive event. This is
     ground rule 5, and it is the single most important test here.
  5. Unparseable timestamps are flagged, not silently sorted to the epoch.
  6. The experiment leaves no trace of the removed host.
  7. The 1.x numbers are unchanged -- the regression gate.

Run:  python -m pytest tests/test_chronopath2.py -v
      python tests/test_chronopath2.py          (no pytest needed)
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import duckdb  # noqa: E402

import graph_engine  # noqa: E402
from chronopath2 import blind_window, gaps, link_evidence, respond  # noqa: E402

# The databases the tests read. Both are products of a real run; these tests
# deliberately verify the ACTUAL output on the organisers' data rather than a
# synthetic fixture, because the failures that matter here are failures against
# real data -- a fixture would have been built to pass.
FIREX_DB = os.path.join(ROOT, "firex.db")
EDR_DB = os.path.join(ROOT, "edr.db")

# The regression gate, from docs/baseline_before_2.0.md.
BASELINE = {
    FIREX_DB: {"incidents": 5, "detections": 373239},
    EDR_DB: {"incidents": 1, "detections": 26119},
}


def _skip(reason):
    print(f"    SKIP: {reason}")
    return True


# --------------------------------------------------------------------------
# 1. Every link is graded and explained
# --------------------------------------------------------------------------

def test_every_link_has_grade_and_reason():
    for db in (FIREX_DB, EDR_DB):
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            rows = con.execute(
                "SELECT link_id, grade, reason FROM cp2_links").fetchall()
        finally:
            con.close()
        assert rows, f"{db}: no links recorded at all"
        valid = {link_evidence.GRADE_HARD, link_evidence.GRADE_SOFT,
                 link_evidence.GRADE_INFERRED, link_evidence.GRADE_UNRESOLVED}
        for link_id, grade, reason in rows:
            assert grade in valid, f"{link_id}: grade {grade!r} is not a grade"
            assert reason and reason.strip(), f"{link_id}: empty reason"
            # A reason that does not mention the evidence is not a reason.
            assert len(reason.strip()) > 20, f"{link_id}: reason too thin"
        print(f"    {os.path.basename(db)}: {len(rows)} links, all graded "
              f"and explained")


# --------------------------------------------------------------------------
# 2. Rejected values never become accepted links
# --------------------------------------------------------------------------

def test_rejected_values_are_not_accepted_links():
    """
    The filter that holds the false-alarm rate at 0%.

    If a value was rejected as infrastructure or as a placeholder, it must not
    also appear as the basis of an accepted link in the same incident -- that
    would mean the engine both refused and used it.
    """
    for db in (FIREX_DB, EDR_DB):
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            rejected = con.execute(
                "SELECT incident_id, attribute_value FROM cp2_rejected_links"
            ).fetchall()
            accepted = con.execute(
                "SELECT incident_id, attribute_value FROM cp2_links"
            ).fetchall()
        finally:
            con.close()
        accepted_set = {(i, v) for i, v in accepted}
        for inc, value in rejected:
            assert (inc, value) not in accepted_set, (
                f"{inc}: {value!r} was rejected AND used as an accepted link")
        # The placeholder must never be an accepted link anywhere.
        for inc, value in accepted:
            assert str(value).strip() not in link_evidence.PLACEHOLDERS, (
                f"{inc}: placeholder {value!r} used as a link")
        print(f"    {os.path.basename(db)}: {len(rejected)} rejected value(s), "
              f"none reused as an accepted link")


# --------------------------------------------------------------------------
# 3. Gap classifications come from the closed list, with a basis
# --------------------------------------------------------------------------

def test_gap_classifications_and_basis():
    for db in (FIREX_DB, EDR_DB):
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            rows = con.execute(
                "SELECT gap_id, classification, basis, impact, "
                "evidence_request FROM cp2_gaps").fetchall()
        finally:
            con.close()
        assert rows, f"{db}: no gaps recorded"
        for gap_id, classification, basis, impact, request in rows:
            assert classification in gaps.CLASSIFICATIONS, (
                f"{gap_id}: {classification!r} is not an allowed "
                f"classification")
            assert basis and basis.strip(), f"{gap_id}: no basis"
            assert impact and impact.strip(), f"{gap_id}: no impact"
            assert request and request.strip(), (
                f"{gap_id}: no evidence request -- a gap the analyst cannot "
                f"act on is just bad news")
        print(f"    {os.path.basename(db)}: {len(rows)} gaps, all classified "
              f"from the closed list with a basis")


# --------------------------------------------------------------------------
# 4. GROUND RULE 5: missing is never reported as malicious
# --------------------------------------------------------------------------

def test_absence_is_never_called_deletion():
    """
    The most important test in this file.

    LOGGING_DISABLED_BY_ACTOR is the only classification that accuses anyone of
    destroying evidence, and it may only be issued when a positive disable
    event exists. Everything else -- however suspicious it looks -- must be
    NOT_COLLECTED or COVERAGE_UNKNOWN.
    """
    for db in (FIREX_DB, EDR_DB):
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            accusing = con.execute(
                "SELECT gap_id, basis FROM cp2_gaps "
                "WHERE classification = 'LOGGING_DISABLED_BY_ACTOR'"
            ).fetchall()
            all_gaps = con.execute(
                "SELECT gap_id, classification, basis, impact FROM cp2_gaps"
            ).fetchall()
        finally:
            con.close()

        # Any accusation must cite the event that justifies it.
        for gap_id, basis in accusing:
            low = (basis or "").lower()
            assert "disabl" in low, (
                f"{gap_id}: accuses an actor of disabling logging without "
                f"citing the disable event")

        # No gap may imply deletion in prose while classified as mere absence.
        forbidden = ("deleted the log", "wiped", "destroyed the evidence",
                     "tampered", "retention expired", "logs were deleted")
        for gap_id, classification, basis, impact in all_gaps:
            if classification in ("LOGGING_DISABLED_BY_ACTOR",):
                continue
            text = f"{basis} {impact}".lower()
            for phrase in forbidden:
                assert phrase not in text, (
                    f"{gap_id} ({classification}): prose claims {phrase!r} "
                    f"without the classification to support it")
        print(f"    {os.path.basename(db)}: {len(all_gaps)} gaps, "
              f"{len(accusing)} accusation(s), all evidenced")


def test_blind_window_needs_a_positive_event():
    """A blind window cannot be opened by an absence -- only by a real event."""
    # An incident with no logging-disable event must yield no blind window,
    # however empty its timeline looks.
    quiet = {"id": "TEST-01", "start_time": "2026-10-23T10:00:00",
             "end_time": "2026-10-23T12:00:00",
             "events": [{"timestamp": "2026-10-23T10:00:00", "host": "h1",
                         "user": "u1", "mitre_technique": "T1078",
                         "rule_name": "Admin Login", "message": "login"}]}
    if not os.path.exists(FIREX_DB):
        _skip("firex.db missing")
        return
    con = duckdb.connect(FIREX_DB, read_only=True)
    try:
        found = blind_window.analyse_incident(con, quiet,
                                              parse_ts=graph_engine._parse_ts)
    finally:
        con.close()
    assert found == [], (
        "a blind window was opened for an incident with no disable event")
    print("    no disable event -> no blind window (correct)")


def test_blind_window_classification_is_measured():
    """
    The INC-02 result must be whichever case the DATA shows.

    This test does not assert a particular classification -- that would bake in
    today's answer and defeat the point. It asserts the classification is one
    of the two legitimate outcomes and that it cites measured numbers.
    """
    if not os.path.exists(FIREX_DB):
        _skip("firex.db missing")
        return
    con = duckdb.connect(FIREX_DB, read_only=True)
    try:
        rows = con.execute(
            "SELECT gap_id, classification, basis FROM cp2_gaps "
            "WHERE classification LIKE 'LOGGING_DISABLED%'").fetchall()
    finally:
        con.close()
    for gap_id, classification, basis in rows:
        assert classification in (
            "LOGGING_DISABLED_BY_ACTOR",
            "LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA"), (
            f"{gap_id}: unexpected classification {classification}")
        assert "%" in (basis or ""), (
            f"{gap_id}: basis cites no measured percentage -- the "
            f"classification must rest on numbers, not narrative")
    print(f"    {len(rows)} blind-window gap(s), each citing measured volume")


# --------------------------------------------------------------------------
# 5. Unparseable timestamps are flagged, not silently moved
# --------------------------------------------------------------------------

def test_bad_timestamps_are_counted_not_hidden():
    """
    Rows with an unparseable timestamp must be counted in the fingerprint, so
    a PARSE_FAILURE gap can report them -- never dropped quietly, and never
    sorted to the epoch where they would appear as the start of the attack.
    """
    for db in (FIREX_DB, EDR_DB):
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            rows = con.execute(
                "SELECT source, total_rows, bad_timestamp_rows, rejected_rows "
                "FROM cp2_source_fingerprint").fetchall()
            parse_gaps = con.execute(
                "SELECT COUNT(*) FROM cp2_gaps "
                "WHERE classification = 'PARSE_FAILURE'").fetchone()[0]
        finally:
            con.close()
        if not rows:
            _skip(f"{db}: no fingerprint -- run scripts/build_coverage.py")
            continue
        for source, total, bad_ts, rejected in rows:
            assert bad_ts is not None, f"{source}: bad-timestamp count is null"
            assert bad_ts >= 0 and rejected >= 0
            # If anything was unusable, a gap must say so.
            if (bad_ts or 0) + (rejected or 0) > 0:
                assert parse_gaps > 0, (
                    f"{source}: {bad_ts + rejected} unusable rows but no "
                    f"PARSE_FAILURE gap -- they were hidden")
            print(f"    {source}: {total:,} rows, {bad_ts:,} bad timestamps, "
                  f"{rejected:,} rejected, {parse_gaps} PARSE_FAILURE gap(s)")


# --------------------------------------------------------------------------
# 6. The experiment invents nothing
# --------------------------------------------------------------------------

def test_removed_host_absent_from_experiment_output():
    """
    If the experiment has been run, no event for the removed host may exist in
    its output, and a gap must cover what the removal orphaned.
    """
    removed_db = os.path.join(ROOT, "edr_removed.db")
    if not os.path.exists(removed_db):
        _skip("edr_removed.db missing -- run scripts/experiment_remove_host.py")
        return
    host = "SRV-DC-01"
    con = duckdb.connect(removed_db, read_only=True)
    try:
        leaked = con.execute(
            'SELECT COUNT(*) FROM suspicious_events WHERE host = ?',
            [host]).fetchone()[0]
        ledger = gaps.get_gaps(con)
    finally:
        con.close()
    assert leaked == 0, f"{leaked} event(s) for the removed host {host} leaked"

    # A NOT_COLLECTED gap must cover the orphaned actor. The gap may not name
    # the host -- the tool never saw it -- but it must name the consequence.
    orphan_gaps = [g for g in ledger
                   if g["classification"] == "NOT_COLLECTED"
                   and ("svc_helpdesk" in (g.get("asset_or_entity") or "")
                        or "origin" in g["gap_id"].lower())]
    assert orphan_gaps, (
        "removing the host that created svc_helpdesk produced no "
        "NOT_COLLECTED gap for the orphaned account")
    print(f"    {host}: 0 events leaked, {len(orphan_gaps)} gap(s) cover the "
          f"orphaned actor")


# --------------------------------------------------------------------------
# 7. The regression gate
# --------------------------------------------------------------------------

def test_regression_gate_unchanged():
    """
    The 1.x numbers must be identical after the 2.0 layer.

    This is ground rule 2. The whole design of 2.0 -- new modules, new tables,
    no edits to the engine -- exists to make this test pass, so it is the test
    that proves the design held.
    """
    for db, expected in BASELINE.items():
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            detections = con.execute(
                "SELECT COUNT(*) FROM suspicious_events").fetchone()[0]
        finally:
            con.close()
        assert detections == expected["detections"], (
            f"{db}: {detections} detections, baseline was "
            f"{expected['detections']} -- the 2.0 layer changed the "
            f"detection output")
        incidents = graph_engine.analyse(db)
        assert len(incidents) == expected["incidents"], (
            f"{db}: {len(incidents)} incidents, baseline was "
            f"{expected['incidents']} -- the 2.0 layer changed correlation")
        print(f"    {os.path.basename(db)}: {detections:,} detections, "
              f"{len(incidents)} incidents -- matches baseline")


def test_cp2_tables_do_not_touch_suspicious_events():
    """
    The 1.x table must still have exactly its original 17 columns.

    A 2.0 module that quietly added a column would break the regression gate's
    meaning even while the counts matched.
    """
    expected = ["timestamp", "host", "user", "event_id", "src_ip", "dest_ip",
                "status", "process", "bytes_out", "message", "rule_name",
                "mitre_technique", "mitre_name", "kill_chain_stage",
                "severity", "event_count", "outcome"]
    for db in (FIREX_DB, EDR_DB):
        if not os.path.exists(db):
            _skip(f"{db} missing")
            continue
        con = duckdb.connect(db, read_only=True)
        try:
            cols = [r[0] for r in con.execute(
                "DESCRIBE suspicious_events").fetchall()]
        finally:
            con.close()
        assert cols == expected, (
            f"{db}: suspicious_events schema changed to {cols}")
        print(f"    {os.path.basename(db)}: 1.x schema intact "
              f"({len(cols)} columns)")


# --------------------------------------------------------------------------
# 8. Respond-now is honest about what it recommends
# --------------------------------------------------------------------------

def test_actions_are_labelled_recommended():
    """
    Nothing in the respond panel may imply an action was taken.

    A tool that blurs "suggested" into "handled" is dangerous in exactly the
    moment it matters, so the label is asserted rather than trusted.
    """
    if not os.path.exists(FIREX_DB):
        _skip("firex.db missing")
        return
    incidents = graph_engine.analyse(FIREX_DB)
    assert incidents, "no incidents to check"
    for inc in incidents:
        actions = respond.suggested_actions(inc)
        for a in actions:
            assert a["status"] == "RECOMMENDED", (
                f"{inc['id']}: action status is {a['status']!r}")
            assert a["observation"].strip(), (
                f"{inc['id']}: an action with no observation behind it")
            assert a["steps"], f"{inc['id']}: an action with no steps"
    print(f"    {len(incidents)} incidents, all actions labelled RECOMMENDED "
          f"with an observation")


def test_indicators_span_whole_dataset():
    """
    First/last seen must come from the whole detections table, not the
    incident -- otherwise "is it still happening?" cannot be answered.
    """
    if not os.path.exists(FIREX_DB):
        _skip("firex.db missing")
        return
    con = duckdb.connect(FIREX_DB, read_only=True)
    try:
        rows = con.execute(
            "SELECT incident_id, value, first_seen, last_seen, occurrences "
            "FROM cp2_indicators WHERE indicator_type = 'account'").fetchall()
        if not rows:
            _skip("no indicators -- run scripts/run_cp2.py")
            return
        for inc_id, value, first, last, n in rows:
            # The count must match a dataset-wide query, not an incident one.
            actual = con.execute(
                'SELECT COUNT(*) FROM suspicious_events WHERE "user" = ?',
                [value]).fetchone()[0]
            assert n == actual, (
                f"{inc_id}/{value}: indicator reports {n} occurrences but the "
                f"dataset holds {actual} -- the lookup was scoped to the "
                f"incident")
    finally:
        con.close()
    print(f"    {len(rows)} account indicator(s), all counted dataset-wide")



# --------------------------------------------------------------------------
# 9. The honest-accuracy guards
#
# These exist because the headline "100% detection / 100% labels" from
# evaluate.py is measured against ground truth WE derived and then wrote rules
# for -- it is close to circular. These tests guard the claims that are NOT
# circular, so that a future change cannot quietly turn an honest number into
# a flattering one.
# --------------------------------------------------------------------------

def test_label_precision_against_vendor_signatures():
    """
    Our ATT&CK labels must agree with the firewall vendor's own signature names.

    Fortinet wrote these signature strings, not us, so they are the one
    external opinion in the data. A signature reading
    `Apache.Log4j...Remote.Code.Execution` is independent evidence that T1190
    is correct -- and a disagreement is a genuine mislabel, not a difference of
    opinion.

    Two real mislabels were found this way and fixed:
      * 135,623 antivirus detections were T1105 "Ingress Tool Transfer" at
        stage Execution. 135,620 of them are action=blocked, so nothing
        executed; they are delivery (T1566).
      * 54,563 app-control events were T1071.001 Command and Control. The
        applications involved are Instagram, Tinder, Skype and Dropbox.
    """
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    try:
        from validate_independent import precision_vs_vendor
    except ImportError:
        _skip("validate_independent.py not importable")
        return
    if not os.path.exists(FIREX_DB):
        _skip("firex.db missing")
        return
    con = duckdb.connect(FIREX_DB, read_only=True)
    try:
        result = precision_vs_vendor(con)
    finally:
        con.close()

    assert result["disagree"] == 0, (
        f"{result['disagree']:,} detections carry an ATT&CK technique that "
        f"contradicts the vendor signature name. First few: "
        f"{result['disagreements'][:3]}")
    assert result["unmapped_missed"] == 0, (
        f"{result['unmapped_missed']:,} detections are UNMAPPED although the "
        f"signature names a real, published threat: {result['missed'][:3]}")
    assert result["precision_pct"] == 100.0, (
        f"label precision is {result['precision_pct']:.1f}%, expected 100%")
    print(f"    {result['agree']:,} agree with the vendor, 0 disagree, "
          f"{result['unmapped_correctly']:,} correctly UNMAPPED")


def test_detections_are_not_purely_memorised():
    """
    Most detections must come from techniques we did NOT write rules from.

    If every detection matched a technique in our own answer key, the pipeline
    would be a lookup table for eight events rather than a detector. This
    asserts the opposite: the overwhelming majority of what it finds is
    independent of the ground truth we authored.
    """
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    try:
        from validate_independent import holdout_detection
    except ImportError:
        _skip("validate_independent.py not importable")
        return
    if not os.path.exists(FIREX_DB):
        _skip("firex.db missing")
        return
    con = duckdb.connect(FIREX_DB, read_only=True)
    try:
        memorised, independent = holdout_detection(con)
    finally:
        con.close()

    mem_n = sum(r["detections"] for r in memorised)
    ind_n = sum(r["detections"] for r in independent)
    assert ind_n > mem_n, (
        f"only {ind_n:,} detections are independent of our answer key against "
        f"{mem_n:,} that are not -- the result is mostly memorisation")
    assert len(independent) >= 5, (
        f"only {len(independent)} distinct techniques found outside the "
        f"answer key; detection is too narrow to call general")
    share = ind_n / (ind_n + mem_n) * 100
    print(f"    {share:.1f}% of detections from {len(independent)} techniques "
          f"outside the answer key")


def test_every_input_byte_is_accounted_for():
    """
    No part of the input may be silently skipped.

    This is the failure mode that invalidates every other number: reading 40%
    of a file and reporting 100% accuracy on the rest is a true statement about
    an unstated subset. Measured on the organisers' file, 1.61 GB -- 26% of the
    bytes -- is not syslog. The test requires that region be positively
    EXPLAINED (high entropy, incompressible, no record markers = padding),
    not merely ignored.
    """
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    try:
        from validate_independent import account_for_input
    except ImportError:
        _skip("validate_independent.py not importable")
        return
    # Look where the log actually tends to live, rather than assuming one
    # path. It has moved between D:\ and the project folder during this work,
    # and a test that reports "not present" for a file sitting next to it is
    # worse than useless -- it reads as a missing prerequisite when the real
    # problem is a hard-coded path.
    candidates = [os.environ.get("CHRONOPATH_LOG"),
                  os.path.join(ROOT, "firex-10G.log"),
                  "D:/firex-10G.log",
                  os.path.join(ROOT, "data", "firex-10G.log")]
    log = next((p for p in candidates if p and os.path.exists(p)), None)
    if not log:
        _skip("firex-10G.log not found (set CHRONOPATH_LOG to point at it)")
        return
    acct = account_for_input(log)
    if acct["trailing_bytes"] > 0:
        assert acct.get("data_loss") is False, (
            f"{acct['trailing_bytes']:,} bytes "
            f"({acct.get('trailing_share_pct', 0):.0f}%) of the input are "
            f"neither parsed nor explained: {acct['verdict']}")
        print(f"    {acct['trailing_share_pct']:.0f}% trailing region "
              f"explained as padding (entropy "
              f"{acct.get('entropy_bits_per_byte')})")
    else:
        print("    every byte is syslog; nothing unexplained")


def test_disabled_rules_are_documented_not_forgotten():
    """
    A rule shipped with `enabled: false` must say why, with numbers.

    Disabling a rule is a judgement call, and an undocumented one is
    indistinguishable from an oversight. The webfilter rule is off because
    enabling it would add ~368,000 detections across 1,386 hosts and find no
    attacker -- that reasoning has to travel with the rule.
    """
    import yaml

    for name in ("rules.yaml", "rules_ecs.yaml", "rules_fortigate.yaml"):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
            data = yaml.safe_load(text)
        disabled = [r for r in data.get("rules", [])
                    if not r.get("enabled", True)]
        for rule in disabled:
            assert (rule.get("description") or "").strip(), (
                f"{name}: disabled rule {rule['name']!r} has no description")
            # The reasoning lives in a YAML comment above the rule, which
            # safe_load discards -- so check the raw text for it.
            assert "DISABLED BY MEASUREMENT" in text, (
                f"{name}: a rule is disabled but the file carries no "
                f"explanation of why")
        if disabled:
            print(f"    {name}: {len(disabled)} disabled rule(s), "
                  f"all documented")

def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"\nChronoPath 2.0 -- {len(tests)} test(s)\n" + "=" * 62)
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
