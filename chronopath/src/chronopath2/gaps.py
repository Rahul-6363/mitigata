"""
gaps.py -- What can't we see? (ChronoPath 2.0, Task 4)

WHY THIS FILE EXISTS
--------------------
Every detection tool reports what it found. Almost none report what they could
not have found, and that omission is where real investigations go wrong.

An analyst reading "INC-01: admin account created, used, deleted -- 3
detections" will reasonably ask what the attacker did with that account in the
six minutes it existed. The honest answer on this data is: we cannot tell. The
firewall logged the account's creation, login and deletion, but nothing in the
supplied data shows what it DID while logged in -- no configuration diff, no
command audit, no endpoint telemetry from the workstation it was driven from.

1.x does not say that. It shows three detections and stops, and silence reads
as "nothing else happened". This module turns that silence into a record:
what is missing, what facts establish it is missing, what the analyst therefore
cannot conclude, and what to request next.

THE RULE THAT GOVERNS THIS WHOLE FILE: MISSING IS NOT MALICIOUS
---------------------------------------------------------------
This is ground rule 5 of the build, and it is the easiest rule in security
tooling to break, because the malicious explanation is always the more
interesting one. A tool that reports "no endpoint logs for this host -- the
attacker may have wiped them" is exciting and almost always wrong.

Logs are absent for mundane reasons overwhelmingly more often than malicious
ones: the agent was never installed, the forwarder was down, the retention
window rolled over, nobody licensed that log source. So absence is classified
NOT_COLLECTED or COVERAGE_UNKNOWN -- never as deletion, never as tampering --
unless a POSITIVE event proves otherwise. Only blind_window.py can issue
LOGGING_DISABLED_BY_ACTOR, and only when it holds an actual "logging disabled"
admin record plus a measured volume drop.

The same restraint applies to retention. "The file starts on 23 October, so
logs before that were deleted" is unsupported: we were given a file with a
start date and no retention policy. That is COVERAGE_UNKNOWN. Claiming expiry
would require retention metadata nobody supplied.

WHY EACH GAP CARRIES A BASIS AND AN IMPACT
------------------------------------------
    basis   -- the facts, so the analyst can check the reasoning rather than
               trust it. A gap without a basis is an opinion.
    impact  -- what this prevents them CONCLUDING. This is the field that
               changes behaviour: "no endpoint telemetry for the workstation"
               is a shrug, while "you cannot rule out that this account was
               used for more than the three logged actions" is a decision.

WHY AN EVIDENCE REQUEST
-----------------------
A gap an analyst cannot act on is just bad news. Each one is paired with the
specific artefact that would close it, so the output of an investigation can be
a concrete request to the people who hold that data -- which is what actually
happens next in a real SOC.
"""

# The ONLY classifications permitted. A fixed vocabulary matters here: if this
# were free text, "possible log tampering" would appear within a week and the
# distinction between measured fact and speculation would be lost. Anything
# that does not clearly fit one of these is COVERAGE_UNKNOWN.
CLASSIFICATIONS = (
    # Telemetry type not present in any supplied source. The honest default
    # for absence: we were not given this kind of data.
    "NOT_COLLECTED",
    # Rows the reader could not use, or timestamps it could not parse. A
    # measurable, non-malicious data-quality defect.
    "PARSE_FAILURE",
    # Issued ONLY by blind_window.py, ONLY with a positive disable event AND a
    # measured volume drop beyond the daily curve.
    "LOGGING_DISABLED_BY_ACTOR",
    # A disable event exists but the data kept arriving. The disable failed,
    # or this file is a forwarded copy.
    "LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA",
    # We do not know whether this was collected. Anything before the file's
    # first timestamp lands here -- NOT "retention expired", which would
    # require retention metadata we were never given.
    "COVERAGE_UNKNOWN",
)

# Telemetry an intrusion investigation normally needs. Used to state what is
# absent rather than guess at it: each entry is a kind of data a SOC would
# expect to consult, and this file reports which of them the supplied sources
# simply do not contain.
EXPECTED_TELEMETRY = {
    "endpoint_process": (
        "endpoint process execution (EDR) for the workstation an "
        "administrator was working from"),
    "config_audit": (
        "configuration change audit showing what each change actually "
        "altered, not merely that a change occurred"),
    "identity_provider": (
        "identity-provider sign-in and directory audit logs for the accounts "
        "involved"),
}

# Which artefact closes which gap. A dictionary rather than generated text,
# because these are the real names of real things an analyst asks a platform
# team for, and inventing plausible-sounding ones would waste their time.
EVIDENCE_REQUESTS = {
    "endpoint_process": (
        "EDR process timeline for the workstation(s) used by {entity} "
        "covering {window} -- specifically process creation, command lines "
        "and network connections."),
    "config_audit": (
        "Firewall configuration revision history for {entity} covering "
        "{window}, plus the running-config backups immediately before and "
        "after, so the actual change can be diffed."),
    "identity_provider": (
        "Identity-provider audit log for {entity} covering {window}: "
        "sign-in events, MFA results, and any directory changes to the "
        "account."),
    "account_lifecycle": (
        "Firewall configuration revision history for the period the account "
        "{entity} existed, plus the identity-provider audit log for that "
        "account, to establish what it was used for between creation and "
        "deletion."),
    "parse_failure": (
        "Original, unmodified export of the {count} affected rows from "
        "{entity} -- ideally in the native format rather than re-serialised "
        "syslog."),
    "coverage_unknown_before_start": (
        "Earlier log archive for {entity} covering the period before "
        "{window}, to establish whether this activity had a precursor."),
    "remote_syslog": (
        "FortiAnalyzer or remote syslog copy for {entity} covering {window}, "
        "as an independent record of what the on-box log would have held."),
}


def _ensure_table(con):
    """
    Create `cp2_gaps`. Shared with blind_window.py -- same schema, either may
    create it first, because an analyst wants one gap ledger rather than two.
    """
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_gaps (
            gap_id           VARCHAR,
            incident_id      VARCHAR,
            asset_or_entity  VARCHAR,
            telemetry        VARCHAR,
            time_start       VARCHAR,
            time_end         VARCHAR,
            classification   VARCHAR,
            basis            VARCHAR,
            impact           VARCHAR,
            evidence_request VARCHAR
        )
    """)


def _sources(con):
    """Read the Task 1 fingerprints -- the record of what we were actually given."""
    try:
        rows = con.execute(
            "SELECT source, detected_format, earliest_ts, latest_ts, "
            "total_rows, rejected_rows, bad_timestamp_rows "
            "FROM cp2_source_fingerprint").fetchall()
    except Exception:
        return []
    return [{"source": r[0], "format": r[1], "earliest": r[2], "latest": r[3],
             "total_rows": r[4], "rejected_rows": r[5],
             "bad_timestamp_rows": r[6]} for r in rows]


def _telemetry_present(sources):
    """
    Work out which kinds of telemetry the supplied sources can possibly hold.

    Derived from the detected formats rather than assumed, because the whole
    point of a gap ledger is that it reflects what we were given. A FortiGate
    syslog export physically cannot contain endpoint process execution, so
    that absence is a fact about the input, not a guess.
    """
    formats = {s["format"] for s in sources}
    present = set()
    if "fortigate" in formats:
        # A firewall sees network flow, its own admin activity and its UTM
        # engines. It does not see inside a host.
        present |= {"network_flow", "firewall_event", "utm_detection"}
    if "ecs" in formats or "flat" in formats:
        present |= {"endpoint_process", "endpoint_auth"}
    return present


def _fmt_window(start, end):
    if start and end:
        return f"{start} to {end}"
    if start:
        return f"from {start}"
    return "the incident window"


def global_gaps(con, sources=None):
    """
    Gaps that are properties of the supplied DATA, not of any one incident.

    Three kinds, each derived from the Task 1 fingerprint:

      * parse failures and unparseable timestamps -- a measured count;
      * everything before the file's first timestamp -- COVERAGE_UNKNOWN,
        deliberately NOT "retention expired";
      * telemetry types no supplied source can contain.
    """
    sources = sources if sources is not None else _sources(con)
    if not sources:
        return []

    out = []
    present = _telemetry_present(sources)

    for s in sources:
        rejected = int(s.get("rejected_rows") or 0)
        bad_ts = int(s.get("bad_timestamp_rows") or 0)

        # PARSE_FAILURE -- only raised when there is actually something to
        # raise. A clean parse should produce no gap, not a reassuring one.
        if rejected or bad_ts:
            total = int(s.get("total_rows") or 0)
            pct = (rejected + bad_ts) / total * 100 if total else 0
            out.append({
                "gap_id": f"GLOBAL-PARSE-{s['source']}",
                "incident_id": "GLOBAL",
                "asset_or_entity": s["source"],
                "telemetry": "all_streams",
                "time_start": s.get("earliest"),
                "time_end": s.get("latest"),
                "classification": "PARSE_FAILURE",
                "basis": (
                    f"Of {total:,} rows read from {s['source']}, "
                    f"{rejected:,} were rejected by the reader and {bad_ts:,} "
                    f"carried a timestamp that could not be parsed "
                    f"({pct:.3f}% of the file). Counted during the coverage "
                    f"pass, not estimated. Rows with an unparseable timestamp "
                    f"are excluded from the hourly volume table and flagged "
                    f"rather than sorted to the start of the timeline."
                ),
                "impact": (
                    f"Up to {rejected + bad_ts:,} events are absent from the "
                    f"analysis. At {pct:.3f}% this is unlikely to hide a whole "
                    f"attack stage, but it does mean no claim of completeness "
                    f"can be made about this file."
                ),
                "evidence_request": EVIDENCE_REQUESTS["parse_failure"].format(
                    count=f"{rejected + bad_ts:,}", entity=s["source"]),
            })

        # COVERAGE_UNKNOWN before the file starts. The careful wording is the
        # point: we do not know what happened before, and we do not know why
        # we were not given it.
        if s.get("earliest"):
            out.append({
                "gap_id": f"GLOBAL-BEFORE-{s['source']}",
                "incident_id": "GLOBAL",
                "asset_or_entity": s["source"],
                "telemetry": "all_streams",
                "time_start": None,
                "time_end": s["earliest"],
                "classification": "COVERAGE_UNKNOWN",
                "basis": (
                    f"The earliest event in {s['source']} is "
                    f"{s['earliest']}. Nothing in the supplied data covers any "
                    f"period before that, and no retention policy or archive "
                    f"index was provided, so we cannot tell whether earlier "
                    f"logs exist, were never collected, or have expired."
                ),
                "impact": (
                    "Reconnaissance or an initial foothold predating "
                    f"{s['earliest']} would be invisible here. The first event "
                    f"in this file is not evidence of the first event in the "
                    f"intrusion."
                ),
                "evidence_request": EVIDENCE_REQUESTS[
                    "coverage_unknown_before_start"].format(
                        entity=s["source"], window=s["earliest"]),
            })

    # Telemetry types no supplied source can contain.
    for telemetry, description in EXPECTED_TELEMETRY.items():
        if telemetry in present:
            continue
        formats = ", ".join(sorted({s["format"] for s in sources}))
        out.append({
            "gap_id": f"GLOBAL-NOTCOLLECTED-{telemetry}",
            "incident_id": "GLOBAL",
            "asset_or_entity": "estate",
            "telemetry": telemetry,
            "time_start": min((s["earliest"] for s in sources
                               if s.get("earliest")), default=None),
            "time_end": max((s["latest"] for s in sources
                             if s.get("latest")), default=None),
            "classification": "NOT_COLLECTED",
            "basis": (
                f"No supplied source contains {description}. The sources "
                f"provided are of format(s) {formats}, which structurally "
                f"cannot carry this telemetry. This is a statement about what "
                f"we were given, not evidence that the data was destroyed."
            ),
            "impact": (
                f"Any question that needs {description} cannot be answered "
                f"from this data set -- not answered in the negative, simply "
                f"not answerable."
            ),
            "evidence_request": EVIDENCE_REQUESTS.get(
                telemetry, EVIDENCE_REQUESTS["endpoint_process"]).format(
                    entity="the affected accounts and hosts",
                    window="the incident window"),
        })

    return out


def incident_gaps(con, incident, sources=None):
    """
    Gaps specific to one incident, derived from what that incident contains.

    The most valuable one here is the account-lifecycle gap. When an account is
    created and deleted inside the data, the firewall records the lifecycle but
    not the use: we can see svc_backup30 was created at 03:55, logged in at
    04:02 and was deleted at 04:07, and we cannot see what it did in between.
    That is precisely the question an incident responder has to answer, and
    saying so is more useful than leaving the analyst to notice the hole.
    """
    import re

    sources = sources if sources is not None else _sources(con)
    present = _telemetry_present(sources)
    events = incident.get("events") or []
    if not events:
        return []

    inc_id = incident.get("id", "INC")
    start = incident.get("start_time")
    end = incident.get("end_time")
    window = _fmt_window(start, end)
    accounts = sorted({str(e["user"]).strip() for e in events
                       if e.get("user") and str(e["user"]).strip() not in
                       ("-", "", "N/A", "unknown")})
    hosts = sorted({str(e["host"]).strip() for e in events if e.get("host")})
    out = []

    # 1. Endpoint telemetry for the administrators seen acting here.
    if "endpoint_process" not in present and accounts:
        who = ", ".join(accounts[:4]) + ("..." if len(accounts) > 4 else "")
        out.append({
            "gap_id": f"{inc_id}-GAP-ENDPOINT",
            "incident_id": inc_id,
            "asset_or_entity": who,
            "telemetry": "endpoint_process",
            "time_start": start, "time_end": end,
            "classification": "NOT_COLLECTED",
            "basis": (
                f"This incident is built entirely from firewall telemetry. No "
                f"supplied source contains endpoint process execution for the "
                f"workstation(s) that {who} administered the firewall from, so "
                f"we see the firewall side of each action and nothing of the "
                f"machine that initiated it."
            ),
            "impact": (
                "Cannot establish whether these were deliberate actions by the "
                "named administrator, an attacker using stolen credentials, or "
                "malware driving an authenticated session. The firewall records "
                "the authenticated identity, which is not the same as the "
                "person."
            ),
            "evidence_request": EVIDENCE_REQUESTS["endpoint_process"].format(
                entity=who, window=window),
        })

    # 2. The account-lifecycle gap. Only raised when the data actually shows a
    #    creation or deletion -- it is grounded in an event, not in suspicion.
    lifecycle = [e for e in events
                 if re.search(r"\b(add|delete)\s+system\.admin\b",
                              f"{e.get('raw_msg') or ''} {e.get('message') or ''}",
                              re.IGNORECASE)
                 or str(e.get("mitre_technique") or "").startswith(("T1136", "T1098"))]
    if lifecycle and "config_audit" not in present:
        named = set()
        for e in lifecycle:
            m = re.search(r"system\.admin\s+(\S+)",
                          f"{e.get('raw_msg') or ''} {e.get('message') or ''}",
                          re.IGNORECASE)
            if m:
                named.add(m.group(1).strip('"'))
        subject = ", ".join(sorted(named)) if named else ", ".join(accounts[:2])
        first = min(e["timestamp"] for e in lifecycle)
        last = max(e["timestamp"] for e in lifecycle)
        out.append({
            "gap_id": f"{inc_id}-GAP-LIFECYCLE",
            "incident_id": inc_id,
            "asset_or_entity": subject,
            "telemetry": "config_audit",
            "time_start": first, "time_end": last,
            "classification": "NOT_COLLECTED",
            "basis": (
                f"The data records the lifecycle of the administrative account "
                f"{subject} -- its creation, its login and its deletion -- but "
                f"FortiGate event logs state only that a configuration "
                f"attribute changed, never what the new value was. No "
                f"configuration revision history or diff was supplied for "
                f"{first} to {last}."
            ),
            "impact": (
                f"Cannot determine what {subject} actually did while it "
                f"existed. Specifically: no answer on whether firewall "
                f"policies, VPN users, administrative accounts or port "
                f"forwards were added that would survive the account's "
                f"deletion. Treat persistence as unverified rather than "
                f"absent."
            ),
            "evidence_request": EVIDENCE_REQUESTS["account_lifecycle"].format(
                entity=subject),
        })

    # 3. Identity-provider corroboration for external administrative access.
    external_auth = [e for e in events
                     if str(e.get("mitre_technique") or "").startswith(
                         ("T1078", "T1133"))]
    if external_auth and "identity_provider" not in present and accounts:
        who = ", ".join(accounts[:4])
        out.append({
            "gap_id": f"{inc_id}-GAP-IDP",
            "incident_id": inc_id,
            "asset_or_entity": who,
            "telemetry": "identity_provider",
            "time_start": start, "time_end": end,
            "classification": "NOT_COLLECTED",
            "basis": (
                f"{len(external_auth)} authentication event(s) in this "
                f"incident were accepted by the firewall for {who}. No "
                f"identity-provider or directory audit log was supplied, so "
                f"the firewall's own record is the only account of the "
                f"authentication."
            ),
            "impact": (
                "Cannot tell whether MFA was satisfied, bypassed or not "
                "configured, and cannot see whether the same credentials were "
                "used successfully against other systems in the estate. A "
                "successful firewall login is not proof that only the "
                "firewall was reached."
            ),
            "evidence_request": EVIDENCE_REQUESTS["identity_provider"].format(
                entity=who, window=window),
        })

    return out


def analyse(con, incidents, persist=True, keep_blind_windows=True):
    """
    Build the whole gap ledger: per-incident gaps plus global ones.

    `keep_blind_windows` preserves rows written by blind_window.py, which share
    this table. Clearing them here would mean whichever module ran second
    deleted the other's findings.
    """
    _ensure_table(con)
    sources = _sources(con)

    found = []
    for inc in incidents:
        found.extend(incident_gaps(con, inc, sources))
    found.extend(global_gaps(con, sources))

    # Guard the fixed vocabulary at the boundary. An unknown classification is
    # a bug in this file, and letting it reach the database would quietly
    # defeat the purpose of having a closed list.
    for g in found:
        if g["classification"] not in CLASSIFICATIONS:
            raise ValueError(
                f"{g['gap_id']}: classification {g['classification']!r} is not "
                f"one of {CLASSIFICATIONS}")
        if not (g.get("basis") or "").strip():
            raise ValueError(f"{g['gap_id']}: a gap must carry its basis")

    if persist:
        if keep_blind_windows:
            con.execute(
                "DELETE FROM cp2_gaps WHERE classification NOT IN "
                "('LOGGING_DISABLED_BY_ACTOR', "
                "'LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA')")
        else:
            con.execute("DELETE FROM cp2_gaps")
        if found:
            con.executemany(
                "INSERT INTO cp2_gaps VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(g["gap_id"], g["incident_id"], g["asset_or_entity"],
                  g["telemetry"],
                  str(g["time_start"]) if g["time_start"] else None,
                  str(g["time_end"]) if g["time_end"] else None,
                  g["classification"], g["basis"], g["impact"],
                  g["evidence_request"]) for g in found])
    return found


def get_gaps(con, incident_id=None):
    """Read the ledger back, for the dashboard and the API."""
    try:
        if incident_id:
            rows = con.execute(
                "SELECT * FROM cp2_gaps WHERE incident_id = ? "
                "ORDER BY classification, gap_id", [incident_id]).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM cp2_gaps ORDER BY incident_id, gap_id"
            ).fetchall()
        cols = [d[0] for d in con.description]
    except Exception:
        return []
    return [dict(zip(cols, r)) for r in rows]
