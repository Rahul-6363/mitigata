"""
link_evidence.py -- Why does each step belong here? (ChronoPath 2.0, Task 3)

WHY THIS FILE EXISTS -- THE CORE 2.0 FEATURE
--------------------------------------------
ChronoPath 1.x produces an incident: five detections, grouped, scored, ranked.
An analyst receiving it has a reasonable next question that 1.x cannot answer:

    "Why do you think these five events are the same intrusion?"

Union-find grouped them because they shared an entity inside a time window.
That is a correct algorithm and a useless explanation. The analyst needs the
grounds: WHICH attribute, WHAT value, HOW far apart, and crucially -- HOW GOOD
is that evidence? Because "the same admin account did both" and "both came
through the same NAT gateway" are not the same quality of claim, and an
investigation that treats them alike will chase the wrong lead.

So every link gets a grade, a plain sentence, and the raw log lines behind it.

AND -- THE PART MOST TOOLS OMIT -- SO DOES EVERY *REJECTED* LINK
----------------------------------------------------------------
ChronoPath 1.x deliberately refuses some links: an entity shared by more than
MAX_USERS_PER_SHARED_ENTITY accounts is infrastructure, not an actor, and the
`-` placeholder is not an identity. Those refusals are why the false-alarm rate
on the real file is 0% instead of catastrophic -- measured, treating `-` as a
username collapsed 395,193 of 395,361 detections into one meaningless blob.

But silent refusal is its own trap. An analyst looking at five separate
incidents cannot tell "these are genuinely unrelated" from "the tool decided
not to connect them and didn't mention it". The second is far more dangerous,
because the analyst will never know to ask. So rejections are recorded too,
with the count that triggered them, and turned into an explicit statement per
incident pair -- see `incident_separation()`.

That is the honest form of the FortiGate result. All eight planted steps are
found with the correct ATT&CK technique, but they come back as five incidents,
because five accounts from five different external addresses share nothing that
would legitimately join them. 1.x reported five incidents and left the analyst
to wonder. 2.0 reports five incidents AND states, per pair, exactly what was
checked and what was found -- which is the difference between a tool that is
quiet and a tool that is accountable.

A DESIGN CONSTRAINT THAT SHAPED EVERYTHING HERE
-----------------------------------------------
Ground rule 1: do not change correlation behaviour. So this module does not
touch `correlate_incidents()`. It RE-DERIVES the links from the finished
incidents using the same rules the engine applied, and asserts nothing the
engine did not already decide. The regression gate proves it: the 1.x numbers
come out identical.

This re-derivation is also cheap, because it runs per reported incident -- a
handful of events each -- not over the 373,061 detections the engine grouped.

WHY GRADES, AND WHY THESE FOUR
------------------------------
    HARD        An identity pivot (this account created that one) or the same
                account on both events. An account is the actor; this is the
                strongest link available in any log.
    SOFT        A shared external source IP, or a shared machine inside the
                window. Good evidence, but an address can be a VPN exit or a
                NAT gateway, and a machine can host unrelated people.
    INFERRED    An ambient detection attached to an anchor by machine alone
                within 15 minutes. Context worth showing, not proof.
    UNRESOLVED  A candidate link that was REJECTED: infrastructure entity, or
                a placeholder value. Recorded so the refusal is visible.

RAW EVIDENCE
------------
Grades and sentences are still a summary. A real investigation ends at the
original log line, so `fetch_raw_lines()` pulls them from the source file on
demand for the detections in ONE incident -- never for all 9,125,382 rows,
which would be a second copy of a 6.54 GB file to serve a few hundred lookups.
The raw line matters concretely here: the detections table records INC-01's
creation event as "Object attribute configured", while the raw line carries
    msg="Add system.admin svc_backup30"
-- the account name, which is the actual proof of the pivot.
"""

import os
import re
from datetime import datetime

# Re-exported from the engine at call time so the two can never drift. If
# someone retunes MAX_USERS_PER_SHARED_ENTITY in graph_engine, the evidence
# layer's rejection reasons change with it rather than quoting a stale number.
GRADE_HARD = "HARD"
GRADE_SOFT = "SOFT"
GRADE_INFERRED = "INFERRED"
GRADE_UNRESOLVED = "UNRESOLVED"

# How many raw log lines to pull per request. A cap exists because the fetch is
# a linear scan of the source file: an unbounded request on a 6.54 GB file
# would take minutes and serve nobody.
MAX_RAW_LINES = 40

# Values that mean "unknown", never "the same actor". Mirrors the engine's own
# list; see the measured collapse described in the module docstring.
PLACEHOLDERS = {"-", "", "N/A", "n/a", "unknown", "none", "null", "NULL"}


def _ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")
                                      ).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _minutes(a, b):
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds()) / 60.0


def _is_placeholder(value):
    return not value or str(value).strip() in PLACEHOLDERS


def _ensure_tables(con):
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_links (
            link_id         VARCHAR,
            incident_id     VARCHAR,
            event_a         VARCHAR,
            event_b         VARCHAR,
            link_attribute  VARCHAR,
            attribute_value VARCHAR,
            time_delta_s    BIGINT,
            window_s        BIGINT,
            grade           VARCHAR,
            reason          VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_rejected_links (
            incident_id     VARCHAR,
            link_attribute  VARCHAR,
            attribute_value VARCHAR,
            distinct_users  INTEGER,
            event_count     INTEGER,
            sample_events   VARCHAR,
            grade           VARCHAR,
            reason          VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_incident_separation (
            incident_a      VARCHAR,
            incident_b      VARCHAR,
            shared_accounts VARCHAR,
            shared_ips      VARCHAR,
            shared_rejected VARCHAR,
            verdict         VARCHAR,
            statement       VARCHAR
        )
    """)


def event_ref(incident_id, index, event):
    """
    A stable, human-readable identity for one detection.

    WHY WE MINT ONE: the 1.x detections table has no primary key -- it was
    built for streaming writes, where a key costs time and buys nothing. But a
    link has to name its two endpoints, and naming them by row offset would
    break the moment the table is rewritten. So the reference is derived from
    the event's own content (incident, position, timestamp), which is stable
    for as long as the finding is.
    """
    return f"{incident_id}:{index:03d}@{event.get('timestamp')}"


def derive_links(incident, window_minutes=120, host_window_minutes=15):
    """
    Re-derive, grade and explain every link inside one reported incident.

    Mirrors the engine's own rules: an account always links; an EXTERNAL source
    or destination IP links; a machine links only as weaker context. Events are
    linked to their immediate neighbour in time per attribute, which is what
    the engine does -- union-find makes connectivity transitive, so adjacent
    pairs produce the same grouping as all pairs at a fraction of the cost.

    Returns (links, rejected). `rejected` holds candidate links the engine's
    own filters refused, aggregated per value rather than per pair so a busy
    infrastructure address cannot produce thousands of rows.
    """
    import graph_engine

    events = incident.get("events") or []
    incident_id = incident.get("id", "INC")
    refs = [event_ref(incident_id, i, e) for i, e in enumerate(events)]
    times = [_ts(e.get("timestamp")) for e in events]

    max_users = getattr(graph_engine, "MAX_USERS_PER_SHARED_ENTITY", 3)
    window_s = int(window_minutes * 60)
    host_window_s = int(host_window_minutes * 60)

    # Group event indices by every entity they mention, exactly as the engine
    # does, so the links we explain are the links it actually formed.
    buckets = {}

    def add(kind, value, idx):
        if _is_placeholder(value):
            return
        buckets.setdefault((kind, str(value).strip()), []).append(idx)

    for i, e in enumerate(events):
        add("account", e.get("user"), i)
        for ip_field in ("src_ip", "dest_ip"):
            ip = e.get(ip_field)
            # Only EXTERNAL addresses are evidence of a shared actor. A shared
            # internal subnet means two machines are on the same LAN, which is
            # true of every machine on the LAN.
            if ip and not _is_placeholder(ip) and not graph_engine._is_internal(ip):
                add("src_ip", ip, i)
        add("machine", e.get("host"), i)

    # THE IDENTITY PIVOT, built as a second pass.
    #
    # An account-creation event names BOTH identities in one record -- the
    # creator in `user=` and the created account in the message. That is the
    # one link that survives an identity change, and nothing else in the data
    # supplies it: on a busy device the creator and the new account are simply
    # two different users.
    #
    # It needs its own pass because the two halves live in different events. A
    # single loop would index the creation event under the new name and stop
    # there, leaving a bucket of one, which forms no pair. So: find each
    # creation, then find every event where that created account is the actor,
    # and bucket them together.
    for i, e in enumerate(events):
        created = _created_account_any(e)
        if not created:
            continue
        users_of_created = [
            j for j, other in enumerate(events)
            if j != i and str(other.get("user") or "").strip().lower()
            == created.strip().lower()]
        if not users_of_created:
            continue
        add("identity_pivot", created, i)
        for j in users_of_created:
            add("identity_pivot", created, j)

    links, rejected = [], []

    # Strongest evidence first, so a weaker explanation of a pair the analyst
    # already has a HARD reason for can be suppressed below. Showing "same
    # account" AND "same machine" AND "same address" for one pair of events is
    # three rows that say one thing, and it buries the grade that matters.
    strength = {"identity_pivot": 0, "account": 1, "src_ip": 2, "machine": 3}
    explained_pairs = {}

    for (kind, value), idxs in sorted(
            buckets.items(), key=lambda kv: strength.get(kv[0][0], 9)):
        if len(idxs) < 2:
            continue

        # THE INFRASTRUCTURE CUT-OFF, made visible. An identifier attached to
        # many distinct accounts names a shared service -- a NAT gateway, a
        # proxy, a management interface -- not an actor. Accounts themselves
        # are never cut off: an account is the actor however busy it is.
        distinct_users = {str(events[i].get("user") or "").strip()
                          for i in idxs}
        distinct_users = {u for u in distinct_users if u and u not in PLACEHOLDERS}
        if kind not in ("account", "identity_pivot") and len(distinct_users) > max_users:
            rejected.append({
                "incident_id": incident_id,
                "link_attribute": kind,
                "attribute_value": value,
                "distinct_users": len(distinct_users),
                "event_count": len(idxs),
                "sample_events": ", ".join(refs[i] for i in idxs[:5]),
                "grade": GRADE_UNRESOLVED,
                "reason": (
                    f"Not linked: {value} is used by {len(distinct_users)} "
                    f"different accounts, more than the {max_users} allowed "
                    f"before an identifier is treated as shared infrastructure "
                    f"rather than an actor. Linking on it would chain "
                    f"unrelated people into one incident."
                ),
            })
            continue

        applied_window = host_window_s if kind == "machine" else window_s

        # Adjacent pairs in time only -- see the note above on transitivity.
        ordered = sorted(idxs, key=lambda i: (times[i] or datetime.min))
        for a, b in zip(ordered, ordered[1:]):
            delta = _minutes(times[a], times[b])
            if delta is None:
                continue
            delta_s = int(delta * 60)

            if kind == "identity_pivot":
                grade = GRADE_HARD
                reason = (
                    f"Linked: the account {value} was created by this event, "
                    f"and {value} is the account acting "
                    f"{_pretty_gap(delta)} later. An account creation names "
                    f"both identities in one record, which is what carries the "
                    f"chain across the identity change."
                )
            elif kind == "account":
                grade = GRADE_HARD
                reason = (f"Linked: same account ({value}), "
                          f"{_pretty_gap(delta)} apart.")
            elif kind == "src_ip":
                grade = GRADE_SOFT
                reason = (
                    f"Linked: same external address ({value}), "
                    f"{_pretty_gap(delta)} apart. Strong but not conclusive -- "
                    f"an address can be a VPN exit or NAT gateway shared by "
                    f"unrelated users."
                )
            else:
                # Machine-only, and only inside the short context window.
                if delta_s > host_window_s:
                    continue
                grade = GRADE_INFERRED
                reason = (
                    f"Attached as context: same machine ({value}), "
                    f"{_pretty_gap(delta)} apart, with no shared account or "
                    f"address. Co-location in time on one host is suggestive, "
                    f"not proof of a shared actor."
                )

            if delta_s > applied_window:
                continue

            # One pair of events needs one best reason, not every reason. A
            # machine link adds nothing once the same two events are already
            # joined by an account or an external address; keeping it would
            # dilute the Evidence tab with rows that restate a weaker version
            # of what the analyst has just read. The rejected-links table still
            # records anything actually refused, so nothing is hidden.
            pair = (min(a, b), max(a, b))
            best = explained_pairs.get(pair)
            if best is not None and strength.get(kind, 9) > best:
                continue
            explained_pairs[pair] = min(best, strength.get(kind, 9)) \
                if best is not None else strength.get(kind, 9)

            links.append({
                "link_id": f"{incident_id}-L{len(links) + 1:03d}",
                "incident_id": incident_id,
                "event_a": refs[a],
                "event_b": refs[b],
                "link_attribute": kind,
                "attribute_value": value,
                "time_delta_s": delta_s,
                "window_s": applied_window,
                "grade": grade,
                "reason": reason,
            })

    # Record placeholder values that were present and deliberately ignored.
    # This is the rejection most likely to surprise an analyst, because the
    # value looks like a username in the raw log.
    placeholder_idxs = [i for i, e in enumerate(events)
                        if _is_placeholder(e.get("user"))]
    if len(placeholder_idxs) >= 2:
        rejected.append({
            "incident_id": incident_id,
            "link_attribute": "account",
            "attribute_value": "-",
            "distinct_users": 0,
            "event_count": len(placeholder_idxs),
            "sample_events": ", ".join(refs[i] for i in placeholder_idxs[:5]),
            "grade": GRADE_UNRESOLVED,
            "reason": (
                f"Not linked: {len(placeholder_idxs)} events carry the "
                f"placeholder user '-', which firewall telemetry writes when "
                f"it knows the address but not the person. Unknown is not "
                f"evidence of a shared actor. Treating it as one would have "
                f"merged these events on a value that means nothing."
            ),
        })

    return links, rejected


def _created_account_any(event):
    """
    Find a created account name in an event, across log formats.

    The engine's own `_created_account` parses Windows command lines
    (`net user <name> /add`). That is correct for EDR data and finds nothing on
    a firewall, where the same act appears as
        msg="Add system.admin svc_backup30"
    so this adds the FortiGate shape. It is evidence-layer only: the engine's
    grouping is untouched (ground rule 1), and this is used to EXPLAIN a link
    the shared source address already formed, not to create a new one.

    It reads `raw_msg` when present -- the field `enrich_from_source()` fills
    from the original log line. The detections table cannot supply it: the
    adapter prefers FortiGate's `logdesc` for the `message` column, so the
    creation event arrives here as the useless "Object attribute configured"
    while the account name sits in `msg` on the raw line. Rather than change
    the detection path to carry an extra column for 9,125,382 rows, the
    evidence layer fetches it for the handful of events it explains.
    """
    import graph_engine

    found = graph_engine._created_account(event)
    if found:
        return found

    text = " ".join(str(event.get(f) or "") for f in
                    ("raw_msg", "message", "rule_name"))
    # `Add system.admin <name>` -- the FortiGate admin-creation record.
    m = re.search(r"\badd\s+system\.admin\s+(\S+)", text, re.IGNORECASE)
    if m:
        return m.group(1).strip('"')
    return None


_MSG_RE = re.compile(r'msg="([^"]*)"')


def enrich_from_source(log_path, incidents, max_scan_hits=None):
    """
    Attach the raw `msg` text to each detection, read from the source file.

    WHY THIS EXISTS: the detections table deliberately does not carry every
    source field -- doing so would multiply the cost of writing 373,061 rows to
    serve a few dozen lookups. But two things in Task 3 genuinely need the
    original text:

      * the identity pivot, because `msg="Add system.admin svc_backup30"` is
        the only place the created account is named; and
      * the Evidence tab, which must show the analyst a real log line.

    So this fills them in afterwards, for the reported incidents only. One
    sequential pass over the file serves all of them at once -- scanning once
    per incident would multiply a 6.54 GB read by the incident count.

    Matching is on date, time and account, which is specific on this data: the
    planted events are the rarest records in the file. A detection that cannot
    be matched simply keeps its original `message`; this never invents text.

    Safe to skip entirely. If the source file has moved, every incident keeps
    working with slightly weaker evidence, which is the correct degradation --
    an investigation tool that refuses to open without its source file is worse
    than one that says "raw line unavailable".
    """
    if not log_path or not os.path.exists(log_path):
        return 0

    # Index the events we want by (date, time, user) so the scan is a dict
    # lookup per line rather than a loop over every wanted event.
    wanted = {}
    for inc in incidents:
        for e in inc.get("events") or []:
            ts = str(e.get("timestamp") or "")
            if "T" not in ts:
                continue
            date_part, time_part = ts.split("T", 1)
            key = (date_part, time_part[:8], str(e.get("user") or "").strip())
            wanted.setdefault(key, []).append(e)
    if not wanted:
        return 0

    # How many detections we are hoping to fill, so the scan can stop early.
    want_total = sum(len(v) for v in wanted.values())
    filled = 0
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            # Pre-filter on the (date, time) pair ALONE before touching a regex.
            #
            # This matters enormously and the first version got it wrong. The
            # comment claimed a cheap pre-filter, but the code ran
            # re.search(r'user="..."') on every line BEFORE testing the date --
            # so 9.1 million regex searches ran to serve 10 lookups. Measured,
            # that took 1,368 seconds. Deriving the timestamp key from fixed
            # string offsets first, and only running the regexes on the handful
            # of lines whose timestamp we actually want, brings it back to a
            # single sequential read.
            #
            # `needles` is keyed by the (date, time) pairs, so the common case
            # is one tuple hash and one dict lookup per line.
            #
            # The time filter alone is not enough on firex-30G.log: from ~30%
            # in, every line carries the SAME timestamp (2026-10-30 08:48:36),
            # so a wanted event there made all ~26 million of those lines pass
            # and hit the regex. `needles` adds a plain substring test for the
            # wanted accounts first. None means an empty account is wanted,
            # which a substring cannot express, so those keep the regex path.
            needles = {}
            for d, t, u in wanted:
                if needles.get((d, t), ()) is None:
                    continue
                needles[(d, t)] = (None if not u else
                                   needles.get((d, t), ()) + (f'user="{u}"',))
            for line in f:
                if not line.startswith("date="):
                    continue
                # Fixed offsets in the FortiGate preamble:
                #   date=YYYY-MM-DD time=HH:MM:SS
                #   0123456789...
                date_part = line[5:15]
                time_part = line[21:29]
                key = (date_part, time_part)
                if key not in needles:
                    continue
                users = needles[key]
                if users is not None and not any(n in line for n in users):
                    continue
                m_user = re.search(r'user="([^"]*)"', line)
                user = m_user.group(1) if m_user else ""
                targets = wanted.get((date_part, time_part, user))
                if not targets:
                    continue
                m_msg = _MSG_RE.search(line)
                for e in targets:
                    if "raw_line" not in e:
                        e["raw_line"] = line.strip()
                        if m_msg:
                            e["raw_msg"] = m_msg.group(1)
                        filled += 1
                if max_scan_hits and filled >= max_scan_hits:
                    break
                # Stop as soon as every detection has its line. The planted
                # events sit early in a 6.5 GB file, so there is no reason to
                # read the remaining gigabytes once they are all found.
                if filled >= want_total:
                    break
    except OSError:
        return filled
    return filled


def _pretty_gap(minutes):
    """Render a gap the way an analyst would say it aloud."""
    if minutes is None:
        return "an unknown interval"
    if minutes < 1:
        return f"{int(minutes * 60)} seconds"
    if minutes < 90:
        return f"{minutes:.0f} min"
    return f"{minutes / 60:.1f} h"


def incident_separation(incidents):
    """
    State, for every pair of reported incidents, why they are NOT one incident.

    WHY THIS IS NECESSARY: five separate incidents is a claim, and an unstated
    claim cannot be checked. The analyst needs to know what was compared. This
    distinguishes the two cases that look identical in a 1.x incident list:

      (a) genuinely unrelated -- no shared account, no shared address;
      (b) connected only through a value the engine deliberately refused.

    Case (b) is the dangerous one, and it is where an analyst's judgement
    should override the tool: a management IP shared by nine accounts is right
    to reject automatically and still worth a human look.
    """
    import graph_engine

    max_users = getattr(graph_engine, "MAX_USERS_PER_SHARED_ENTITY", 3)
    out = []

    def entities(inc):
        accounts, ips, machines = set(), set(), set()
        for e in inc.get("events") or []:
            if not _is_placeholder(e.get("user")):
                accounts.add(str(e["user"]).strip())
            for f in ("src_ip", "dest_ip"):
                ip = e.get(f)
                if ip and not _is_placeholder(ip) and not graph_engine._is_internal(ip):
                    ips.add(str(ip).strip())
            if not _is_placeholder(e.get("host")):
                machines.add(str(e["host"]).strip())
        return accounts, ips, machines

    # How many distinct accounts each machine is associated with ACROSS all
    # reported incidents -- the number that justifies calling it infrastructure.
    machine_users = {}
    for inc in incidents:
        for e in inc.get("events") or []:
            h = e.get("host")
            if _is_placeholder(h):
                continue
            u = e.get("user")
            if not _is_placeholder(u):
                machine_users.setdefault(str(h).strip(), set()).add(str(u).strip())

    for i, inc_a in enumerate(incidents):
        acc_a, ip_a, mach_a = entities(inc_a)
        for inc_b in incidents[i + 1:]:
            acc_b, ip_b, mach_b = entities(inc_b)
            shared_acc = sorted(acc_a & acc_b)
            shared_ip = sorted(ip_a & ip_b)
            shared_mach = sorted(mach_a & mach_b)

            # A shared machine only counts as "rejected infrastructure" when it
            # really is promiscuous. If it is quiet, say so -- it would have
            # been a usable link and the separation is weaker than it looks.
            rejected_bits, weak_bits = [], []
            for m in shared_mach:
                n = len(machine_users.get(m, ()))
                if n > max_users:
                    rejected_bits.append(f"{m} (used by {n} accounts)")
                else:
                    weak_bits.append(f"{m} (used by {n} accounts)")

            if shared_acc or shared_ip:
                verdict = "SHARED_ENTITY_PRESENT"
                bits = []
                if shared_acc:
                    bits.append(f"account(s) {', '.join(shared_acc)}")
                if shared_ip:
                    bits.append(f"external address(es) {', '.join(shared_ip)}")
                statement = (
                    f"{inc_a['id']} and {inc_b['id']} DO share "
                    f"{' and '.join(bits)}. They are reported separately "
                    f"because the shared activity falls outside the "
                    f"correlation window, so review them together."
                )
            elif rejected_bits:
                verdict = "SEPARATED_BY_INFRASTRUCTURE_CUTOFF"
                statement = (
                    f"{inc_a['id']} and {inc_b['id']} are not linked: they "
                    f"share no account and no external source address. The "
                    f"only common value is {'; '.join(rejected_bits)}, which "
                    f"exceeds the {max_users}-account limit and is therefore "
                    f"treated as infrastructure rather than as an actor. "
                    f"A shared firewall is where everyone's traffic meets, so "
                    f"it is not evidence that these two are one intrusion."
                )
            elif weak_bits:
                verdict = "SEPARATED_BY_TIME"
                statement = (
                    f"{inc_a['id']} and {inc_b['id']} are not linked: they "
                    f"share no account and no external source address. They do "
                    f"share {'; '.join(weak_bits)}, which is not promiscuous, "
                    f"so the separation rests on time -- their activity is "
                    f"further apart than the correlation window. Worth a human "
                    f"look if you suspect one campaign."
                )
            else:
                verdict = "NO_SHARED_ENTITY"
                statement = (
                    f"{inc_a['id']} and {inc_b['id']} are not linked: they "
                    f"share no account, no external source address and no "
                    f"machine. Nothing in the supplied data connects them."
                )

            out.append({
                "incident_a": inc_a["id"],
                "incident_b": inc_b["id"],
                "shared_accounts": ", ".join(shared_acc) or "none",
                "shared_ips": ", ".join(shared_ip) or "none",
                "shared_rejected": "; ".join(rejected_bits) or "none",
                "verdict": verdict,
                "statement": statement,
            })
    return out


def fetch_raw_lines(log_path, incident, max_lines=MAX_RAW_LINES):
    """
    Pull the original log lines behind one incident's detections.

    WHY ON DEMAND RATHER THAN STORED: storing the raw text for every row would
    mean a second copy of a 6.54 GB file to serve a few hundred lookups. The
    brief is explicit -- raw text for detections only. This goes further and
    stores none, fetching per incident instead, which costs one scan of the
    file and keeps the database small enough to copy around.

    The match is on timestamp plus account, which is specific enough on this
    data: the planted events are the rarest records in 9,125,382 rows.

    Returns [] if the source file is not available -- a dashboard that shows
    evidence when it can and says nothing when it cannot is honest; one that
    crashes is not.
    """
    if not log_path or not os.path.exists(log_path):
        return []

    wanted = []
    for e in incident.get("events") or []:
        ts = str(e.get("timestamp") or "")
        if "T" in ts:
            date_part, time_part = ts.split("T", 1)
            wanted.append((date_part, time_part[:8],
                           str(e.get("user") or "").strip()))
    if not wanted:
        return []

    found = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(found) >= max_lines:
                    break
                for date_part, time_part, user in wanted:
                    # FortiGate: date=.. time=.. user="..";
                    # application log: "<date> <time> ... user=..".
                    fortigate = (f"date={date_part}" in line
                                 and f"time={time_part}" in line
                                 and (not user or f'user="{user}"' in line))
                    applog = (line.startswith(f"{date_part} {time_part} ")
                              and (not user or f" user={user} " in line))
                    if fortigate or applog:
                        found.append(line.strip())
                        break
    except OSError:
        return []
    return found


def analyse(con, incidents, persist=True, window_minutes=120, log_path=None):
    """
    Build the full evidence record for every reported incident.

    Returns (links, rejected, separation). Persisting replaces the previous
    run's rows wholesale rather than appending: these are derived facts about
    the current incident set, and stale rows from an earlier run would be
    evidence for findings that no longer exist.

    `log_path` is optional and improves the result rather than gating it: with
    it, the raw log line is attached to each detection, which is what lets the
    identity pivot be recognised and the Evidence tab show real source text.
    Without it, every link is still graded and explained from the detections
    table alone.
    """
    _ensure_tables(con)
    if log_path:
        enrich_from_source(log_path, incidents)
    all_links, all_rejected = [], []
    for inc in incidents:
        links, rejected = derive_links(inc, window_minutes=window_minutes)
        all_links.extend(links)
        all_rejected.extend(rejected)
    separation = incident_separation(incidents)

    if persist:
        con.execute("DELETE FROM cp2_links")
        con.execute("DELETE FROM cp2_rejected_links")
        con.execute("DELETE FROM cp2_incident_separation")
        if all_links:
            con.executemany(
                "INSERT INTO cp2_links VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(l["link_id"], l["incident_id"], l["event_a"], l["event_b"],
                  l["link_attribute"], l["attribute_value"],
                  l["time_delta_s"], l["window_s"], l["grade"], l["reason"])
                 for l in all_links])
        if all_rejected:
            con.executemany(
                "INSERT INTO cp2_rejected_links VALUES (?,?,?,?,?,?,?,?)",
                [(r["incident_id"], r["link_attribute"], r["attribute_value"],
                  r["distinct_users"], r["event_count"], r["sample_events"],
                  r["grade"], r["reason"]) for r in all_rejected])
        if separation:
            con.executemany(
                "INSERT INTO cp2_incident_separation VALUES (?,?,?,?,?,?,?)",
                [(s["incident_a"], s["incident_b"], s["shared_accounts"],
                  s["shared_ips"], s["shared_rejected"], s["verdict"],
                  s["statement"]) for s in separation])

    return all_links, all_rejected, separation
