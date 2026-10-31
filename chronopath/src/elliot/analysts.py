"""
Observations: the things an experienced, sceptical investigator would stop at.

Each analyst reads the evidence pack and returns Findings in the seven-part
format (observation, reasoning, connection, hypothesis, counterargument,
unknowns, next move). An analyst may only quote values that are in the pack,
and cites the items it quotes. If its pattern is absent it returns nothing --
a missing finding is better than a manufactured one.

Each section carries a fixed epistemic label so the analyst can tell a fact
from an inference at a glance:

  observation      FACT        what the data says, with citations
  reasoning        INFERENCE   why it matters
  connection       FACT        related evidence, cited
  hypothesis       HYPOTHESIS  one possible explanation
  counterargument  INFERENCE   why that explanation may be wrong
  unknowns         FACT        what the data cannot establish (absence)
  next_move        RECOMMENDATION  not done -- only suggested
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

import duckdb

import graph_engine

from .evidence import is_external, is_identity

SECTIONS = ("observation", "reasoning", "connection", "hypothesis",
            "counterargument", "unknowns", "next_move")
SECTION_TITLES = {
    "observation": "Observation", "reasoning": "Reasoning",
    "connection": "Connection", "hypothesis": "Hypothesis",
    "counterargument": "Counterargument", "unknowns": "Unknowns",
    "next_move": "Next move",
}
SECTION_LABELS = {
    "observation": "FACT", "reasoning": "INFERENCE", "connection": "FACT",
    "hypothesis": "HYPOTHESIS", "counterargument": "INFERENCE",
    "unknowns": "FACT", "next_move": "RECOMMENDATION",
}


@dataclass
class Finding:
    key: str            # stable across runs, so memory can recognise it
    title: str
    category: str
    priority: int       # 0-100, investigative relevance
    observation: str
    reasoning: str
    connection: str
    hypothesis: str
    counterargument: str
    unknowns: str
    next_move: str
    cites: list = field(default_factory=list)

    def as_dict(self):
        d = {s: getattr(self, s) for s in SECTIONS}
        d.update(key=self.key, title=self.title, category=self.category,
                 priority=self.priority, cites=list(self.cites),
                 labels=dict(SECTION_LABELS))
        return d


def refs(ids):
    ids = [i for i in ids if i]
    return f" [{', '.join(dict.fromkeys(ids))}]" if ids else ""


def _ts(value):
    return graph_engine._parse_ts(value)


def _gaps(pack, *telemetry_words):
    """Gap items whose telemetry or classification mentions any word."""
    out = []
    for g in pack.of("G"):
        hay = f"{g.data.get('telemetry', '')} {g.data.get('classification', '')}".lower()
        if not telemetry_words or any(w in hay for w in telemetry_words):
            out.append(g)
    return out


def _first_sentence(text):
    text = str(text or "").strip()
    cut = text.find(". ")
    return text[:cut + 1] if cut > 0 else text


def _wider(pack, column, value):
    return next((x for x in pack.of("X")
                 if x.data["column"] == column and x.data["value"] == str(value)), None)


def _query(pack, sql, params):
    try:
        con = duckdb.connect(pack.db_path, read_only=True)
    except duckdb.Error:
        return []
    try:
        cur = con.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except duckdb.Error:
        return []
    finally:
        con.close()


# ---------------------------------------------------------------------------
# The analysts
# ---------------------------------------------------------------------------
def stage_order(pack):
    """A later kill-chain stage recorded before an earlier one."""
    worst, seen = None, []
    for item, e in pack.events:
        rank = graph_engine.STAGE_ORDER.get(e["kill_chain_stage"])
        if rank is None:
            continue
        for prev_item, prev_e, prev_rank in seen:
            if prev_rank > rank and worst is None:
                worst = (prev_item, prev_e, item, e)
        seen.append((item, e, rank))
    if not worst:
        return []
    a_item, a, b_item, b = worst
    actor = a["user"] if is_identity(a["user"]) else None
    x = _wider(pack, "user", actor) if actor else None
    auth_gaps = _gaps(pack, "identity", "auth", "endpoint")
    return [Finding(
        key=f"stage-order:{a_item.id}-{b_item.id}",
        title="The attack starts in the middle",
        category="contradiction", priority=85,
        observation=(f"{b['rule_name']} ({b['kill_chain_stage']}) at {b['timestamp']} "
                     f"comes after {a['rule_name']} ({a['kill_chain_stage']}) at "
                     f"{a['timestamp']}.{refs([a_item.id, b_item.id])}"),
        reasoning=(f"In the usual kill-chain order {b['kill_chain_stage']} comes before "
                   f"{a['kill_chain_stage']}, yet it was detected later. Either an "
                   f"earlier {b['kill_chain_stage']} step happened and was not "
                   f"detected, or the actor's access predates the incident's first "
                   f"detection and {b_item.id} is a second pass."),
        connection=(f"{actor} appears elsewhere in the data: {x.text}{refs([x.id])}"
                    if x else
                    (f"No other detections for {actor} exist in this data set."
                     if actor else f"{a_item.id} carries no account.")),
        hypothesis=(f"The real entry point predates {a['timestamp']} and was not "
                    f"detected, or the actor behind {a_item.id} already held "
                    f"legitimate access."),
        counterargument=(f"Stage labels are assigned by detection rules, not observed "
                         f"intent. {b_item.id} may be a second, independent way in "
                         f"rather than the first one."),
        unknowns=(f"How the actor of {a_item.id} authenticated before "
                  f"{a['timestamp']}.{refs([g.id for g in auth_gaps])}"),
        next_move=(f"Retrieve authentication records for "
                   f"{actor or 'the actor'} on {a['host']} before {a['timestamp']}"
                   f"{refs([g.id for g in auth_gaps[:2]])}."),
        cites=[a_item.id, b_item.id] + ([x.id] if x else []) + [g.id for g in auth_gaps],
    )]


def account_lifecycle(pack):
    """An account created, used and removed inside the incident."""
    out = []
    for link in pack.of("L"):
        if link.data.get("attribute") != "identity_pivot":
            continue
        account = link.data["value"]
        created = pack.get(link.data["a"])
        if not created:
            continue
        used = [it for it, e in pack.events if e["user"] == account]
        removed = [(it, e) for it, e in pack.events
                   if ("T1070" in str(e["mitre_technique"]) or
                       "delet" in e["rule_name"].lower())
                   and _ts(e["timestamp"]) >= _ts(created.data["timestamp"])]
        cite = [created.id] + [u.id for u in used] + [r[0].id for r in removed] + [link.id]
        life = ""
        if removed:
            mins = (_ts(removed[-1][1]["timestamp"]) -
                    _ts(created.data["timestamp"])).total_seconds() / 60
            life = (f" and removed by {removed[-1][1]['timestamp']} "
                    f"({mins:.0f} minutes after creation)")
        config_gaps = _gaps(pack, "config", "lifecycle", "audit")
        creator = created.data.get("user")
        out.append(Finding(
            key=f"lifecycle:{account}",
            title=f"A short-lived account: {account}",
            category="persistence", priority=90 if removed else 75,
            observation=(f"{account} was created at {created.data['timestamp']}"
                         f"{' by ' + creator if is_identity(creator) else ''}, used "
                         f"{len(used)} time(s){life}.{refs(cite)}"),
            reasoning=("Creating a privileged account, using it, then deleting it is "
                       "a backdoor followed by clean-up. Deleting it also throws away "
                       "the access the actor built, which needs explaining: either "
                       "the goal was reached while it existed, or another way back "
                       "exists." if removed else
                       "A new privileged account used soon after creation is how an "
                       "intruder makes access survive a password reset."),
            connection=(f"The creator and the new account are joined by an identity "
                        f"pivot{refs([link.id])}."),
            hypothesis=(f"The objective was achieved while {account} existed, and "
                        f"the actor may retain a different access path."),
            counterargument=("Administrators also create temporary accounts for "
                             "maintenance and delete them afterwards. A matching "
                             "change ticket would make this routine."),
            unknowns=(f"Everything {account} did beyond what was detected while it "
                      f"existed{refs([g.id for g in config_gaps])}."),
            next_move=(f"Get the configuration change history covering "
                       f"{created.data['timestamp']} onwards, and list every other "
                       f"account {creator if is_identity(creator) else 'the creator'} "
                       f"has created{refs([g.id for g in config_gaps[:1]])}."),
            cites=cite + [g.id for g in config_gaps],
        ))
    return out


def wider_footprint(pack):
    """The same account or address active outside the incident."""
    out = []
    for x in pack.of("X"):
        column, value = x.data["column"], x.data["value"]
        if column == "host" and x.data["outside"] > 500:
            # A machine in hundreds of other detections is a busy asset or the
            # log source itself; that is not a lead.
            continue
        before = x.data["before"]
        priority = {"user": 80, "src_ip": 75, "host": 40}[column] + (5 if before else 0)
        noun = {"user": "account", "src_ip": "address", "host": "machine"}[column]
        attempts = x.data.get("attempted", 0)
        out.append(Finding(
            key=f"footprint:{column}:{value}",
            title=f"The {noun} {value} is busier than this incident shows",
            category="overlooked connection", priority=min(priority, 95),
            observation=x.text + refs([x.id]),
            reasoning=(f"Correlation only pulled in detections that link inside its "
                       f"window. {x.data['outside']} detection(s) involving this "
                       f"{noun} were left out"
                       + (f", {before} of them before the incident began, so the "
                          f"actor may have been present earlier than its first event"
                          if before else ", all after it began")
                       + (f"; {attempts} of them were blocked or failed attempts"
                          if attempts else "") + "."),
            connection=f"Rules involved: {', '.join(x.data['rules'][:6])}{refs([x.id])}.",
            hypothesis=(f"The incident starts too late: activity by {value} from "
                        f"{x.data['first']} may be its reconnaissance or access phase."
                        if before else
                        f"The actor kept operating after the incident's last event, "
                        f"until at least {x.data['last']}."),
            counterargument=(f"A busy {noun} appears in many detections for ordinary "
                             f"reasons; shared use or volume is not attribution."
                             + (" A machine is a weak link: many people use one."
                                if column == "host" else "")),
            unknowns=f"Whether these detections involve the same person as this incident.",
            next_move=(f"Review {value}'s detections from {x.data['first']}"
                       + (f" up to the incident start" if before else "")
                       + ", oldest first, and decide which belong to this incident."),
            cites=[x.id],
        ))
    return out


FAILURE_WORDS = ("fail", "brute", "attempt", "spray", "guess", "denied", "invalid")


def is_successful_login(e):
    """A detection that records an access that WORKED -- not attempts, not grants."""
    rule = e["rule_name"].lower()
    if any(w in rule for w in FAILURE_WORDS):
        return False
    if (e.get("outcome") or "observed") != "observed":
        return False
    return ("login" in rule or "logon" in rule or "sign-in" in rule
            or "vpn" in rule or str(e["mitre_technique"]).startswith("T1133"))


def success_after_failure(pack):
    """A successful login preceded, or not, by failures for the same actor."""
    out, clean_seen = [], set()
    for item, e in pack.events:
        if not is_successful_login(e):
            continue
        user = e["user"] if is_identity(e["user"]) else None
        src = e.get("src_ip") or None
        if not user and not src:
            continue
        rows = _query(pack, """
            SELECT COUNT(*) AS n, MIN(timestamp) AS first, MAX(timestamp) AS last,
                   COUNT(DISTINCT src_ip) AS sources
            FROM suspicious_events
            WHERE outcome IN ('attempted', 'prevented') AND timestamp < ?
              AND ((? IS NOT NULL AND "user" = ?) OR (? IS NOT NULL AND src_ip = ?))
        """, [str(e["timestamp"]), user, user, src, src])
        n = rows[0]["n"] if rows else 0
        idp = _gaps(pack, "identity")
        who = " / ".join(v for v in (f"account {user}" if user else "",
                                     f"address {src}" if src else "") if v)
        if n:
            r = rows[0]
            out.append(Finding(
                key=f"guessed:{item.id}",
                title="Failures before a success",
                category="credential access", priority=80,
                observation=(f"{n} blocked or failed attempt(s) involving {who} precede "
                             f"the successful {e['rule_name']} at {e['timestamp']}; "
                             f"first {r['first']}, last {r['last']}, from "
                             f"{r['sources']} source address(es).{refs([item.id])}"),
                reasoning=("Failures followed by a success for the same account or "
                           "source is the shape of password guessing that worked."),
                connection=(f"Those attempts are in the wider data set, outside this "
                            f"incident.{refs([x.id for x in pack.of('X') if x.data['value'] in (user, src)])}"),
                hypothesis=f"The credential used in {item.id} was guessed or sprayed.",
                counterargument=("People mistype passwords. Failures days earlier, or "
                                 "from different addresses, are weak evidence of "
                                 "guessing."),
                unknowns=f"Whether MFA was challenged at {e['timestamp']}.{refs([g.id for g in idp])}",
                next_move=(f"Compare the source addresses of the failures with "
                           f"{item.id}'s, and check whether the password was changed "
                           f"after {e['timestamp']}."),
                cites=[item.id] + [g.id for g in idp],
            ))
        elif (user or src) not in clean_seen:
            # One "clean login" observation per actor is enough.
            clean_seen.add(user or src)
            out.append(Finding(
                key=f"known-credential:{item.id}",
                title="A clean login: no failures first",
                category="credential access", priority=60,
                observation=(f"The successful {e['rule_name']} at {e['timestamp']} "
                             f"({who}) has no blocked or failed attempt before it "
                             f"anywhere in the data.{refs([item.id])}"),
                reasoning=("No guessing was detected, so the credential was most "
                           "likely already known: phished, reused from another "
                           "breach, or held legitimately."),
                connection=f"The rest of the incident around it:{refs([i.id for i, _ in pack.events])}.",
                hypothesis="The credential was obtained outside the visible data.",
                counterargument=("Guessing may have happened against a system whose "
                                 "logs were not supplied."),
                unknowns=f"Where the credential came from.{refs([g.id for g in idp])}",
                next_move=(f"Check for password resets, phishing reports or "
                           f"third-party breach exposure for {user or src}."),
                cites=[item.id] + [g.id for g in idp],
            ))
    return out


def timing(pack):
    """Off-hours activity, long pauses and machine-speed sequences."""
    if len(pack.events) < 1:
        return []
    off, notes, cite = [], [], []
    for item, e in pack.events:
        t = _ts(e["timestamp"])
        if t == datetime.min:
            continue
        if t.hour < 7 or t.hour >= 20 or t.weekday() >= 5:
            off.append(item)
    pairs = list(zip(pack.events, pack.events[1:]))
    long_pauses, fast = [], []
    for (a_item, a), (b_item, b) in pairs:
        ta, tb = _ts(a["timestamp"]), _ts(b["timestamp"])
        if datetime.min in (ta, tb):
            continue
        gap = (tb - ta).total_seconds()
        if gap > 3600:
            long_pauses.append((a_item, b_item, gap))
        elif 0 <= gap < 60 and a["mitre_technique"] != b["mitre_technique"]:
            fast.append((a_item, b_item, gap))
    if off:
        notes.append(f"{len(off)} step(s) fall outside 07:00-20:00 or on a weekend "
                     f"by the log's clock{refs([i.id for i in off])}")
        cite += [i.id for i in off]
    for a, b, gap in long_pauses[:3]:
        notes.append(f"{gap / 3600:.1f} h pass between {a.id} and {b.id}")
        cite += [a.id, b.id]
    for a, b, gap in fast[:3]:
        notes.append(f"{b.id} follows {a.id} after {gap:.0f} s with a different technique")
        cite += [a.id, b.id]
    if not notes:
        return []
    clock = _gaps(pack, "clock", "time")
    return [Finding(
        key="timing", title="When it happened", category="timing", priority=50,
        observation="; ".join(notes) + ".",
        reasoning=("Out-of-hours steps are when an intruder expects nobody to watch; "
                   "a long pause can be the actor waiting or working elsewhere; "
                   "sub-minute changes of technique suggest a script, not a person."),
        connection=f"The steps involved:{refs(cite)}.",
        hypothesis=("Part of this sequence was automated, and part was done by a "
                    "person who chose a quiet time." if fast else
                    "The actor chose a time when the activity was unlikely to be "
                    "noticed."),
        counterargument=("These are the log's own timestamps with no verified time "
                         "zone; shift work and scheduled jobs also run at night."),
        unknowns=(f"The account's normal working hours, which no supplied source "
                  f"records.{refs([g.id for g in clock])}"),
        next_move=("Compare these times with the account's usual sign-in hours in "
                   "the identity provider"
                   + (", and look for activity on other systems during the long pauses"
                      if long_pauses else "")
                   + (", and check whether the fast steps share a tool or script"
                      if fast else "") + "."),
        cites=cite + [g.id for g in clock],
    )]


def weak_links(pack):
    """Detections in the incident that no HARD link explains."""
    if len(pack.events) < 2:
        return []
    linked_hard, linked_any = set(), set()
    for link in pack.of("L"):
        for end in (link.data.get("a"), link.data.get("b")):
            if end:
                linked_any.add(end)
                if link.data.get("grade") == "HARD":
                    linked_hard.add(end)
    loose = [it for it, _ in pack.events if it.id not in linked_hard]
    if not loose:
        return []
    unlinked = [it for it in loose if it.id not in linked_any]
    soft = [l for l in pack.of("L") if l.data.get("grade") != "HARD"]
    return [Finding(
        key="weak-links:" + ",".join(i.id for i in loose),
        title="Parts of the chain rest on weak links",
        category="contradiction", priority=70 if unlinked else 55,
        observation=(f"{len(loose)} of {len(pack.events)} detections have no HARD "
                     f"link to the rest{refs([i.id for i in loose])}"
                     + (f"; {len(unlinked)} have no recorded link at all"
                        f"{refs([i.id for i in unlinked])}" if unlinked else "")
                     + (f". Weaker links: {refs([l.id for l in soft]).strip()}"
                        if soft else "") + "."),
        reasoning=("A shared address or a nearby time can join unrelated activity. "
                   "Without a HARD link (same account, or an account creation naming "
                   "both identities) these detections may not belong to this attack."),
        connection=f"The links that do exist:{refs([l.id for l in pack.of('L')])}.",
        hypothesis=(f"{', '.join(i.id for i in loose[:4])} belong to a different "
                    f"activity that happened to overlap in time or address."),
        counterargument=("Context attachment (same account within the window, same "
                         "machine within 15 minutes) is weaker evidence, but it is "
                         "usually right."),
        unknowns="A session or process identifier that would tie these steps together.",
        next_move=(f"Open the raw lines of {', '.join(i.id for i in loose[:3])} and "
                   f"look for a session, port or account that ties them to the rest."),
        cites=[i.id for i in loose] + [l.id for l in pack.of("L")],
    )]


def absence(pack):
    """What the conclusion cannot see."""
    out = []
    gaps = pack.of("G")
    disabled = [g for g in gaps if "LOGGING_DISABLED" in g.data["classification"]
                or "BLIND" in g.data["classification"]]
    for g in disabled:
        out.append(Finding(
            key=f"blind:{g.data.get('gap_id', g.id)}",
            title="Logging was switched off",
            category="missing evidence", priority=75,
            observation=g.text + refs([g.id]),
            reasoning=("An actor who disables logging wants something unseen. The "
                       "measured result above says whether data was actually lost, "
                       "which decides how much the gap matters."),
            connection=f"Detections in the same window:{refs([i.id for i, _ in pack.events])}.",
            hypothesis="The actor did something they expected to hide after this point.",
            counterargument=("If no events were lost, the attempt failed, and the "
                             "missing activity may simply not exist."),
            unknowns=g.data.get("impact") or "What happened while logging was affected.",
            next_move=(g.data.get("request") or "Request a copy of the logs from any "
                       "upstream collector for the same window."),
            cites=[g.id],
        ))
    not_collected = [g for g in gaps if g not in disabled]
    if not_collected:
        kinds = sorted({g.data["telemetry"] for g in not_collected})
        out.append(Finding(
            key="absence:" + ",".join(kinds),
            title="What this incident cannot see",
            category="missing evidence", priority=55,
            observation=(f"{len(not_collected)} gap(s) in {len(kinds)} kind(s) of "
                         f"evidence that was never supplied: {', '.join(kinds)}"
                         f"{refs([g.id for g in not_collected])}."),
            reasoning=("Missing data is not evidence that nothing happened, and not "
                       "evidence that it did. Each gap caps how sure any conclusion "
                       "about this incident can be."),
            connection=("The incident is built only from the detections "
                        f"listed{refs([i.id for i, _ in pack.events])}."),
            hypothesis=("Steps of this attack exist in the missing sources: the "
                        "detected chain is the visible part of a longer one."),
            counterargument=("The detected steps may be the whole story; a gap is a "
                             "limit on certainty, not a finding."),
            unknowns=" ".join(_first_sentence(g.data.get("impact", "")) + refs([g.id])
                              for g in not_collected[:3]),
            next_move=not_collected[0].data.get("request") or "Request the missing sources.",
            cites=[g.id for g in not_collected],
        ))
    return out


def outcome_mix(pack):
    """Blocked attempts mixed with steps that went through."""
    stopped = [(it, e) for it, e in pack.events
               if (e.get("outcome") or "observed") in ("prevented", "attempted")]
    through = [(it, e) for it, e in pack.events
               if (e.get("outcome") or "observed") == "observed"]
    if not stopped:
        return []
    return [Finding(
        key="outcomes", title="Not every step succeeded", category="contradiction",
        priority=45,
        observation=(f"{len(stopped)} step(s) were blocked or only attempted"
                     f"{refs([i.id for i, _ in stopped])}; {len(through)} went "
                     f"through{refs([i.id for i, _ in through])}."),
        reasoning=("A blocked step shows intent, not success. The conclusion about "
                   "what the actor achieved should rest on the steps that went through."),
        connection="The successful steps are the ones to build the timeline on.",
        hypothesis="The actor tried several routes and only some worked.",
        counterargument=("A 'blocked' label is the control's own verdict; a partial "
                         "block can still let some traffic through."),
        unknowns="Whether the blocked attempts were retried by another route.",
        next_move=("Check whether each blocked target was later reached another way "
                   "by the same account or address."),
        cites=[i.id for i, _ in stopped + through],
    )]


def single_detection(pack):
    if len(pack.events) != 1:
        return []
    item, e = pack.events[0]
    return [Finding(
        key=f"single:{item.id}", title="A story with one sentence",
        category="missing evidence", priority=60,
        observation=f"This incident is one detection: {item.text}{refs([item.id])}",
        reasoning=("With one step there is no sequence to test. Its severity is why it "
                   "is reported, not evidence of a wider attack."),
        connection=(f"Same entities elsewhere:{refs([x.id for x in pack.of('X')])}."
                    if pack.of("X") else "No other detections share its entities."),
        hypothesis="It is the visible tip of a longer sequence that was not detected.",
        counterargument="It may be an isolated action with a legitimate explanation.",
        unknowns="What happened immediately before and after it on the same system.",
        next_move=(f"Pull all logs for {e['host'] or 'the system'} from one hour "
                   f"before to one hour after {e['timestamp']}."),
        cites=[item.id] + [x.id for x in pack.of("X")],
    )]


def shared_address(pack):
    """One external address behind several accounts."""
    by_ip = defaultdict(set)
    items = defaultdict(list)
    for it, e in pack.events:
        for ip in (e.get("src_ip"), e.get("dest_ip")):
            if ip and is_external(ip) and is_identity(e["user"]):
                by_ip[ip].add(e["user"])
                items[ip].append(it.id)
    out = []
    for ip, users in by_ip.items():
        if len(users) < 2:
            continue
        rejected = [r for r in pack.of("R") if r.data.get("value") == ip]
        out.append(Finding(
            key=f"shared-ip:{ip}", title=f"{ip} speaks for {len(users)} accounts",
            category="overlooked connection", priority=65,
            observation=(f"External address {ip} is used by {', '.join(sorted(users))}"
                         f"{refs(items[ip])}."),
            reasoning=("Several accounts from one outside address is one operator "
                       "holding several credentials, or a shared exit such as a VPN "
                       "or proxy."),
            connection=(f"ChronoPath refused it as a link elsewhere{refs([r.id for r in rejected])}."
                        if rejected else "It was accepted as a link in this incident."),
            hypothesis=f"One operator at {ip} controls all {len(users)} accounts.",
            counterargument="A VPN concentrator or proxy puts unrelated people on one address.",
            unknowns=f"Who owns {ip} and whether it is a known egress point.",
            next_move=f"Look up {ip}'s ownership and check whether it appears in VPN or proxy logs.",
            cites=items[ip] + [r.id for r in rejected],
        ))
    return out


def kept_apart(pack):
    """Another incident sharing an entity with this one."""
    out = []
    for s in pack.of("S"):
        shared = ", ".join(v for v in (s.data.get("shared_accounts"),
                                       s.data.get("shared_ips"))
                           if v and v.strip().lower() not in ("[]", "none", "-", "null"))
        if not shared:
            continue
        out.append(Finding(
            key=f"apart:{s.data['other']}", title=f"Related to {s.data['other']}?",
            category="overlooked connection", priority=65,
            observation=f"{s.text}{refs([s.id])}",
            reasoning=("Two incidents that share an account or address were kept "
                       "apart by the correlation rules. That decision deserves a look."),
            connection=f"Shared: {shared}.",
            hypothesis=f"This incident and {s.data['other']} are one campaign.",
            counterargument=("They were separated for a stated reason; the shared "
                             "value may be infrastructure."),
            unknowns="Whether the same person is behind the shared value in both.",
            next_move=f"Read {s.data['other']} side by side with this one, in time order.",
            cites=[s.id],
        ))
    return out


def frozen_clock(pack):
    """
    One hour holding most of the file's events: the clock stopped moving.

    On firex-30G.log ~70% of all lines carry the same second
    (2026-10-30 08:48:36). Ordering inside that stretch is unknowable, so any
    sequence placed there by timestamp is an artefact. Measured from the
    coverage table the parser already recorded; nothing is re-read.
    """
    c = next(iter(pack.of("C")), None)
    if c is None:
        return []
    hour_key = c.data["hour"][:13].replace(" ", "T")
    inside = [it for it, e in pack.events if str(e["timestamp"])[:13] == hour_key]
    return [Finding(
        key=f"frozen-clock:{hour_key}",
        title="The log's clock stopped moving",
        category="data quality", priority=80 if inside else 35,
        observation=(f"{c.text}{refs([c.id])}."
                     + (f" This incident's steps{refs([i.id for i in inside])} are in it."
                        if inside else " None of this incident's steps fall in it.")),
        reasoning=("No real network produces most of a week's traffic in one hour. "
                   "Timestamps there stopped advancing, so the order of events inside "
                   "that stretch cannot be read from the clock."),
        connection="Measured from the per-hour coverage recorded during detection.",
        hypothesis=("The source's clock or the export that produced this file froze; "
                    "the events are real but their times are not."),
        counterargument=("A genuine flood (a scan or a storm of retries) can pack an "
                         "hour; but it would not give every event the same second."),
        unknowns="The true time of each event inside that hour.",
        next_move=("Treat the order of any steps inside that hour as unknown, and ask "
                   "for the same period from a source with an independent clock."),
        cites=[c.id] + [i.id for i in inside],
    )]


ANALYSTS = (stage_order, account_lifecycle, wider_footprint, success_after_failure,
            timing, weak_links, absence, outcome_mix, single_detection,
            shared_address, kept_apart, frozen_clock)


def observe(pack):
    findings = []
    for analyst in ANALYSTS:
        try:
            findings.extend(analyst(pack))
        except Exception as exc:  # noqa: BLE001 -- one analyst must not sink the rest
            findings.append(Finding(
                key=f"error:{analyst.__name__}", title=f"{analyst.__name__} failed",
                category="internal", priority=0,
                observation=f"This check could not run: {exc}", reasoning="",
                connection="", hypothesis="", counterargument="", unknowns="",
                next_move="", cites=[]))
    findings.sort(key=lambda f: -f.priority)
    return findings


# ---------------------------------------------------------------------------
# Strategic questions: the wider implications of what was detected.
# They are QUESTIONS, never statements that the activity happened.
# ---------------------------------------------------------------------------
THEMES = (
    ("account", ("T1078", "T1110", "T1133", "T1136", "T1098", "T1556"),
     "If {who} is compromised, what else did it touch?",
     "Every sign-in for the account across all systems, MFA results, password "
     "changes, and sessions from the same source address.",
     ("identity", "auth")),
    ("process", ("T1059", "T1204", "T1053", "T1105", "T1547", "T1218"),
     "What started the suspicious process on {host}, and what did it start?",
     "Parent and child processes with command lines from the endpoint (EDR) "
     "timeline for {host}.",
     ("endpoint", "process")),
    ("lateral", ("T1021", "T1210", "T1570", "T1550", "T1076"),
     "Which other machines did {who} or {host} reach?",
     "Authentication events on other hosts from this host or account, and "
     "SMB/RDP/WinRM network flows.",
     ("network", "auth", "endpoint")),
    ("exfiltration", ("T1041", "T1048", "T1567", "T1020", "T1030", "T1537"),
     "Did data actually leave, and how much?",
     "Network flows with byte counts by destination, file-access logs on the "
     "source host, proxy or DLP records.",
     ("network", "proxy", "file")),
    ("evasion", ("T1562", "T1070", "T1112"),
     "What did the actor want hidden after disabling or deleting evidence?",
     "The same logs from an upstream collector or SIEM, ingestion volume for the "
     "window, and configuration backups.",
     ("logging", "config", "audit")),
    ("c2", ("T1071", "T1090", "T1095", "T1573", "T1572"),
     "Is the remote endpoint talking to anything else in the estate?",
     "DNS and proxy logs for the destination, beacon timing, and other hosts "
     "contacting it.",
     ("dns", "proxy", "network")),
    ("impact", ("T1486", "T1490", "T1485", "T1489"),
     "What was damaged, and are backups intact?",
     "Backup job logs, shadow-copy deletion events, file-rename volume per host.",
     ("endpoint", "backup")),
)


def strategic_questions(pack):
    questions = []
    techniques = [(it, e) for it, e in pack.events]
    for theme, prefixes, question, evidence_needed, gap_words in THEMES:
        hits = [(it, e) for it, e in techniques
                if str(e["mitre_technique"]).startswith(prefixes)]
        if not hits:
            continue
        users = sorted({e["user"] for _, e in hits if is_identity(e["user"])})
        hosts = sorted({e["host"] for _, e in hits if e["host"]})
        who = ", ".join(users) or "the account"
        host = ", ".join(hosts[:3]) or "the host"
        gaps = _gaps(pack, *gap_words)
        questions.append({
            "key": f"question:{theme}",
            "theme": theme,
            "question": question.format(who=who, host=host),
            "why": (f"Prompted by {', '.join(sorted({str(e['mitre_technique']) for _, e in hits}))}"
                    f"{refs([it.id for it, _ in hits])}. This is a question to answer, "
                    f"not an assumption that it happened."),
            "evidence_needed": evidence_needed.format(who=who, host=host),
            "where": (f"Not in the supplied data{refs([g.id for g in gaps])}."
                      if gaps else "Partly answerable from the detections already loaded."),
            "cites": [it.id for it, _ in hits] + [g.id for g in gaps],
        })
    return questions
