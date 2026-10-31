"""
The evidence pack: everything the investigator is allowed to cite.

Every fact gets a short, stable ID so any statement can point at its source:

  E  a detection inside the incident            (FACT)
  L  a link between two of those detections     (FACT, graded HARD/SOFT/INFERRED)
  R  a value refused as a link (infrastructure) (FACT)
  G  a gap: telemetry that was not supplied     (FACT about absence)
  I  an indicator with first/last sighting      (FACT)
  S  why this incident is separate from another (FACT)
  X  the same account/address/machine elsewhere in the data set (FACT)
  P  a system reachable next                    (PREDICTION, never observed)

Nothing here is computed by guesswork: E/L/R/G/I/S come straight from the
tables ChronoPath already wrote, X from read-only queries over
suspicious_events, P from graph_engine.look_ahead().
"""

import ipaddress
import os
import re
from dataclasses import dataclass, field

import duckdb

import graph_engine

KIND_LABEL = {
    "E": "detection", "L": "link", "R": "rejected link", "G": "gap",
    "I": "indicator", "S": "separation", "X": "wider data", "C": "coverage",
    "P": "prediction",
}

# Matches the timestamp shapes found in ChronoPath data: 2026-10-28T06:13:50,
# 2026-10-28 06:13, with optional seconds/fraction/zone.
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Values that mean "unknown", mirrored from graph_engine.
NON_IDENTITIES = {"-", "", "N/A", "n/a", "unknown", "none", "null", "NULL"}


def is_identity(value):
    return bool(value) and str(value).strip() not in NON_IDENTITIES


def is_external(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_unspecified or a.is_reserved)


@dataclass
class Item:
    id: str
    kind: str          # first letter of id
    text: str          # one line an analyst can read
    data: dict = field(default_factory=dict)

    @property
    def label(self):
        return "PREDICTION" if self.kind == "P" else "FACT"


class EvidencePack:
    """The citable facts for one incident, plus lookups the analysts use."""

    def __init__(self, incident, db_path):
        self.incident = incident
        self.db_path = db_path
        self.items = {}
        self.events = []           # (Item, raw event dict) in time order
        self.event_by_index = {}   # incident event index -> Item

    # -- building -----------------------------------------------------------
    def add(self, kind, text, **data):
        n = sum(1 for i in self.items if i.startswith(kind)) + 1
        item = Item(f"{kind}{n}", kind, text, data)
        self.items[item.id] = item
        return item

    def of(self, kind):
        return [i for i in self.items.values() if i.kind == kind]

    def get(self, item_id):
        return self.items.get(item_id)

    # -- what the validator checks against ------------------------------------
    def known_timestamps(self):
        """Every timestamp string that appears anywhere in the pack."""
        found = set()
        for item in self.items.values():
            for m in TS_RE.findall(item.text):
                found.add(m.replace(" ", "T"))
            for v in item.data.values():
                if isinstance(v, str):
                    for m in TS_RE.findall(v):
                        found.add(m.replace(" ", "T"))
        return found

    def known_ips(self):
        found = set()
        for item in self.items.values():
            found.update(IP_RE.findall(item.text))
            for v in item.data.values():
                if isinstance(v, str):
                    found.update(IP_RE.findall(v))
        return found

    def render(self, kinds=None, limit_per_kind=40):
        """Plain-text listing, for the language model and for the UI."""
        lines = []
        for kind in "ELRGISXCP":
            if kinds and kind not in kinds:
                continue
            rows = self.of(kind)
            if not rows:
                continue
            lines.append(f"[{KIND_LABEL[kind]}]")
            for item in rows[:limit_per_kind]:
                lines.append(f"  {item.id} ({item.label}): {item.text}")
            if len(rows) > limit_per_kind:
                lines.append(f"  ... {len(rows) - limit_per_kind} more not shown")
        return "\n".join(lines)


def _read(con, sql, params=None):
    try:
        cur = con.execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except duckdb.Error:
        # A 2.0 table that was never built: that evidence is simply absent.
        return []


def _event_line(e):
    who = e["user"] if is_identity(e["user"]) else "no account recorded"
    parts = [f"{e['timestamp']}", f"{e['rule_name']}",
             f"[{e['mitre_technique']} {e['mitre_name']}, {e['kill_chain_stage']}]",
             f"host {e['host'] or '-'}", f"account {who}"]
    if e.get("src_ip"):
        parts.append(f"from {e['src_ip']}")
    if e.get("dest_ip"):
        parts.append(f"to {e['dest_ip']}")
    parts.append(f"outcome {e.get('outcome') or 'observed'}")
    if (e.get("event_count") or 1) > 1:
        parts.append(f"{e['event_count']} raw events")
    if e.get("context"):
        parts.append(f"attached as {e['context']} context")
    if e.get("message"):
        parts.append(f"detail: {str(e['message'])[:140]}")
    return "; ".join(parts)


def build(db_path, incident, wider=True):
    """Assemble the evidence pack for one incident. Read-only throughout."""
    pack = EvidencePack(incident, db_path)

    for idx, e in enumerate(incident["events"]):
        item = pack.add("E", _event_line(e), timestamp=str(e["timestamp"]),
                        index=idx, rule=e["rule_name"],
                        technique=e["mitre_technique"],
                        stage=e["kill_chain_stage"], host=e["host"] or "",
                        user=e["user"] or "", src_ip=e.get("src_ip") or "",
                        dest_ip=e.get("dest_ip") or "",
                        outcome=e.get("outcome") or "observed",
                        severity=e.get("severity") or 0,
                        message=str(e.get("message") or ""),
                        context=e.get("context") or "")
        pack.events.append((item, e))
        pack.event_by_index[idx] = item

    if not os.path.exists(db_path):
        return pack
    con = duckdb.connect(db_path, read_only=True)
    try:
        _add_cp2(pack, con, incident)
        _add_coverage(pack, con)
        if wider:
            _add_wider(pack, con, incident)
    finally:
        con.close()

    for a in graph_engine.look_ahead(incident):
        role = f" ({a['role']})" if a.get("role") else ""
        pack.add("P", f"{a['target']}{role} could be reached next: {a['reason']}",
                 target=str(a["target"]), basis=a.get("basis", ""))
    return pack


def _event_ref(pack, ref):
    """cp2 event references look like 'INC-01:002@2026-...' -> E3."""
    m = re.match(r".*?:(\d+)@", str(ref or ""))
    if not m:
        return None
    item = pack.event_by_index.get(int(m.group(1)))
    return item.id if item else None


def _add_cp2(pack, con, incident):
    iid = incident["id"]
    for r in _read(con, "SELECT * FROM cp2_links WHERE incident_id = ? "
                        "ORDER BY time_delta_s", [iid]):
        a, b = _event_ref(pack, r["event_a"]), _event_ref(pack, r["event_b"])
        pack.add("L", f"{a} -> {b} linked by {r['link_attribute']} "
                      f"'{r['attribute_value']}', grade {r['grade']}: {r['reason']}",
                 a=a or "", b=b or "", grade=r["grade"],
                 attribute=r["link_attribute"], value=str(r["attribute_value"]))
    for r in _read(con, "SELECT * FROM cp2_rejected_links WHERE incident_id = ?",
                   [iid]):
        pack.add("R", f"{r['link_attribute']} '{r['attribute_value']}' refused as "
                      f"a link: {r['reason']}",
                 attribute=r["link_attribute"], value=str(r["attribute_value"]))
    for r in _read(con, "SELECT * FROM cp2_gaps WHERE incident_id = ? "
                        "OR incident_id IS NULL OR incident_id = ''", [iid]):
        window = ""
        if r.get("time_start") or r.get("time_end"):
            window = f" for {r.get('time_start') or '?'} to {r.get('time_end') or '?'}"
        pack.add("G", f"{r['classification']}: {r['telemetry']} for "
                      f"{r['asset_or_entity']}{window}. {r['basis']} "
                      f"Request: {r['evidence_request']}",
                 classification=r["classification"], telemetry=r["telemetry"],
                 entity=str(r["asset_or_entity"]), impact=str(r["impact"] or ""),
                 request=str(r["evidence_request"] or ""), gap_id=r["gap_id"])
    for r in _read(con, "SELECT * FROM cp2_indicators WHERE incident_id = ?", [iid]):
        note = f" ({r['note']})" if r.get("note") else ""
        pack.add("I", f"{r['indicator_type']} {r['value']}: first seen "
                      f"{r['first_seen']}, last seen {r['last_seen']}, "
                      f"{r['occurrences']} occurrence(s){note}",
                 type=r["indicator_type"], value=str(r["value"]),
                 first_seen=str(r["first_seen"]), last_seen=str(r["last_seen"]),
                 occurrences=int(r["occurrences"] or 0))
    for r in _read(con, "SELECT * FROM cp2_incident_separation "
                        "WHERE incident_a = ? OR incident_b = ?", [iid, iid]):
        other = r["incident_b"] if r["incident_a"] == iid else r["incident_a"]
        pack.add("S", f"vs {other}: {r['verdict']} -- {r['statement']}",
                 other=other, verdict=str(r["verdict"]),
                 shared_accounts=str(r.get("shared_accounts") or ""),
                 shared_ips=str(r.get("shared_ips") or ""))


def _add_coverage(pack, con):
    """
    The busiest hour of the whole file, from the coverage the parser recorded.
    Only a file spanning at least a day can show a clock that stopped: on a
    short sample every event falls in one hour quite legitimately.
    """
    rows = _read(con, """
        SELECT hour_bucket, SUM(event_count) AS n,
               SUM(SUM(event_count)) OVER () AS total,
               COUNT(*) OVER () AS hours
        FROM cp2_stream_volume GROUP BY 1 ORDER BY n DESC LIMIT 1""")
    if not rows or not rows[0]["total"] or rows[0]["hours"] < 24:
        return
    r = rows[0]
    share = r["n"] / r["total"]
    if share < 0.5:
        return
    hour = str(r["hour_bucket"])
    pack.add("C", f"{r['n']:,} of the file's {r['total']:,} events ({share:.0%}) are "
                  f"stamped within the single hour starting {hour}; the file spans "
                  f"{r['hours']} hours",
             hour=hour, n=int(r["n"]), total=int(r["total"]), share=share)


def _add_wider(pack, con, incident):
    """
    The incident's accounts, external addresses and machines everywhere else
    in the detection table. This is where overlooked connections live: activity
    by the same actor that correlation did not pull into the incident.
    """
    inside = {(str(e["timestamp"]), e["rule_name"]) for e in incident["events"]}
    users = sorted({e["user"] for e in incident["events"] if is_identity(e["user"])})
    ips = sorted({ip for e in incident["events"]
                  for ip in (e.get("src_ip"), e.get("dest_ip"))
                  if ip and is_external(ip)})
    hosts = sorted({e["host"] for e in incident["events"] if e["host"]})

    for column, values, label in (("user", users, "account"),
                                  ("src_ip", ips, "address"),
                                  ("host", hosts, "machine")):
        for value in values:
            rows = _read(con, f"""
                SELECT rule_name, timestamp, outcome, mitre_technique
                FROM suspicious_events WHERE "{column}" = ?
                ORDER BY timestamp LIMIT 20001""", [value])
            outside = [r for r in rows
                       if (str(r["timestamp"]), r["rule_name"]) not in inside]
            if not outside:
                continue
            truncated = len(rows) > 20000
            by_rule = {}
            for r in outside:
                s = by_rule.setdefault(r["rule_name"], {"n": 0, "first": r["timestamp"],
                                                        "last": r["timestamp"],
                                                        "outcomes": set()})
                s["n"] += 1
                s["last"] = r["timestamp"]
                s["outcomes"].add(r["outcome"] or "observed")
            first = str(outside[0]["timestamp"])
            last = str(outside[-1]["timestamp"])
            before = sum(1 for r in outside if str(r["timestamp"]) < str(incident["start_time"]))
            rules = "; ".join(
                f"{name} x{s['n']} ({'/'.join(sorted(s['outcomes']))}, "
                f"{s['first']} to {s['last']})"
                for name, s in sorted(by_rule.items(), key=lambda kv: -kv[1]["n"])[:6])
            more = "+" if truncated else ""
            pack.add("X", f"{label} {value} has {len(outside)}{more} detection(s) "
                          f"outside this incident, {before} of them before it "
                          f"started; first {first}, last {last}. Rules: {rules}",
                     column=column, value=str(value), outside=len(outside),
                     before=before, first=first, last=last,
                     rules=sorted(by_rule), truncated=truncated,
                     attempted=sum(s["n"] for s in by_rule.values()
                                   if s["outcomes"] <= {"attempted", "prevented"}))
