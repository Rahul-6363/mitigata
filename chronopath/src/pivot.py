"""
pivot.py -- Rank every entity in the data by how anomalous it is.

WHY THIS FILE EXISTS
--------------------
Inspired by Hayabusa (Yamato-Security), the leading open-source Windows event
log forensics tool, which ships a `pivot-keywords-list` command. Its insight:
before you know what the attack is, list every distinct user, host and IP, and
look for the ones that stand out. Analysts call these **pivot points** -- once
you have one, you pivot on it to find everything else the attacker touched.

Hayabusa produces those lists for a human to eyeball. We go a step further and
**rank them automatically**, because on 9 million events a human cannot eyeball
anything.

THE MEASUREMENT THAT JUSTIFIES THIS
-----------------------------------
Counting how often each account appears in our detections from the real
firex-10G.log:

        155  "002"              <- noise
          3  Deepika.Khan       <- ATTACKER
          2  Rakes              <- ATTACKER
          2  Tejas.Roy          <- ATTACKER
          1  parul.sinha        <- ATTACKER
          1  svc_backup30       <- ATTACKER (created by the attacker)
          1  keerat.ghughal     <- ATTACKER

**Every single attacker account appears 1-3 times. The noise appears 155.**
Sorting by rarity surfaces the entire attack without any rule knowing what to
look for. That is the whole argument for this file.

HOW IT DIFFERS FROM OUR DETECTION RULES
---------------------------------------
Rules are *knowledge-based*: they find what we thought to describe in advance.
This is *statistics-based*: it finds what is unusual, including attacks nobody
wrote a rule for. The two are complementary, and having both is what separates
a detection tool from a hunting tool.

An analyst uses it the other way round from the rest of ChronoPath:
  - the rest answers "here is the attack we found"
  - this answers "here is what looks odd -- go and look"

SCORING
-------
Each entity gets 0-100 from three signals:

  RARITY (50%)      How few events mention it. Attackers touch few things;
                    legitimate users and servers appear constantly.
  SEVERITY (30%)    The worst detection it is involved in.
  STAGE SPREAD (20%) How many distinct kill chain stages it appears across.
                    One entity spanning Persistence AND Defense Evasion AND
                    Initial Access is a campaign, not a coincidence.

Rarity is deliberately the largest term: it is the signal that found the real
attack, and unlike the other two it needs no prior knowledge of what an attack
looks like.
"""

import math
import os
from collections import defaultdict

import duckdb

# Kill chain ordering, duplicated from graph_engine rather than imported so
# this module can be used standalone against a database.
STAGE_WEIGHT = {
    "Reconnaissance": 1, "Initial Access": 2, "Execution": 3,
    "Persistence": 4, "Privilege Escalation": 5, "Credential Access": 6,
    "Defense Evasion": 6, "Discovery": 7, "Lateral Movement": 8,
    "Collection": 9, "Command and Control": 9, "Exfiltration": 10,
    "Impact": 11,
}

# Values that occupy an identity field but name nobody. Ranking these would
# put "-" at the top of every list, since it is both common and meaningless.
PLACEHOLDERS = {"-", "", "N/A", "n/a", "unknown", "none", "null", "NULL", "0"}

# Which columns hold which kind of entity. Mirrors Hayabusa's
# rules/config/pivot_keywords.txt, where keywords are declared as
# KeywordName.FieldName, but keyed to our normalised schema so it works
# across all three log formats.
ENTITY_COLUMNS = {
    "Users": ["user"],
    "Hosts": ["host"],
    "Source IPs": ["src_ip"],
    "Destination IPs": ["dest_ip"],
    "Processes": ["process"],
}


def _usable(value):
    return value is not None and str(value).strip() not in PLACEHOLDERS


def collect_entities(db_path="chronopath.db"):
    """
    Pull every entity out of the detections table with its context.

    Reads only the detections, not the raw logs -- by this point the parser has
    already reduced 6.5 GB to a few hundred thousand rows, so the whole thing
    is a sub-second in-memory operation.
    """
    if not os.path.exists(db_path):
        return {}

    con = duckdb.connect(db_path, read_only=True)
    try:
        rows = con.execute("""
            SELECT host, user, src_ip, dest_ip, process,
                   severity, kill_chain_stage, mitre_technique, rule_name,
                   timestamp
            FROM suspicious_events
        """).fetchall()
    except duckdb.Error:
        return {}
    finally:
        con.close()

    cols = ["host", "user", "src_ip", "dest_ip", "process",
            "severity", "kill_chain_stage", "mitre_technique", "rule_name",
            "timestamp"]

    entities = defaultdict(lambda: {
        "count": 0, "max_severity": 0, "stages": set(),
        "techniques": set(), "rules": set(),
        "first_seen": None, "last_seen": None,
    })

    for row in rows:
        rec = dict(zip(cols, row))
        for kind, fields in ENTITY_COLUMNS.items():
            for field in fields:
                value = rec.get(field)
                if not _usable(value):
                    continue
                e = entities[(kind, str(value))]
                e["count"] += 1
                e["max_severity"] = max(e["max_severity"],
                                        rec.get("severity") or 0)
                if rec.get("kill_chain_stage"):
                    e["stages"].add(rec["kill_chain_stage"])
                if rec.get("mitre_technique"):
                    e["techniques"].add(rec["mitre_technique"])
                if rec.get("rule_name"):
                    e["rules"].add(rec["rule_name"])
                ts = rec.get("timestamp")
                if ts:
                    if e["first_seen"] is None or ts < e["first_seen"]:
                        e["first_seen"] = ts
                    if e["last_seen"] is None or ts > e["last_seen"]:
                        e["last_seen"] = ts

    return entities


def score_entity(stats, max_count):
    """
    Score one entity 0-100. Higher means "look at this first".

    RARITY uses a logarithmic scale, which matters at this data's scale. The
    gap between 1 event and 10 is far more meaningful than between 1,000 and
    1,010, and a linear scale would squash every genuinely rare entity into an
    indistinguishable band near zero. With log scaling, the attacker accounts
    (1-3 events) separate cleanly from the noise account (155).
    """
    count = max(stats["count"], 1)
    if max_count > 1:
        rarity = 1.0 - (math.log(count) / math.log(max_count))
    else:
        rarity = 1.0
    rarity = max(0.0, min(1.0, rarity))

    severity = stats["max_severity"] / 10.0

    # Spread across kill chain stages. Full marks at four or more: an entity
    # touching four distinct stages is following a campaign, not repeating one
    # kind of alert.
    spread = min(len(stats["stages"]) / 4.0, 1.0)

    return round((rarity * 50) + (severity * 30) + (spread * 20), 1)


def rank_entities(db_path="chronopath.db", top_n=10):
    """
    Return the most anomalous entities of each kind, worst first.

    Grouped by kind (Users, Hosts, Source IPs...) because an analyst asks
    "which accounts are odd?" rather than wanting one merged list where hosts
    and IPs compete with each other for the top spot.
    """
    entities = collect_entities(db_path)
    if not entities:
        return {}

    # Normalise rarity within each kind. A host appearing 500 times is normal;
    # a user appearing 500 times may not be. Comparing each entity only against
    # others of its own kind keeps the scores meaningful.
    by_kind = defaultdict(list)
    for (kind, value), stats in entities.items():
        by_kind[kind].append((value, stats))

    results = {}
    for kind, items in by_kind.items():
        max_count = max(s["count"] for _, s in items)
        scored = []
        for value, stats in items:
            scored.append({
                "value": value,
                "kind": kind,
                "anomaly_score": score_entity(stats, max_count),
                "event_count": stats["count"],
                "max_severity": stats["max_severity"],
                "kill_chain_stages": sorted(stats["stages"]),
                "techniques": sorted(stats["techniques"]),
                "rules": sorted(stats["rules"])[:4],
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"],
            })
        scored.sort(key=lambda x: (-x["anomaly_score"], x["event_count"]))
        results[kind] = scored[:top_n]

    return results


def activity_timeline(db_path="chronopath.db", buckets=24):
    """
    Detections per time bucket -- Hayabusa's "detection frequency timeline".

    WHY IT EARNS ITS PLACE: an attack is usually a burst. Seeing WHEN the
    detections cluster tells an analyst which hours to investigate before
    reading a single event, and a spike at 03:00 on a Sunday is itself a
    finding. It is also the cheapest possible visualisation -- one GROUP BY --
    for how much it communicates.
    """
    if not os.path.exists(db_path):
        return []

    con = duckdb.connect(db_path, read_only=True)
    try:
        rows = con.execute("""
            SELECT SUBSTR(timestamp, 1, 13) AS hour,
                   COUNT(*)                 AS detections,
                   MAX(severity)            AS worst
            FROM suspicious_events
            WHERE timestamp <> ''
            GROUP BY 1 ORDER BY 1
        """).fetchall()
    except duckdb.Error:
        return []
    finally:
        con.close()

    return [{"hour": r[0], "detections": r[1], "max_severity": r[2]}
            for r in rows]


def sparkline(values, width=48, ascii_only=False):
    """
    Render counts as a one-line bar chart for the terminal.

    Pure standard library -- no plotting dependency for something this simple.

    ASCII FALLBACK: Windows consoles default to the cp1252 code page, which
    cannot encode the Unicode block characters and raises UnicodeEncodeError
    mid-print. That is a crash in the middle of a demo, so we detect whether
    the active encoding can represent the blocks and fall back to plain ASCII
    if not. Tested: this path triggers on the demo machine's default console.
    """
    if not values:
        return ""

    blocks = "▁▂▃▄▅▆▇█"
    if ascii_only or not _console_supports(blocks):
        blocks = ".:-=+*#@"

    step = max(1, len(values) // width) if len(values) > width else 1
    sampled = values[::step][:width]

    # LOG SCALING, because real detection volumes are wildly uneven. On the
    # FortiGate data one hour holds 229,101 detections while others hold a
    # handful; on a linear scale every bar but one rounds to the floor and the
    # chart is a flat line. Log scaling keeps the shape readable across orders
    # of magnitude, which is the entire point of drawing it.
    peak = max(sampled) or 1
    log_peak = math.log1p(peak)
    return "".join(
        blocks[min(int(math.log1p(v) / log_peak * (len(blocks) - 1)), 7)]
        for v in sampled)


def _console_supports(text):
    """True if the active stdout encoding can represent `text`."""
    import sys
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Rank entities by how anomalous they look (threat hunting).")
    ap.add_argument("--db", default="chronopath.db")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    ranked = rank_entities(args.db, args.top)
    if not ranked:
        print("No detections found. Run the parser first.")
        return

    if args.json:
        import json
        print(json.dumps(ranked, indent=2, default=str))
        return

    print("\n" + "=" * 74)
    print("  PIVOT POINTS -- the most anomalous entities, worst first")
    print("=" * 74)
    print("  Rarity-weighted: attackers touch few things, noise touches many.")

    for kind in ("Users", "Hosts", "Source IPs", "Destination IPs", "Processes"):
        if kind not in ranked:
            continue
        print(f"\n  {kind}")
        print("  " + "-" * 70)
        for e in ranked[kind]:
            stages = ", ".join(e["kill_chain_stages"][:3]) or "-"
            print(f"    {e['anomaly_score']:>5.1f}  {e['value'][:28]:<28} "
                  f"{e['event_count']:>7} events  sev {e['max_severity']}")
            print(f"           {stages}")

    timeline = activity_timeline(args.db)
    if timeline:
        counts = [t["detections"] for t in timeline]
        print("\n" + "=" * 74)
        print("  DETECTION FREQUENCY OVER TIME")
        print("=" * 74)
        print(f"  {sparkline(counts)}")
        print(f"  {timeline[0]['hour']}  ->  {timeline[-1]['hour']}")
        busiest = max(timeline, key=lambda t: t["detections"])
        print(f"  Busiest hour: {busiest['hour']} "
              f"with {busiest['detections']:,} detections")
    print()


if __name__ == "__main__":
    main()
