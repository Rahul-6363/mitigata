"""
discover_firex.py -- Find the planted attack in the organisers' FortiGate file.

WHY THIS FILE EXISTS
--------------------
The organisers supplied `firex-10G.log` (6.5 GB) but no answer key, and the
PRD scores us on matching "the planted attacks (ground truth)". So the first
job was to work out what the planted attack actually is.

This script is how we did it, kept in the repo so the finding is reproducible
rather than asserted. Run it and you get the same answer we did.

THE METHOD: RARITY, NOT VOLUME
------------------------------
The temptation on a firewall log is to chase the biggest numbers. That is
exactly backwards. Measured across all 9,125,382 events:

    Admin login FAILED ............. 1,272,524      <- internet background noise
    IPS exploit detections ........... 177,772      <- constant scanning
    Antivirus hits ................... 135,623      <- constant
    ---------------------------------------------
    Admin login SUCCEEDED .................... 5    <- THE ATTACK
    SSL VPN tunnel up ........................ 4
    Config attribute changed ................. 3
    Admin account added/deleted .............. 2

A million failed logins against an exposed management interface is what the
internet does to every firewall, all day. It is noise. Five *successes* are
the intrusion. The signal is four orders of magnitude rarer than the noise,
and the whole detection strategy follows from that single observation.

WHAT IT PRINTS
    - the rare-event census above
    - every rare event in time order, which reads as the attack narrative
    - the create/use/delete admin account cycle, the clearest evidence present

Run:  python scripts/discover_firex.py --input D:/mitigata/firex-10G.log
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import duckdb  # noqa: E402
import fortigate_adapter  # noqa: E402

# Housekeeping events the device emits constantly. Excluded so the rare,
# security-relevant events stand out.
ROUTINE = ("'%statistic%'", "'%health-check%'", "'%HA device%'", "'%DHCP%'")


def main():
    ap = argparse.ArgumentParser(
        description="Locate the planted attack in FortiGate logs by rarity.")
    ap.add_argument("--input", default="D:/mitigata/firex-10G.log")
    ap.add_argument("--memory-limit", default="6GB")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        raise SystemExit(f"Not found: {args.input}")

    con = duckdb.connect()
    con.execute(f"SET memory_limit='{args.memory_limit}'")
    con.execute("SET temp_directory='./tmp_spill'")
    con.execute("SET preserve_insertion_order=false")
    src = fortigate_adapter.fortigate_source_expr(args.input)

    size_gb = os.path.getsize(args.input) / 1e9
    print(f"\nScanning {args.input}  ({size_gb:.2f} GB)")
    print("Looking for the RAREST security events, not the most common.\n")

    not_routine = " AND ".join(f"fg_logdesc NOT LIKE {p}" for p in ROUTINE)

    print("=" * 72)
    print("  EVENT CENSUS -- rarest first")
    print("=" * 72)
    rows = con.execute(f"""
        SELECT fg_logdesc, fg_status, COUNT(*) AS c
        FROM {src}
        WHERE fg_logdesc <> '' AND {not_routine}
        GROUP BY 1, 2 ORDER BY c ASC
    """).fetchall()
    for desc, status, count in rows:
        flag = "  <-- RARE, investigate" if count < 100 else ""
        print(f"  {count:>10,}  {desc} [{status}]{flag}")

    print()
    print("=" * 72)
    print("  THE ATTACK NARRATIVE -- every rare event, in time order")
    print("=" * 72)
    narrative = con.execute(f"""
        SELECT timestamp, src_ip, "user", fg_logdesc, fg_msg
        FROM {src}
        WHERE fg_logdesc IN ('Admin login successful', 'SSL VPN tunnel up',
                             'Attribute configured', 'Object attribute configured')
        ORDER BY timestamp
    """).fetchall()
    for ts, ip, user, desc, msg in narrative:
        print(f"\n  {ts}  {ip:<16} {user}")
        print(f"      {desc}")
        if msg:
            print(f"      {msg[:100]}")

    print()
    print("=" * 72)
    print("  SMOKING GUN -- admin account created, used, then deleted")
    print("=" * 72)
    cycle = con.execute(f"""
        SELECT timestamp, src_ip, "user", fg_msg
        FROM {src}
        WHERE fg_msg LIKE '%system.admin%'
           OR (fg_logdesc = 'Admin login successful'
               AND "user" LIKE 'svc_%')
        ORDER BY timestamp
    """).fetchall()
    for ts, ip, user, msg in cycle:
        print(f"  {ts}  {ip:<16} {user:<14} {msg[:60]}")
    if len(cycle) >= 3:
        print("\n  An administrator account created, used and destroyed within")
        print("  minutes is not administration -- it is anti-forensics.")

    print()
    print("=" * 72)
    print("  BRUTE FORCE CONTEXT")
    print("=" * 72)
    bf = con.execute(f"""
        SELECT COUNT(*) AS total, COUNT(DISTINCT src_ip) AS sources
        FROM {src} WHERE fg_logdesc = 'Admin login failed'
    """).fetchone()
    print(f"  {bf[0]:,} failed admin logins from {bf[1]:,} distinct source IPs")
    print(f"  ...against only {len(narrative)} rare successful/config events.")
    print("  The failures are background noise; the successes are the attack.\n")

    con.close()


if __name__ == "__main__":
    main()
