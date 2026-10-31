"""
generate_sample.py -- Build a synthetic security log file with a known attack inside.

WHY THIS FILE EXISTS
--------------------
Two reasons, both practical:

1. WE CAN BUILD BEFORE THE DATA ARRIVES. The real 15 GB tier downloads when the
   hackathon build starts. Waiting on it would waste hours. This script produces
   logs in the same shape, so every other file can be written and tested offline.

2. WE GET GROUND TRUTH. The PRD scores us on "share of planted attack steps your
   tool finds". To measure recall you must know the right answer in advance. This
   script plants a specific 7-step attack (INC-01) and writes the answer key to
   ground_truth.json. evaluate.py then grades the detector against it.

WHAT IT WRITES
--------------
  data/sample.ndjson      newline-delimited JSON, one log event per line
  data/ground_truth.json  the planted attack steps, for scoring

WHY NDJSON (one JSON object per line) rather than one big JSON array?
A 15 GB JSON array must be parsed as a single document -- the parser cannot know
where it ends until it reaches the end, so it tends to materialise the whole thing
in memory. NDJSON can be split at any newline, which is exactly what lets DuckDB
stream it in chunks and keep memory flat. The file format choice IS the memory
strategy.
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta

# Fixed seed: the same logs every run. A demo that changes under you is a demo
# that breaks on stage.
random.seed(1337)

# --- The fictional company -------------------------------------------------
# A few hundred machines and users, matching the PRD's "few hundred laptops,
# servers and users".
WORKSTATIONS = [f"HR-{i:02d}" for i in range(1, 41)]
FILE_SERVERS = [f"FS-{i:02d}" for i in range(1, 13)]
DOMAIN_CTRL = ["DC-01", "DC-02"]
ALL_HOSTS = WORKSTATIONS + FILE_SERVERS + DOMAIN_CTRL

NORMAL_USERS = [f"user{i:03d}" for i in range(1, 181)]
ADMINS = ["admin_jane", "admin_raj"]
SERVICE_ACCOUNTS = ["svc_backup", "svc_monitor"]

BENIGN_PROCESSES = ["explorer.exe", "chrome.exe", "outlook.exe", "teams.exe",
                    "word.exe", "excel.exe", "svchost.exe", "cmd.exe"]

# Event IDs are real Windows Security Log codes, so the rules in rules.yaml look
# like rules a real SOC would write.
EVT_LOGON_OK = 4624
EVT_LOGON_FAIL = 4625
EVT_SPECIAL_PRIV = 4672
EVT_PROCESS = 4688
EVT_ACCOUNT_NEW = 4720
EVT_SHARE_ACCESS = 5140
EVT_FILE_ACCESS = 5145

START = datetime(2026, 10, 20, 8, 0, 0)


def internal_ip() -> str:
    return f"10.0.{random.randint(1, 50)}.{random.randint(2, 250)}"


def external_ip() -> str:
    """Deliberately outside 10.x and 192.168.x so the rules flag it."""
    return f"203.0.{random.randint(1, 200)}.{random.randint(2, 250)}"


def event(ts, host, user, event_id, **extra):
    """
    One log line. Every record carries the same keys, because an explicit, stable
    schema is what lets DuckDB skip type inference on the big file (see parser.py).
    Missing values are written as defaults rather than omitted.
    """
    rec = {
        "timestamp": ts.isoformat(),
        "host": host,
        "user": user,
        "event_id": event_id,
        "src_ip": extra.get("src_ip", internal_ip()),
        "dest_ip": extra.get("dest_ip", ""),
        "status": extra.get("status", "success"),
        "process": extra.get("process", ""),
        "bytes_out": extra.get("bytes_out", 0),
        "message": extra.get("message", ""),
    }
    return rec


def generate_noise(n, clock):
    """
    Ordinary business activity: the haystack.

    This matters as much as the attack. If the logs contained only the attack,
    a detector that flags everything would score 100%. Realistic noise is what
    makes the false-positive metric (<30% Good, <10% Great) meaningful, and it
    includes a few *failed logins* because real users mistype passwords -- our
    brute-force rule must be smart enough not to trip on those.
    """
    out = []
    for _ in range(n):
        clock += timedelta(milliseconds=random.randint(50, 400))
        user = random.choice(NORMAL_USERS)
        host = random.choice(ALL_HOSTS)
        roll = random.random()

        if roll < 0.40:
            out.append(event(clock, host, user, EVT_LOGON_OK))
        elif roll < 0.48:
            # A handful of genuine typos -- noise, not an attack.
            out.append(event(clock, host, user, EVT_LOGON_FAIL, status="failed"))
        elif roll < 0.75:
            out.append(event(clock, host, user, EVT_PROCESS,
                             process=random.choice(BENIGN_PROCESSES)))
        elif roll < 0.90:
            out.append(event(clock, random.choice(FILE_SERVERS), user,
                             EVT_FILE_ACCESS))
        else:
            # Everyday internal uploads, far below the exfil threshold.
            out.append(event(clock, host, user, EVT_PROCESS,
                             dest_ip=internal_ip(),
                             bytes_out=random.randint(1000, 500000)))
    return out, clock


def generate_attack(clock):
    """
    INC-01: the planted attack. Modelled on the 2013 retail breach referenced in
    the hackathon brief -- one stolen vendor login that ends in mass data theft.

    Each step is one kill-chain stage, and each returns the ground-truth record
    that evaluate.py will grade against. The steps are deliberately spread across
    different hosts and users, because the whole point of FR-4 is linking events
    that look unrelated.
    """
    events, truth = [], []
    attacker_ip = external_ip()
    exfil_ip = external_ip()
    vendor = "svc_vendor_hvac"     # the third-party account
    foothold = "HR-07"             # first laptop
    target_fs = "FS-02"            # file server
    backdoor = "svc_helpdesk_adm"  # account the attacker creates

    def step(ts, stage, technique, ev):
        events.append(ev)
        truth.append({
            "step": len(truth) + 1,
            "stage": stage,
            "technique": technique,
            "timestamp": ev["timestamp"],
            "host": ev["host"],
            "user": ev["user"],
        })

    # STEP 1 - Initial Access. Stolen vendor credential, used from outside.
    clock += timedelta(minutes=3)
    step(clock, "Initial Access", "T1078",
         event(clock, foothold, vendor, EVT_LOGON_OK,
               src_ip=attacker_ip, message="Vendor portal login"))

    # STEP 2 - Credential Access. Brute force against a local admin.
    # 35 failures comfortably exceeds the rule's threshold of 20.
    for _ in range(35):
        clock += timedelta(seconds=random.randint(2, 9))
        events.append(event(clock, foothold, "admin_jane", EVT_LOGON_FAIL,
                            src_ip=attacker_ip, status="failed"))
    clock += timedelta(seconds=5)
    truth.append({"step": len(truth) + 1, "stage": "Credential Access",
                  "technique": "T1110", "timestamp": clock.isoformat(),
                  "host": foothold, "user": "admin_jane"})
    # ...and then the success that proves they got in.
    events.append(event(clock, foothold, "admin_jane", EVT_LOGON_OK,
                        src_ip=attacker_ip))

    # STEP 3 - Credential Dumping. Mimikatz-style LSASS read.
    clock += timedelta(minutes=2)
    step(clock, "Credential Access", "T1003.001",
         event(clock, foothold, "admin_jane", EVT_PROCESS,
               process="lsass.exe", src_ip=attacker_ip,
               message="Suspicious memory read of LSASS"))

    # STEP 4 - Privilege Escalation. Create a persistent backdoor account.
    clock += timedelta(minutes=4)
    step(clock, "Privilege Escalation", "T1136",
         event(clock, foothold, backdoor, EVT_ACCOUNT_NEW,
               src_ip=attacker_ip, message=f"Account {backdoor} created"))
    clock += timedelta(seconds=30)
    step(clock, "Privilege Escalation", "T1078.003",
         event(clock, foothold, backdoor, EVT_SPECIAL_PRIV, src_ip=attacker_ip))

    # STEP 5 - Lateral Movement. Foothold laptop -> file server.
    clock += timedelta(minutes=6)
    step(clock, "Lateral Movement", "T1021.002",
         event(clock, target_fs, backdoor, EVT_SHARE_ACCESS,
               src_ip=attacker_ip, message="SMB share C$ accessed"))

    # STEP 6 - Collection. Sweep up files (45 reads > threshold of 30).
    for _ in range(45):
        clock += timedelta(seconds=random.randint(1, 6))
        events.append(event(clock, target_fs, backdoor, EVT_FILE_ACCESS,
                            src_ip=attacker_ip))
    truth.append({"step": len(truth) + 1, "stage": "Collection",
                  "technique": "T1005", "timestamp": clock.isoformat(),
                  "host": target_fs, "user": backdoor})

    # STEP 7 - Exfiltration. 250 MB out to an external IP.
    clock += timedelta(minutes=8)
    step(clock, "Exfiltration", "T1041",
         event(clock, target_fs, backdoor, EVT_PROCESS,
               dest_ip=exfil_ip, bytes_out=250_000_000,
               process="powershell.exe",
               message="Large outbound transfer"))

    return events, truth, clock


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic logs with a planted attack.")
    ap.add_argument("--size-mb", type=float, default=50,
                    help="Approximate output size in MB (default 50).")
    ap.add_argument("--out", default="data/sample.ndjson")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    # ~320 bytes/line measured; used only to decide how much noise to make.
    target_lines = int(args.size_mb * 1_000_000 / 320)
    clock = START

    print(f"Generating ~{args.size_mb} MB  (~{target_lines:,} events)")

    # The attack is planted in the MIDDLE of the noise, not at the start.
    # The PRD's premise is that attack lines sit "millions of lines apart" --
    # if the attack were at the top, finding it would prove nothing.
    noise_before = target_lines // 2
    noise_after = target_lines - noise_before

    with open(args.out, "w", encoding="utf-8") as f:
        batch, clock = generate_noise(noise_before, clock)
        for rec in batch:
            f.write(json.dumps(rec) + "\n")
        del batch  # free it; we never hold the whole log set at once

        attack, truth, clock = generate_attack(clock)
        for rec in attack:
            f.write(json.dumps(rec) + "\n")

        batch, clock = generate_noise(noise_after, clock)
        for rec in batch:
            f.write(json.dumps(rec) + "\n")
        del batch

    truth_path = os.path.join(os.path.dirname(args.out) or ".", "ground_truth.json")
    with open(truth_path, "w", encoding="utf-8") as f:
        json.dump({"incident": "INC-01",
                   "description": "Stolen vendor credential -> data theft",
                   "steps": truth}, f, indent=2)

    size_mb = os.path.getsize(args.out) / 1e6
    print(f"  wrote {args.out}  ({size_mb:.1f} MB)")
    print(f"  wrote {truth_path}  ({len(truth)} planted attack steps)")
    print(f"  attack hidden at roughly line {noise_before:,}")


if __name__ == "__main__":
    main()
