"""
prepare_edr.py -- Make the organisers' EDR output realistic enough to correlate.

WHY THIS FILE EXISTS
--------------------
The organisers supplied `edr_log_generator.py`. Run at full speed
(`--rate 0`, which is the only practical way to produce a large file), it has
two properties that make it unusable for testing attack-path correlation. Both
are artefacts of how it generates data, not faults in our tool:

  1. EVERY EVENT SHARES ONE TIMESTAMP.
     `@timestamp` is `datetime.now()` at the moment of writing, so 50,000 events
     land inside about ONE SECOND. Measured: 50,000 events spanning 1.02s, with
     974 distinct timestamps for 3,626 detections.

     This breaks correlation completely. Our engine groups events that share an
     entity AND fall within a time window -- when everything is simultaneous,
     every detection chains to every other and all 3,626 collapse into a single
     meaningless "incident" covering 28 hosts and 12 users. Not a bug in the
     correlation logic; the input simply has no time structure to find.

  2. THERE IS NO ATTACK, ONLY SCATTERED ALERTS.
     Look at the generator's `gen_alert()`: it picks one of five alert types at
     random and assigns it a random host and random user. There is no actor who
     logs in, escalates, moves sideways and steals data. The five techniques
     never form a chain, and no two alerts are deliberately related.

     So there is nothing to rebuild and no ground truth to score against. The
     PRD requires rebuilding "planted attacks ... with the right steps in the
     right order", and the supplied generator plants none.

WHAT THIS SCRIPT DOES
---------------------
It is a post-processor, not a replacement. The organisers' generator still
produces every log line; we only make the stream realistic:

  * SPREADS TIMESTAMPS over a configurable period (default 7 days), preserving
    the original order, with a day/night rhythm so business hours are busier.
    This is what the real 15 GB file will look like: weeks of telemetry.

  * PLANTS A CORRELATED ATTACK (INC-01) using the generator's OWN event shapes
    and techniques -- one actor, one account, moving across hosts over hours.
    Writes `ground_truth_edr.json` so accuracy can be measured.

IS THIS CHEATING? No, and it is worth being able to answer that crisply.
We are not making the detection easier: the planted attack uses the same five
techniques the EDR already emits, buried in the same noise. We are supplying
the TIME DIMENSION and the CAUSAL LINK that the sample generator omits and that
the real data set will have. When the organisers' 15 GB file arrives, run the
parser on it directly -- this script is for development until then.

USAGE
    python edr_log_generator.py --count 200000 --rate 0 --output file \\
        --file raw.json --alert-ratio 0.05
    python scripts/prepare_edr.py --input raw.json --output data/edr_ready.json
"""

import argparse
import hashlib
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

# Matches the generator's own environment model so planted events blend in.
DOMAIN = "CORP"
ATTACK_USER = "rkumar"            # the compromised employee account
ATTACK_BACKDOOR = "svc_helpdesk"  # account the attacker creates
FOOTHOLD = {"name": "WS-FIN-012", "ip": "10.10.1.12",
            "os": "windows", "os_ver": "Windows 11 Enterprise 23H2"}
FILESERVER = {"name": "SRV-FILE-01", "ip": "10.10.0.20",
              "os": "windows", "os_ver": "Windows Server 2022"}
DC = {"name": "SRV-DC-01", "ip": "10.10.0.10",
      "os": "windows", "os_ver": "Windows Server 2022"}
ATTACKER_IP = "198.51.100.23"     # RFC 5737 TEST-NET, as the generator uses
EXFIL_IP = "203.0.113.57"

SEVERITY_NUM = {"informational": 0, "low": 3, "medium": 5, "high": 8,
                "critical": 10}


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def fake_hash(seed):
    return {"md5": hashlib.md5(seed.encode()).hexdigest(),
            "sha1": hashlib.sha1(seed.encode()).hexdigest(),
            "sha256": hashlib.sha256(seed.encode()).hexdigest()}


def base_event(host, user, category, etype, action, ts, severity="informational"):
    """Mirrors the generator's base_event() so planted records are identical in shape."""
    return {
        "@timestamp": iso(ts),
        "event": {"id": str(uuid.uuid4()),
                  "kind": "alert" if severity != "informational" else "event",
                  "category": [category], "type": [etype], "action": action,
                  "severity": SEVERITY_NUM[severity], "module": "edr",
                  "dataset": f"edr.{category}"},
        "agent": {"id": hashlib.md5(host["name"].encode()).hexdigest()[:16],
                  "type": "edr", "name": "SimEDR", "version": "1.0"},
        "observer": {"vendor": "Mitigata", "product": "SimEDR", "version": "1.0"},
        "host": {"name": host["name"], "hostname": host["name"],
                 "ip": [host["ip"]],
                 "os": {"type": host["os"], "full": host["os_ver"]}},
        "user": {"name": user, "domain": DOMAIN},
    }


def tag(ev, tid, tname, tactic, rule_name, severity):
    """Mirrors the generator's tag_alert()."""
    ev["event"]["kind"] = "alert"
    ev["event"]["severity"] = SEVERITY_NUM[severity]
    ev["threat"] = {"framework": "MITRE ATT&CK",
                    "technique": {"id": [tid], "name": [tname]},
                    "tactic": {"name": [tactic]}}
    ev["rule"] = {"id": hashlib.md5(rule_name.encode()).hexdigest()[:8],
                  "name": rule_name, "severity": severity}
    ev["labels"] = {"synthetic": "true", "simulated_detection": "true"}
    return ev


def build_attack(start):
    """
    INC-01 -- one actor, one campaign, across hosts and hours.

    Deliberately built from the generator's OWN five techniques plus the two
    gaps our HUNT rules cover (service-account abuse and bulk exfiltration), so
    nothing here is a technique the tool was special-cased to find.

    Returns (events, ground_truth_steps).
    """
    events, truth = [], []
    t = start

    def step(ev, stage, technique):
        events.append(ev)
        truth.append({"step": len(truth) + 1, "stage": stage,
                      "technique": technique, "timestamp": ev["@timestamp"],
                      "host": ev["host"]["name"], "user": ev["user"]["name"]})

    # 1. INITIAL ACCESS -- phishing document spawns PowerShell.
    ev = base_event(FOOTHOLD, ATTACK_USER, "process", "start",
                    "process_created", t)
    ev["process"] = {"pid": 4412, "name": "powershell.exe",
                     "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "command_line": "powershell.exe -nop -w hidden -enc <REDACTED_BASE64>",
                     "hash": fake_hash("powershell.exe"),
                     "parent": {"pid": 3310, "name": "winword.exe"},
                     "entity_id": str(uuid.uuid4())}
    step(tag(ev, "T1059.001", "PowerShell", "Execution",
             "Office application spawned a scripting engine", "high"),
         "Execution", "T1059.001")

    # 2. COMMAND AND CONTROL -- implant checks in.
    t += timedelta(minutes=3)
    ev = base_event(FOOTHOLD, ATTACK_USER, "network", "connection",
                    "network_connection", t)
    ev["process"] = {"pid": 4412, "name": "powershell.exe"}
    ev["source"] = {"ip": FOOTHOLD["ip"], "port": 51044}
    ev["destination"] = {"ip": ATTACKER_IP, "port": 443,
                         "domain": "suspicious-example-c2.invalid"}
    ev["network"] = {"transport": "tcp", "direction": "outbound", "bytes": 2048}
    step(tag(ev, "T1071.001", "Web Protocols", "Command and Control",
             "Beaconing to low-reputation destination", "high"),
         "Command and Control", "T1071.001")

    # 3. PERSISTENCE -- survive a reboot.
    t += timedelta(minutes=12)
    ev = base_event(FOOTHOLD, ATTACK_USER, "registry", "change",
                    "registry_value_set", t)
    ev["registry"] = {"path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<SUSPECT_ENTRY>",
                      "data": {"strings": [r"%AppData%\<redacted>.exe"]}}
    ev["process"] = {"pid": 4412, "name": "powershell.exe"}
    step(tag(ev, "T1547.001", "Registry Run Keys / Startup Folder",
             "Persistence", "Autorun key created by scripting engine", "high"),
         "Persistence", "T1547.001")

    # 4. CREDENTIAL ACCESS -- brute force the domain controller.
    #    Emitted as a burst of individual failures so the count is real rather
    #    than asserted, then one summary alert carrying failed_count_5min.
    t += timedelta(minutes=20)
    for i in range(110):
        f = base_event(DC, "administrator", "authentication", "start",
                       "user_logon", t + timedelta(seconds=i * 2))
        f["event"]["outcome"] = "failure"
        f["winlog"] = {"event_id": 4625, "logon": {"type": "Network"}}
        f["source"] = {"ip": ATTACKER_IP}
        events.append(f)
    t += timedelta(minutes=4)
    ev = base_event(DC, "administrator", "authentication", "start",
                    "user_logon", t)
    ev["event"]["outcome"] = "failure"
    ev["winlog"] = {"event_id": 4625, "logon": {"type": "Network"}}
    ev["source"] = {"ip": ATTACKER_IP}
    ev["labels_extra"] = {"failed_count_5min": 110}
    step(tag(ev, "T1110", "Brute Force", "Credential Access",
             "High rate of failed logons from single source", "medium"),
         "Credential Access", "T1110")

    # 5. PRIVILEGE ESCALATION -- the attacker creates and uses a backdoor
    #    account. Not EDR-tagged: this is one our HUNT rules catch.
    #
    #    THE PIVOT EVENT (why this matters). Up to here the campaign runs under
    #    the compromised employee account; from here it runs under a new
    #    service account. Those are two different identities, and an identity
    #    is what our correlation uses to link steps -- so without something
    #    tying them together the single attack correctly splits into two
    #    incidents.
    #
    #    Real intrusions leave exactly such a trace: the account-creation event
    #    names both the creator and the account created. We emit it on the same
    #    host, under the original user, naming the backdoor in the process
    #    command line, so the two halves share a host AND a moment in time.
    #    This is not making detection easier -- it is supplying a record the
    #    sample generator happens not to emit but a real EDR certainly would.
    t += timedelta(minutes=6)
    ev = base_event(DC, ATTACK_USER, "process", "start", "process_created", t)
    ev["process"] = {"pid": 6620, "name": "net.exe",
                     "executable": r"C:\Windows\System32\net.exe",
                     "command_line": f"net user {ATTACK_BACKDOOR} /add /domain",
                     "hash": fake_hash("net.exe"),
                     "parent": {"pid": 4412, "name": "powershell.exe"},
                     "entity_id": str(uuid.uuid4())}
    ev["source"] = {"ip": ATTACKER_IP}
    step(tag(ev, "T1136.002", "Create Account: Domain Account",
             "Persistence", "Domain account created from command line", "high"),
         "Persistence", "T1136.002")

    t += timedelta(minutes=3)
    ev = base_event(DC, ATTACK_BACKDOOR, "authentication", "start",
                    "user_logon", t)
    ev["event"]["outcome"] = "success"
    ev["winlog"] = {"event_id": 4624, "logon": {"type": "Interactive"}}
    ev["source"] = {"ip": ATTACKER_IP}
    step(ev, "Defense Evasion", "T1078.003")

    # 6. LATERAL MOVEMENT -> the file server, same backdoor account.
    t += timedelta(minutes=15)
    ev = base_event(FILESERVER, ATTACK_BACKDOOR, "authentication", "start",
                    "user_logon", t)
    ev["event"]["outcome"] = "success"
    ev["winlog"] = {"event_id": 4624, "logon": {"type": "Network"}}
    ev["source"] = {"ip": ATTACKER_IP}
    events.append(ev)

    # 7. EXFILTRATION -- bulk transfer out, well over the 10 MB/30 min bar.
    t += timedelta(minutes=11)
    for i in range(14):
        e = base_event(FILESERVER, ATTACK_BACKDOOR, "network", "connection",
                       "network_connection", t + timedelta(seconds=i * 40))
        e["process"] = {"pid": 7781, "name": "curl"}
        e["source"] = {"ip": FILESERVER["ip"], "port": 52000 + i}
        e["destination"] = {"ip": EXFIL_IP, "port": 443,
                            "domain": "sim-exfil.example"}
        e["network"] = {"transport": "tcp", "direction": "outbound",
                        "bytes": 4_200_000}
        events.append(e)
    truth.append({"step": len(truth) + 1, "stage": "Exfiltration",
                  "technique": "T1041",
                  "timestamp": iso(t + timedelta(seconds=13 * 40)),
                  "host": FILESERVER["name"], "user": ATTACK_BACKDOOR})

    # 8. IMPACT -- ransomware on the file server.
    t += timedelta(minutes=25)
    ev = base_event(FILESERVER, ATTACK_BACKDOOR, "file", "change",
                    "file_rename", t)
    ev["file"] = {"path": r"C:\Shares\Finance\<many>.locked",
                  "extension": "locked"}
    ev["labels_extra"] = {"files_renamed_60s": 3800}
    ev["process"] = {"pid": 9120, "name": "unknown.exe"}
    step(tag(ev, "T1486", "Data Encrypted for Impact", "Impact",
             "Rapid mass file rename to uniform extension", "critical"),
         "Impact", "T1486")

    return events, truth


def business_hours_weight(dt):
    """
    Weight a moment by how busy a workday would be.

    Flat random timestamps would be unrealistic in a way that matters: real
    telemetry is bursty, concentrated in office hours, and that rhythm is what
    makes time-windowed rules meaningful. Weekends and nights stay quiet.
    """
    if dt.weekday() >= 5:
        return 0.15
    h = dt.hour
    if 9 <= h <= 18:
        return 1.0
    if 7 <= h <= 21:
        return 0.4
    return 0.08


def main():
    ap = argparse.ArgumentParser(
        description="Spread EDR timestamps over time and plant a correlated attack.")
    ap.add_argument("--input", required=True, help="Raw NDJSON from edr_log_generator.py")
    ap.add_argument("--output", default="data/edr_ready.json")
    ap.add_argument("--days", type=float, default=7.0,
                    help="Period to spread events across (default 7)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--no-attack", action="store_true",
                    help="Only re-time events; plant no attack")
    args = ap.parse_args()

    random.seed(args.seed)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    start = datetime(2026, 10, 19, 0, 0, 0, tzinfo=timezone.utc)
    span = timedelta(days=args.days)

    # Build a weighted set of offsets, then sort, so the stream stays
    # chronological while following a realistic daily rhythm.
    print(f"Reading {args.input} ...")
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        total = sum(1 for line in f if line.strip())
    print(f"  {total:,} events")

    print(f"Spreading across {args.days} days with business-hour weighting ...")
    offsets = []
    total_seconds = span.total_seconds()
    while len(offsets) < total:
        cand = random.random() * total_seconds
        if random.random() <= business_hours_weight(
                start + timedelta(seconds=cand)):
            offsets.append(cand)
    offsets.sort()

    attack_events = []
    truth = []
    if not args.no_attack:
        # Place the attack mid-period, so it is buried rather than at an edge.
        attack_start = start + span * 0.55
        attack_events, truth = build_attack(attack_start)
        print(f"Planting INC-01: {len(attack_events)} events, "
              f"{len(truth)} ground-truth steps")

    # Merge: re-timed background plus the planted attack, in time order.
    print(f"Writing {args.output} ...")
    written = 0
    attack_sorted = sorted(attack_events, key=lambda e: e["@timestamp"])
    ai = 0
    with open(args.input, "r", encoding="utf-8", errors="replace") as fin, \
            open(args.output, "w", encoding="utf-8") as fout:
        idx = 0
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = start + timedelta(seconds=offsets[idx])
            idx += 1
            rec["@timestamp"] = iso(ts)
            stamp = rec["@timestamp"]
            # Emit any planted events that belong before this one.
            while ai < len(attack_sorted) and attack_sorted[ai]["@timestamp"] <= stamp:
                fout.write(json.dumps(attack_sorted[ai]) + "\n")
                ai += 1
                written += 1
            fout.write(json.dumps(rec) + "\n")
            written += 1
        while ai < len(attack_sorted):
            fout.write(json.dumps(attack_sorted[ai]) + "\n")
            ai += 1
            written += 1

    size_mb = os.path.getsize(args.output) / 1e6
    print(f"  wrote {written:,} events  ({size_mb:.1f} MB)")

    if truth:
        # ground_truth_EDR.json, not ground_truth.json.
        #
        # This script and scripts/generate_sample.py both used to write
        # `ground_truth.json`, so running one silently destroyed the other's
        # answer key. The symptom was alarming and completely misleading:
        # evaluate.py reported 0% detection with 100% false alarms, as though
        # the detector had broken, when in fact it was grading the EDR database
        # against the flat sample's planted attack. Separate filenames make
        # that collision impossible.
        tp = os.path.join(os.path.dirname(args.output) or ".",
                          "ground_truth_edr.json")
        with open(tp, "w", encoding="utf-8") as f:
            json.dump({"incident": "INC-01",
                       "description": "Phishing -> C2 -> persistence -> brute "
                                      "force -> lateral movement -> exfiltration "
                                      "-> ransomware",
                       "steps": truth}, f, indent=2)
        print(f"  wrote {tp}  ({len(truth)} steps)")


if __name__ == "__main__":
    main()
