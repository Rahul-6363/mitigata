"""
validate_independent.py -- Accuracy that is not circular (ChronoPath).

WHY THIS FILE EXISTS -- READ THIS BEFORE QUOTING ANY ACCURACY NUMBER
--------------------------------------------------------------------
`scripts/evaluate.py` reports 100% detection and 100% correct ATT&CK labels on
the organisers' file. That number is real but it is **nearly circular**, and
anyone quoting it without saying so is overclaiming.

Here is the circularity, stated plainly:

  1. The organisers supplied `firex-10G.log` with NO answer key.
  2. We derived one ourselves (`scripts/discover_firex.py`) by finding the
     rarest security-relevant events -- 14 events out of 9,125,382.
  3. We then wrote rules to detect those events.
  4. `evaluate.py` measures whether those rules find those events.

Step 4 therefore measures "do the rules we wrote find the things we wrote them
for". The answer is yes, and it is worth almost nothing as evidence of real
detection ability. Six of our twelve FortiGate rules map 1:1 onto the eight
ground-truth steps.

WHAT THIS SCRIPT MEASURES INSTEAD
---------------------------------
Four things that cannot be gamed by having written the rules:

  A. HOLD-OUT DETECTION. Score only against techniques NO rule was written
     for. If detection generalises at all, independent signal should appear.
     If it is purely memorised, this is zero -- and that is worth knowing.

  B. SIGNATURE COVERAGE. Of every distinct threat signature the firewall
     itself reports, what share do we label with an ATT&CK technique, and what
     share do we honestly mark UNMAPPED? This is measured against the DATA's
     own vocabulary, not against our answer key.

  C. PRECISION ON A LABELLED SUBSET. Where the firewall states its own verdict
     (`action=blocked`, `severity=critical`, a named CVE signature), we can
     check our label against the vendor's -- an external opinion we did not
     author.

  D. INPUT ACCOUNTING. Every byte of the input is either parsed, or explained.
     Silently skipping part of a file and then reporting 100% accuracy on the
     rest is the most dangerous failure mode available to a log tool.

WHAT IT CANNOT MEASURE, AND WHY NO SCRIPT COULD
-----------------------------------------------
True false-negative rate on real-world attacks. That needs labelled real
intrusion data from an organisation's actual estate. We do not have any, and
no amount of code substitutes for it. Treating this synthetic file as a proxy
for real-world accuracy would be the same error as step 4 above, one level up.

So this script reports what is measurable and names what is not. That is the
difference between an accuracy claim and a sales figure.

Run:  python scripts/validate_independent.py
"""

import argparse
import collections
import json
import math
import mmap
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import duckdb  # noqa: E402

# Techniques our FortiGate rules were explicitly written to catch, taken from
# the ground truth we authored. Anything detected OUTSIDE this set is
# independent evidence; anything inside it is, at least partly, memorisation.
#
# Listed by hand rather than parsed from the rules, because the point is to be
# conservative: if in doubt, call it memorised.
GROUND_TRUTH_TECHNIQUES = {
    "T1562", "T1562.004",   # logging disabled, policy purge
    "T1078",                # admin login from internet
    "T1133",                # VPN from two countries
    "T1136",                # admin account created
    "T1070",                # admin account deleted
}

# Signature fragments that name a REAL, published vulnerability, malware
# family or offensive tool. Verified by recognition, not by pattern -- each one
# below corresponds to something with a CVE, a MITRE software entry or an
# industry name. This list is the external opinion we check ourselves against.
REAL_THREAT_SIGNATURES = {
    # --- Remote code execution / exploitation of public-facing apps ---
    "Log4j": ("T1190", "CVE-2021-44228, Apache Log4Shell"),
    "SSLVPN.Path.Traversal": ("T1190", "CVE-2018-13379, FortiOS SSL-VPN"),
    "Citrix.ADC": ("T1190", "CVE-2019-19781, Citrix ADC"),
    "Confluence.OGNL": ("T1190", "CVE-2022-26134, Atlassian Confluence"),
    "HTTP.sys": ("T1190", "CVE-2015-1635 / CVE-2021-31166, Windows HTTP.sys"),
    "WebLogic": ("T1190", "CVE-2019-2725, Oracle WebLogic deserialisation"),
    "vCenter": ("T1190", "CVE-2021-22005, VMware vCenter file upload"),
    "PHP.CGI": ("T1190", "CVE-2012-1823, PHP-CGI argument injection"),
    "Buffer.Overflow": ("T1190", "memory-corruption exploit over HTTP"),
    "SQL.Injection": ("T1190", "generic SQL injection"),
    "Password.Files.Access": ("T1190", "web server password file access"),
    "Path.Traversal": ("T1190", "directory traversal"),
    "Command.Injection": ("T1190", "OS command injection over HTTP"),
    "URI.XSS": ("T1190", "cross-site scripting via URI"),

    # --- Lateral movement / remote service exploitation ---
    "ZeroLogon": ("T1210", "CVE-2020-1472, Netlogon privilege escalation"),
    "SMB.Server.Trans": ("T1210", "SMB transaction information disclosure"),

    # --- Local privilege escalation ---
    "Netfilter.Privilege.Escalation": (
        "T1068", "CVE-2021-22555, Linux netfilter heap overflow"),
    "Privilege.Escalation": ("T1068", "exploitation for privilege escalation"),

    # --- Command and control ---
    "Cobalt.Strike": ("T1071", "Cobalt Strike, MITRE software S0154"),
    "Beacon": ("T1071", "C2 beaconing"),
    "Mirai": ("T1071", "Mirai botnet, MITRE software S0587"),
    "Botnet": ("T1071", "botnet C2"),

    # --- Credential access ---
    "SSH.Connection.Brute.Force": ("T1110", "SSH credential brute force"),
    "RDP.Connection.Brute.Force": ("T1110", "RDP credential brute force"),

    # --- Reconnaissance ---
    "DNS.Zone.Transfer": ("T1590.002", "DNS zone transfer reconnaissance"),

    # --- Test file, deliberately excluded from the malware rule ---
    "Eicar": ("T1105", "EICAR antivirus test file, harmless by design"),
}

# FortiGate antivirus verdicts end in `!tr` (trojan) or carry a family prefix
# such as `JS/Nemucod`. These are malicious content intercepted at the
# perimeter, which is delivery -- see the long note on the AV rule in
# rules_fortigate.yaml for why this is T1566 and not T1105.
AV_VERDICT_RE = re.compile(r"!tr|^[A-Z]{1,3}\d*/|\.dldr$", re.IGNORECASE)
AV_EXPECTED_TECHNIQUE = "T1566"

# Vendor-product strings that name no threat. These are the signatures we
# deliberately report as UNMAPPED, and this script checks that choice was
# right rather than assuming it.
SYNTHETIC_MARKERS = (
    "splunk.security", "solarwinds.security", "citrix.security",
    "apache.security", "netscout.security", "nordlayer", "kaseya",
    "extreme.firewall", "extreme.security", "checkpoint.security",
    "hewlettpackard", "vmware.security", "paloalto.security",
    "zerotrust.security", "f5.security", "mikrotik.security",
    "fortinet.protection",
)


# ---------------------------------------------------------------------------
# D. Input accounting -- is every byte of the file explained?
# ---------------------------------------------------------------------------

def account_for_input(log_path, sample_bytes=4_000_000):
    """
    Confirm that every byte of the input is either parsed or explained.

    WHY THIS IS FIRST: it is the check that can invalidate every other number.
    A tool that reads 40% of a file and reports 100% accuracy on what it read
    is not 100% accurate -- it is 100% accurate on an unstated subset, which is
    a different and much weaker claim.

    Measured on the organisers' file, this found that 1.61 GB (26% of the
    bytes) is not syslog at all. The entropy test below is what distinguishes
    "we are missing data" from "that region contains no data": at ~8.0
    bits/byte and incompressible, a region carries no parseable records.
    """
    size = os.path.getsize(log_path)
    with open(log_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            last_record = mm.rfind(b"\ndate=")
            if last_record < 0:
                return {"size_bytes": size, "text_bytes": size,
                        "trailing_bytes": 0, "verdict": "no syslog found"}
            text_end = mm.find(b"\n", last_record + 1)
            if text_end < 0:
                text_end = len(mm)
            trailing = len(mm) - text_end - 1

            result = {
                "size_bytes": size,
                "text_bytes": text_end + 1,
                "trailing_bytes": trailing,
                "trailing_share_pct": trailing / size * 100 if size else 0,
            }

            if trailing <= 0:
                result["verdict"] = "fully accounted for: all bytes are syslog"
                return result

            # Characterise the trailing region rather than guessing at it.
            region_start = text_end + 1
            sample = mm[region_start:region_start + min(sample_bytes, trailing)]
            counts = collections.Counter(sample)
            entropy = -sum((n / len(sample)) * math.log2(n / len(sample))
                           for n in counts.values()) if sample else 0.0

            import zlib
            ratio = (len(zlib.compress(bytes(sample[:2_000_000]), 6))
                     / min(len(sample), 2_000_000)) if sample else 0.0

            # Would any records hide in there?
            record_markers = sum(mm[region_start:].count(m) for m in
                                 (b"devname=", b"logdesc=", b"srcip="))

            result.update({
                "entropy_bits_per_byte": round(entropy, 3),
                "zlib_ratio": round(ratio, 3),
                "distinct_bytes": len(counts),
                "record_markers_found": record_markers,
            })

            if entropy > 7.9 and ratio > 0.98 and record_markers <= 1:
                result["verdict"] = (
                    "EXPLAINED: random padding. Entropy ~8.0 bits/byte and "
                    "incompressible, with no record markers -- this region "
                    "cannot contain log records. No events are missing.")
                result["data_loss"] = False
            else:
                result["verdict"] = (
                    "UNEXPLAINED: this region may contain readable data the "
                    "pipeline is not reading. Investigate before quoting any "
                    "accuracy figure.")
                result["data_loss"] = True
            return result
        finally:
            mm.close()


# ---------------------------------------------------------------------------
# B. Signature coverage -- measured against the data's own vocabulary
# ---------------------------------------------------------------------------

def signature_inventory(log_path, limit_lines=None):
    """
    Count every distinct threat signature the firewall itself reports.

    This is the honest denominator for a coverage claim: it comes from the
    data, not from our rules. If we label 20 of 69 signatures, the coverage is
    29% -- regardless of how well we do on the 8 events we chose to call the
    attack.
    """
    attack = collections.Counter()
    virus = collections.Counter()
    category = collections.Counter()
    rx_attack = re.compile(rb'attack="([^"]*)"')
    rx_virus = re.compile(rb'virus="([^"]*)"')
    rx_cat = re.compile(rb'catdesc="([^"]*)"')

    # Read as bytes: the trailing binary region would raise on strict decode,
    # and errors="replace" on 6 GB costs real time for no benefit here.
    with open(log_path, "rb") as f:
        for n, line in enumerate(f):
            if limit_lines and n >= limit_lines:
                break
            if not line.startswith(b"date="):
                continue
            m = rx_attack.search(line)
            if m:
                attack[m.group(1).decode("utf-8", "replace")] += 1
            m = rx_virus.search(line)
            if m:
                virus[m.group(1).decode("utf-8", "replace")] += 1
            m = rx_cat.search(line)
            if m:
                category[m.group(1).decode("utf-8", "replace")] += 1
    return {"attack": attack, "virus": virus, "category": category}


def classify_signature(name):
    """
    Decide whether a signature names a real threat or is a vendor-product string.

    Returns ("real", technique, note) or ("synthetic", None, reason).

    WHY THIS MATTERS FOR ACCURACY: our rules mark 45 signatures UNMAPPED. That
    looks like a 65% coverage failure until you read the names -- they are
    strings like `Splunk.security.VM` and `Kaseya-network-scurological-scan`,
    which name a vendor and a product and no attack technique. Mapping those to
    T1190 would raise our apparent coverage to 100% and make the output a lie.
    So "UNMAPPED" is the correct answer, and this function is how we show that
    rather than assert it.
    """
    low = name.lower()
    for fragment, (technique, note) in REAL_THREAT_SIGNATURES.items():
        if fragment.lower() in low:
            return "real", technique, note
    for marker in SYNTHETIC_MARKERS:
        if marker in low:
            return "synthetic", None, f"vendor-product string ({marker})"
    # An antivirus verdict names real malicious content even when the family
    # name itself is synthetic -- the verdict IS the vendor's opinion, which is
    # what makes it checkable.
    if AV_VERDICT_RE.search(name):
        return ("real", AV_EXPECTED_TECHNIQUE,
                "antivirus verdict: malicious content at the perimeter")
    # Application-control reports the firewall's own policy label, not a
    # threat. UNMAPPED is the correct answer for these.
    if low in ("app-ctrl", "webfilter", "dns", "ips", "virus"):
        return "synthetic", None, "firewall subsystem name, not a threat"
    # OUR OWN OUTPUT, not a vendor signature. Aggregate rules summarise a burst
    # ("Matching events: 4752") and the firewall's own event descriptions
    # ("Admin login successful") carry no signature name. There is no external
    # opinion to check these against, so they are excluded from the precision
    # denominator rather than counted as failures -- scoring ourselves against
    # our own text would be the circularity this whole script exists to avoid.
    if low.startswith(("matching events:", "distinct source ips:")) or low in (
            "admin login successful", "admin login failed",
            "attribute configured", "object attribute configured",
            "ssl vpn tunnel up"):
        return "self", None, "our own aggregate output or a bare event description"
    return "unknown", None, "neither a recognised threat nor a known vendor string"


# ---------------------------------------------------------------------------
# A + C. Hold-out detection and precision against the vendor's own verdict
# ---------------------------------------------------------------------------

def holdout_detection(con):
    """
    Score detection on techniques NO rule was written for.

    Everything in GROUND_TRUTH_TECHNIQUES is excluded, because we wrote those
    rules from those events. What remains is signal the pipeline found without
    being told what to look for -- the only part of the detection result that
    is evidence of generalisation rather than memorisation.
    """
    rows = con.execute("""
        SELECT mitre_technique, mitre_name, COUNT(*) AS n,
               COUNT(DISTINCT rule_name) AS rules,
               MAX(severity) AS worst
        FROM suspicious_events
        GROUP BY 1, 2
    """).fetchall()

    memorised, independent = [], []
    for technique, name, n, rules, worst in rows:
        bucket = (memorised if technique in GROUND_TRUTH_TECHNIQUES
                  else independent)
        bucket.append({"technique": technique, "name": name, "detections": n,
                       "rules": rules, "worst_severity": worst})
    memorised.sort(key=lambda r: -r["detections"])
    independent.sort(key=lambda r: -r["detections"])
    return memorised, independent


def precision_vs_vendor(con):
    """
    Check our ATT&CK label against the firewall vendor's own signature name.

    This is the one external opinion available in the data. FortiGate's
    signature names were written by Fortinet, not by us, so a signature that
    says `Apache.Log4j...Remote.Code.Execution` is independent evidence that
    T1190 (Exploit Public-Facing Application) is the right label.

    Three outcomes per detection:
        agree       our technique matches what the signature describes
        disagree    it does not -- a genuine mislabel, worth fixing
        unlabelled  we said UNMAPPED. Correct when the signature names no
                    threat; a miss when it names a real one.
    """
    rows = con.execute("""
        SELECT message, mitre_technique, COUNT(*) AS n
        FROM suspicious_events
        WHERE message <> '' AND message IS NOT NULL
        GROUP BY 1, 2
    """).fetchall()

    agree = disagree = unmapped_ok = unmapped_miss = unknown = 0
    self_labelled = 0
    disagreements, missed = [], []

    for message, technique, n in rows:
        kind, expected, note = classify_signature(message)
        if kind == "self":
            # No external opinion exists for these -- see classify_signature.
            self_labelled += n
            continue
        if kind == "synthetic":
            if technique == "UNMAPPED":
                unmapped_ok += n
            else:
                # We put a confident label on a string that names no threat.
                disagree += n
                disagreements.append((message, technique, "names no threat", n))
            continue
        if kind == "unknown":
            unknown += n
            continue
        # A real threat signature: does our label match?
        if technique == "UNMAPPED":
            unmapped_miss += n
            missed.append((message, expected, note, n))
        elif technique == expected or technique.startswith(expected + "."):
            agree += n
        else:
            disagree += n
            disagreements.append((message, technique, f"expected {expected}", n))

    scored = agree + disagree + unmapped_miss
    return {
        "agree": agree, "disagree": disagree,
        "unmapped_correctly": unmapped_ok, "unmapped_missed": unmapped_miss,
        "unclassifiable": unknown,
        "not_externally_checkable": self_labelled,
        "precision_pct": (agree / scored * 100) if scored else None,
        "disagreements": sorted(disagreements, key=lambda d: -d[3])[:10],
        "missed": sorted(missed, key=lambda d: -d[3])[:10],
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Measure accuracy independently of our own answer key.")
    ap.add_argument("--db", default="firex.db")
    ap.add_argument("--input", default="D:/firex-10G.log")
    ap.add_argument("--truth", default="data/ground_truth_firex.json")
    ap.add_argument("--skip-scan", action="store_true",
                    help="Skip the signature inventory (needs a full file read)")
    ap.add_argument("--limit-lines", type=int, default=None)
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    print("\n" + "=" * 72)
    print("  ChronoPath -- INDEPENDENT accuracy validation")
    print("=" * 72)
    print("  The 100% figure from evaluate.py is measured against ground truth")
    print("  WE derived and then wrote rules for. This script measures what")
    print("  cannot be gamed that way, and names what it cannot measure.")

    # ---- D. Input accounting (first: it can invalidate everything else) ----
    print("\n" + "-" * 72)
    print("  D. INPUT ACCOUNTING -- is every byte explained?")
    print("-" * 72)
    if os.path.exists(args.input):
        acct = account_for_input(args.input)
        gb = 1024 ** 3
        print(f"  file size              {acct['size_bytes'] / gb:.2f} GB")
        print(f"  syslog region          {acct['text_bytes'] / gb:.2f} GB")
        print(f"  trailing region        {acct['trailing_bytes'] / gb:.2f} GB"
              f"  ({acct.get('trailing_share_pct', 0):.0f}% of the file)")
        if acct["trailing_bytes"] > 0:
            print(f"  entropy                "
                  f"{acct.get('entropy_bits_per_byte')} bits/byte "
                  f"(8.0 = random)")
            print(f"  zlib ratio             {acct.get('zlib_ratio')} "
                  f"(1.0 = incompressible)")
            print(f"  log record markers     "
                  f"{acct.get('record_markers_found')}")
        print(f"\n  VERDICT: {acct['verdict']}")
    else:
        acct = None
        print(f"  input not found: {args.input} -- skipped")

    con = duckdb.connect(args.db, read_only=True)
    try:
        # ---- A. Hold-out detection ----
        print("\n" + "-" * 72)
        print("  A. HOLD-OUT DETECTION -- techniques no rule was written for")
        print("-" * 72)
        memorised, independent = holdout_detection(con)
        mem_n = sum(r["detections"] for r in memorised)
        ind_n = sum(r["detections"] for r in independent)

        print(f"  Techniques we wrote rules FROM the answer key "
              f"({len(memorised)}):")
        for r in memorised:
            print(f"      {r['detections']:>9,}  {r['technique']:<12} "
                  f"{r['name'][:40]}")
        print(f"      {'-' * 9}")
        print(f"      {mem_n:>9,}  total  <- circular, proves little")

        print(f"\n  Techniques found INDEPENDENTLY ({len(independent)}):")
        for r in independent:
            print(f"      {r['detections']:>9,}  {r['technique']:<12} "
                  f"{r['name'][:40]}")
        print(f"      {'-' * 9}")
        print(f"      {ind_n:>9,}  total  <- real evidence of detection")

        share = ind_n / (ind_n + mem_n) * 100 if (ind_n + mem_n) else 0
        print(f"\n  {share:.1f}% of all detections come from techniques outside "
              f"our answer key.")
        print(f"  {len(independent)} of {len(independent) + len(memorised)} "
              f"distinct techniques are independent of it.")

        # ---- C. Precision against the vendor's own labels ----
        print("\n" + "-" * 72)
        print("  C. PRECISION vs the FIREWALL VENDOR'S OWN SIGNATURE NAMES")
        print("-" * 72)
        print("  Fortinet named these signatures, not us. A signature reading")
        print("  'Apache.Log4j...Remote.Code.Execution' is independent evidence")
        print("  that T1190 is the right label.")
        prec = precision_vs_vendor(con)
        print(f"\n      agree with the signature        "
              f"{prec['agree']:>9,}")
        print(f"      disagree (genuine mislabel)     "
              f"{prec['disagree']:>9,}")
        print(f"      UNMAPPED, correctly             "
              f"{prec['unmapped_correctly']:>9,}   "
              f"(signature names no threat)")
        print(f"      UNMAPPED, a real miss           "
              f"{prec['unmapped_missed']:>9,}   "
              f"(signature names a real threat)")
        print(f"      unclassifiable                  "
              f"{prec['unclassifiable']:>9,}")
        print(f"      no external opinion exists      "
              f"{prec['not_externally_checkable']:>9,}   "
              f"(our own aggregate output)")
        if prec["precision_pct"] is not None:
            print(f"\n  LABEL PRECISION on signatures we can check "
                  f"independently: {prec['precision_pct']:.1f}%")
        if prec["disagreements"]:
            print("\n  Disagreements worth fixing:")
            for sig, got, why, n in prec["disagreements"]:
                print(f"      {n:>7,}  {sig[:44]:<44} we said {got} ({why})")
        if prec["missed"]:
            print("\n  Real threats we left UNMAPPED:")
            for sig, expected, note, n in prec["missed"]:
                print(f"      {n:>7,}  {sig[:40]:<40} -> {expected}  ({note})")

        # ---- B. Signature coverage ----
        if not args.skip_scan and os.path.exists(args.input):
            print("\n" + "-" * 72)
            print("  B. SIGNATURE COVERAGE -- against the data's own vocabulary")
            print("-" * 72)
            print("  Scanning for every distinct signature the firewall "
                  "reports...", flush=True)
            inv = signature_inventory(args.input, args.limit_lines)
            labelled = {r[0] for r in con.execute(
                "SELECT DISTINCT message FROM suspicious_events "
                "WHERE mitre_technique <> 'UNMAPPED'").fetchall()}

            for field in ("attack", "virus", "category"):
                counter = inv[field]
                if not counter:
                    continue
                real = synth = unk = 0
                for name in counter:
                    kind, _, _ = classify_signature(name)
                    real += kind == "real"
                    synth += kind == "synthetic"
                    unk += kind == "unknown"
                covered = sum(1 for name in counter if name in labelled)
                print(f"\n    {field}: {len(counter)} distinct signatures, "
                      f"{sum(counter.values()):,} events")
                print(f"        name a real threat        {real:>4}")
                print(f"        vendor-product strings    {synth:>4}  "
                      f"(UNMAPPED is correct for these)")
                print(f"        unclassifiable            {unk:>4}")
                print(f"        we give an ATT&CK label   {covered:>4}"
                      f"  = {covered / len(counter) * 100:.0f}% of signatures")
                if real:
                    print(f"        coverage of REAL threats  "
                          f"{covered}/{real} = "
                          f"{min(covered, real) / real * 100:.0f}%")
        else:
            print("\n  B. SIGNATURE COVERAGE -- skipped (--skip-scan)")

        # ---- The honest summary ----
        print("\n" + "=" * 72)
        print("  WHAT THESE NUMBERS DO AND DO NOT SHOW")
        print("=" * 72)
        print("  CAN be claimed:")
        print(f"    - {share:.0f}% of detections come from techniques outside "
              f"our own answer key.")
        if prec["precision_pct"] is not None:
            print(f"    - {prec['precision_pct']:.0f}% label precision against "
                  f"the vendor's signature names,")
            print(f"      which we did not author.")
        if acct and acct.get("trailing_bytes", 0) > 0:
            loss = acct.get("data_loss")
            print(f"    - every byte of the input is accounted for "
                  f"({'NOT ' if loss else ''}explained).")
        print("\n  CANNOT be claimed, and no script here could show it:")
        print("    - a true false-negative rate. That needs labelled real")
        print("      intrusion data from a production estate. We have none.")
        print("    - that 100% from evaluate.py generalises. It is measured")
        print("      against ground truth we derived and then wrote rules for.")
        print("    - performance against an attacker who knows these rules.")
        print()
    finally:
        con.close()


if __name__ == "__main__":
    main()
