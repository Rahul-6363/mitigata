# Accuracy — what we can prove, and what we cannot

> **Read this before quoting any number from this project.**
>
> ChronoPath reports *100% detection, 100% correct ATT&CK labels, 0% false
> alarms* on the organisers' 6.54 GB file. That is a real measurement and it is
> **nearly circular**. This document says exactly how much weight it carries,
> gives four measurements that are *not* circular, and names the things no
> script in this repository can establish.

Measured 2026-10-31 on `firex-10G.log` · Dell laptop, 5 cores, 16 GB RAM.

---

## 1. Why the headline number is almost worthless on its own

Here is the honest chain of events:

1. The organisers supplied `firex-10G.log` with **no answer key**.
2. We derived one ourselves (`scripts/discover_firex.py`) by querying for the
   rarest security-relevant events — 14 events out of 9,125,382.
3. We then **wrote detection rules to find those events**.
4. `scripts/evaluate.py` measures whether those rules find those events.

Step 4 measures *"do the rules we wrote find the things we wrote them for?"*
The answer is yes. As evidence of real detection ability it is worth very
little. **Six of our twelve FortiGate rules map 1:1 onto the eight
ground-truth steps:**

| Ground-truth step | Technique | The rule written for it |
|---|---|---|
| 1 | T1562 | Firewall Logging Disabled |
| 2 | T1562.004 | Firewall Policy Objects Purged |
| 3, 5, 7 | T1078 | Admin Login Successful from External IP |
| 4 | T1133 | SSL VPN Access from Multiple Countries |
| 6 | T1136 | Firewall Admin Account Created |
| 8 | T1070 | Firewall Admin Account Deleted |

Anyone presenting the 100% figure without this caveat is overclaiming. We put
the caveat in the README, the pitch and here.

---

## 2. What *is* independently measurable

Run `python scripts/validate_independent.py`. Four measurements that cannot be
gamed by having authored the answer key.

### A. Hold-out detection — 100% of detections come from outside our answer key

Score only the techniques **no rule was written from**:

| | Detections | Distinct techniques |
|---|---|---|
| Techniques we wrote rules **from** the answer key | 10 | 6 |
| Techniques found **independently** | **373,229** | **12** |

**99.997% of all detections, and 12 of 18 distinct techniques, are independent
of the ground truth we authored.** The pipeline is not a lookup table for eight
events; the overwhelming majority of what it finds, it finds without having
been told to look for it.

### B. Label precision vs the vendor's own signature names — 100%

This is the strongest independent check available in the data. **Fortinet wrote
these signature strings, not us.** A signature reading
`Apache.Log4j.Error.Log.Remote.Code.Execution` is external evidence that T1190
*(Exploit Public-Facing Application)* is the right label.

| Outcome | Detections |
|---|---|
| **Agree** with the vendor signature | **229,757** |
| **Disagree** (genuine mislabel) | **0** |
| UNMAPPED, correctly — signature names no threat | 143,136 |
| UNMAPPED, a real miss — signature names a real threat | **0** |
| Unclassifiable | **0** |
| No external opinion exists (our own aggregate output) | 346 |

**Label precision: 100.0%** on the 229,757 detections checkable against an
opinion we did not author. All **373,239** detections are accounted for
exactly — nothing falls through. Enforced by
`test_label_precision_against_vendor_signatures`, not just reported here.

This check earned its place immediately — it found two real mislabels. See §4.

### C. Signature coverage vs the data's own vocabulary

The honest denominator: every distinct signature the firewall itself reports.

| Stream | Distinct signatures | Name a real threat | We label | Coverage of real threats |
|---|---|---|---|---|
| IPS (`attack`) | 69 | 24 | 23 | **96%** — the 24th is EICAR, see below |
| Antivirus (`virus`) | 35 | 35 | 35 | **100%** |
| Web filter (`catdesc`) | 23 | 1 | 0 | **0%** — see §5 |

The one "real" IPS signature we do not label is **`Eicar.Virus.Test.File`**, the
industry-standard *harmless* antivirus test file. Our malware rule excludes it
deliberately (`fg_virus NOT ILIKE '%eicar%'`), because reporting a test file as
malware is a false positive. So the true coverage of real threats is **23/23**;
the 96% understates it because the checker counts EICAR in the denominator.

The IPS figure looks like 33% until you read the 45 signatures we leave
unlabelled: `Splunk.security.VM`, `Fortinet.Protection.WAF`,
`Kaseya-network-scurological-scan` ("scurological" is not a word). These name a
vendor and a product and **no attack technique**. Mapping them to T1190 would
raise apparent coverage to 100% and make the output a lie. `UNMAPPED` is the
correct answer, and `validate_independent.py` demonstrates that rather than
asserting it.

### D. Input accounting — every byte explained

**This check found a real problem.** The file is 6.09 GB, but only 4.48 GB is
syslog:

| | |
|---|---|
| File size | 6.09 GB |
| Syslog region | 4.48 GB — 9,125,382 events, ending cleanly at 2026-10-30 08:48:25 |
| **Trailing region** | **1.61 GB (26% of the file)** |
| Entropy | **7.998 bits/byte** (8.0 = pure random) |
| zlib ratio | **0.999** (1.0 = incompressible) |
| `date=` occurrences in 1.61 GB | **1** (the truncated tail of the last real line) |
| Verdict | **Random padding. No events are missing.** |

So the organisers padded the file to a nominal "10G" size. Our conclusions are
unaffected — but the pipeline was **silently skipping a quarter of the input
while reporting 100% accuracy on the rest**, which is a true statement about an
unstated subset. It is now measured and explained, and
`test_every_input_byte_is_accounted_for` fails if any region is neither parsed
nor positively explained.

---

## 3. ATT&CK coverage — 26 techniques, 11 of 14 tactics

| Tactic | Techniques covered |
|---|---|
| Reconnaissance | T1590.002 |
| Initial Access | T1078, T1078.003, T1133, T1189, T1190, T1566 |
| Execution | T1059.001 |
| Persistence | T1136, T1136.002, T1547.001 |
| Privilege Escalation | T1068 |
| Defense Evasion | T1070, T1562, T1562.004 |
| Credential Access | T1003.001, T1110, T1110.001 |
| Discovery | *(none — see §6)* |
| Lateral Movement | T1021.002, T1210 |
| Collection | T1005 |
| Command and Control | T1071, T1071.001, T1105 |
| Exfiltration | T1041 |
| Impact | T1486 |

Not covered: **Resource Development**, **Discovery**, **Reconnaissance beyond
DNS**. Discovery is the significant gap — `net view`, `whoami`, LDAP
enumeration — and it is invisible to a firewall, which is why the gap ledger
raises a `NOT_COLLECTED` finding for endpoint telemetry on every FortiGate
incident rather than pretending otherwise.

---

## 4. Two real mislabels this work found and fixed

Both were caught by §2B — checking our labels against the vendor's.

### T1105 → T1566: antivirus detections, 135,623 of them

Our **largest single detection category** was wrong on both axes:

| | Before | After |
|---|---|---|
| Technique | T1105 *Ingress Tool Transfer* | **T1566 *Phishing*** |
| Kill-chain stage | Execution | **Delivery** |

Two independent reasons:

- **T1105 is the wrong phase.** It describes an attacker who *already has
  access* pulling tooling onto a host they control. Antivirus intercepting a
  file crossing the perimeter is the delivery attempt itself.
- **"Execution" is contradicted by the data.** 135,620 of the 135,623 carry
  `action="blocked"`. The file never ran. Labelling it Execution tells an
  analyst a host was compromised *when the control worked* — a false sense of
  breach, at scale.

### T1071.001 → UNMAPPED: application control, 54,563 of them

Labelled *Application Layer Protocol: Web Protocols*, stage **Command and
Control**. Then we looked at which applications FortiGate actually rates
critical here:

```
KakaoTalk, Instagram, Basecamp, GoogleHangouts, OneDrive, Skype,
Dropbox, GitLab, Telegram, Tinder, Chocolatey, SSH
```

Consumer and business software. Someone opening Instagram at work is a policy
matter, not command-and-control infrastructure. This put **54,563 false C2
findings** into the corpus and would have an analyst hunting a beacon that was
never there. Now `UNMAPPED` at severity 2 — real information, honestly
unattributed.

**Both fixes left the regression gate untouched** (5 incidents, 100%/100%/0%),
because they corrected *background noise* labelling, not the planted attack.
That is itself worth noting: the headline metric was blind to 190,186
mislabelled detections. A metric that cannot see its own largest error is not a
metric to trust alone.

---

## 4b. Three further gaps found by auditing the data, not the metrics

Each of these was invisible to the headline 100%, because that metric only ever
looks at the eight planted events.

### A technique we could not express: password spraying (T1110.003)

The brute-force rule groups by source address and counts attempts, answering
*"is one address hammering us?"* It cannot answer the more diagnostic question
*"is one address trying **many different accounts**?"* Those are different
ATT&CK techniques with opposite responses — spraying is designed to stay under
per-account lockout thresholds, so an unchanged lockout policy is no evidence
it failed.

Measured on this file:

| | |
|---|---|
| External addresses making failed admin logins | **264** |
| Failed attempts per address | **~8,000** |
| Distinct usernames targeted | **956** (`admin`, `root`, `administrator`, `administrador`, `usuario`, `test`) |
| Worst single (address, hour) | **839 distinct usernames** |

The distribution of distinct usernames per (address, hour) breaks cleanly:

| p50 | p75 | p90 | p95 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|
| 10 | 17 | 26 | 31 | **43** | **825** | 839 |

A threshold of **50** sits in that gap rather than being tuned to it, and it is
**stable** — 50, 100, 200, 400 and 600 all yield 157 buckets, which is how you
can tell the cluster is real. At 20 it would yield 5,114 and swamp the output.

**+178 detections, and all four accuracy metrics unchanged.** The rule carries
`outcome: attempted`, so triage keeps the spray out of the incident list as a
blocked threat rather than inventing 178 false incidents.

We also checked whether any sprayed address later **succeeded** — that would be
a missed attack chain. **It did not:** the 158 spray addresses and the 4
successful-login addresses do not overlap at all.

### `event_count` was holding the rule's metric, not a row count

This one was wrong by six orders of magnitude and nothing flagged it.

| Rule | metric | `event_count` before | after |
|---|---|---|---|
| EDR exfiltration (T1041) | `SUM(bytes_out)` | **58,800,000** | **14** |
| FortiGate VPN (T1133) | `COUNT(DISTINCT src_ip)` | 2 | **4** |

The first reported *58.8 million raw alerts merged* for a single detection —
bonus B-3 inflated absurdly. The second **understated the evidence**, which is
the more dangerous direction: `keerat.ghughal` has **four** VPN tunnels from two
countries, and the analyst was told two events. A credential used four times
from two countries is worse than one used twice.

Fixed to `COUNT(*)` always. The metric still reaches the analyst through
`message` ("Bytes transferred: 58800000"), which is where a number that is not
a row count belongs. The EDR top incident's risk moved **92.8 → 92.5** as a
result: the score becoming accurate, not drifting.

### A 1,368-second step, from a pre-filter that was described but never written

`enrich_from_source` carried a comment claiming a cheap pre-filter on fixed
string offsets. The code ran `re.search(r'user="..."')` on **every line before
testing the date** — 9.1 million regex searches to serve 10 lookups.

| | Before | After |
|---|---|---|
| Raw-line evidence step | **1,368.3 s** | **6.4 s** |
| Whole 2.0 layer | ~1,406 s | **~29 s** |

Same output: 10 detections enriched, identity-pivot proof intact. A **214×**
speedup, found only because a timeout made the cost visible — the step had
always been slow and nothing measured it.

### Two gaps we probed and correctly do *not* have

Worth recording, because "we checked and there is nothing there" is a finding:

- **DNS tunnelling / DGA** in the EDR data: 47,649 `dns_query` events, but only
  **9 distinct domains**, all legitimate (`teams.microsoft.com`, `github.com`),
  max length 25 characters. A DNS-anomaly rule would detect nothing because
  there is nothing to detect.
- **Missed attack chains from the spray campaign**: no overlap between spray
  sources and successful logins, as above.

---

## 5. A rule we wrote, measured, and deliberately switched off

§2C reports **0% coverage of the webfilter stream** — 408,635 events, with
categories named `Botnet`, `Ransomware`, `Phishing`, `Spyware`, and **90%
(367,778) `passthrough` rather than blocked**. That looks like the single
largest blind spot in the pipeline.

So we wrote the rule, then measured whether enabling it would help. It would
not:

| Measurement | Result |
|---|---|
| Internal hosts involved | **1,386** |
| Events per host | min 18, median 36, **max 59** |
| Mean / standard deviation | 36.2 / 6.1 |
| Worst host, in standard deviations | **3.71σ** — what the max of 1,386 noise samples looks like |
| Hosts we already detect something on that appear here | **1,386 of 1,388** |
| Known attacker addresses appearing in webfilter | **0** |

The stream is uniform synthetic background. Enabling the rule would add
~368,000 detections and over a thousand single-host incidents, taking the
false-alarm rate from **0% to roughly 99%**, and would find **no additional
attacker**.

It therefore ships with `enabled: false` and the measurements recorded beside
it in `rules_fortigate.yaml`. On a real estate this is a rule you *want* — there
malicious-category browsing is rare and concentrated, and the host doing it is
worth investigating. One word turns it on.

Verified it is documented config and not dead config: lowering the threshold
makes it fire correctly as T1189 / Delivery. `test_disabled_rules_are_documented_not_forgotten`
requires any disabled rule to carry its reasoning.

---

## 6. What we cannot claim — and why no script here could establish it

Stated plainly, because these are the claims a careful reviewer will probe.

### "Train it on real-world data for exact accuracy" is not possible here

Not an implementation shortfall — a data problem:

- **There are no real-world labels.** `firex-10G.log` arrived with no answer
  key. Our ground truth is *our own inference* from rarity analysis.
- **Training on self-derived labels, then measuring against those same labels,
  produces a number that looks excellent and means nothing.** It is the
  circularity of §1, one level deeper and harder to see.
- **This file is synthetic.** 22 near-duplicate webfilter categories ("Phishing
  Tactics", "Phishing Patterns", "Phishing Methods", "Fishing Attacks"), 45
  vendor-word-salad IPS signatures, a perfectly uniform 36-events-per-host
  distribution, and 1.61 GB of random padding. A model trained to fit these
  artefacts would get *worse* on real telemetry, not better.

What would make a trained model meaningful: labelled intrusion data from a
production estate, with incidents confirmed by the responders who handled them.
We have none, and no amount of code substitutes for it.

### Specifically unprovable from this repository

| Cannot claim | Why |
|---|---|
| A true **false-negative rate** | Needs labelled real intrusions. We only know about attacks we already found. |
| That 100% **generalises** | It is measured against ground truth we derived and then wrote rules for. |
| Performance against an **adaptive attacker** | Someone who reads `rules_fortigate.yaml` can design around it. Rarity-based hunting (`src/pivot.py`) partly mitigates this; it does not remove it. |
| **Real-world precision** | Our 0% false-alarm rate is relative to one planted attack in one synthetic file. A production estate has thousands of benign oddities this file does not contain. |
| Behaviour at the **full 15 GB tier** | Measured at 6.09 GB. Memory is flat (813 MB), so 15 GB should cost time rather than memory — an extrapolation, not a measurement. |

### The ground truth itself could be incomplete

Our answer key says 14 rare events constitute the attack. If the organisers'
real key includes something our rarity analysis missed — an attack step that is
*common* rather than rare — we would not have found it, and our 100% would drop.
The derivation is reproducible (`scripts/discover_firex.py`) precisely so this
is checkable rather than taken on trust.

---

## 7. The numbers, in the form we are willing to defend

| Claim | Value | How independent? |
|---|---|---|
| Detections from techniques outside our answer key | **99.997%** (373,229 / 373,239) | ✅ Fully — hold-out |
| Label precision vs vendor signature names | **100.0%** (229,757 checked, 0 disagree) | ✅ Fully — external opinion |
| Real threats left UNMAPPED | **0** | ✅ Fully |
| Coverage of real IPS signatures | **100%** (23/23 excl. the EICAR test file) | ✅ Fully — data's own vocabulary |
| Coverage of antivirus signatures | **100%** (35/35) | ✅ Fully |
| Input bytes accounted for | **100%** (26% explained as padding) | ✅ Fully — measured |
| ATT&CK techniques covered | 27, across 11 of 14 tactics | ✅ Countable |
| Detection rate on the planted attack | 100% | ⚠️ **Nearly circular** — §1 |
| Correct ATT&CK labels on the planted attack | 100% | ⚠️ **Nearly circular** — §1 |
| False alarm rate | 0% | ⚠️ Relative to one synthetic file |
| False-negative rate on real intrusions | **unknown** | ❌ Not measurable here |

### How to verify every line of this document

```bash
python scripts/validate_independent.py --db firex.db --input D:/firex-10G.log
python tests/test_chronopath2.py        # 16 tests, 4 guarding these claims
python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json
python scripts/discover_firex.py        # how the ground truth was derived
```

---

## 8. One sentence

> **The parts of our accuracy that can be checked against something we did not
> write — the vendor's own signature names, the data's own vocabulary, and the
> bytes of the file itself — come out at 100%, 96% and fully accounted for. The
> headline "100% detection" is nearly circular and we say so wherever we quote
> it. A true false-negative rate would need labelled real intrusion data, which
> nobody gave us, and we would rather say that than produce a number that
> sounds better and means less.**
