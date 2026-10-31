# 🕸️ ChronoPath 2.0 — Pitch

**CyberForge Hackathon · Mitigata · 31 Oct – 1 Nov 2026**
**Problem statement: Kill Chain and Attack Path Analysis**

> Written for judges and reviewers. Every number here was measured on the
> organisers' own 6.54 GB data file, on a 16 GB laptop. Nothing is estimated,
> and where the data did not support the exciting answer, the unexciting one is
> reported — that turns out to be the most interesting result in the project.

---

## The one-liner

> **ChronoPath 2.0 reconstructs the attack from millions of raw log lines, shows
> the raw evidence behind every step, detects when the attacker tried to blind
> your logging, and tells the analyst what they can't conclude, what to contain
> now, and what evidence to request next.**

---

## The problem, as the organisers framed it

Analysts waste hours reconstructing what happened. A real intrusion arrives as
a handful of unremarkable alerts scattered across millions of ordinary events,
with nothing joining them. In the organisers' file:

- **9,125,382 events** in 6.54 GB
- **1,272,524 failed admin logins** — pure internet background noise
- **5 successful ones** — four orders of magnitude rarer, and the actual attack

No analyst finds that by reading. No SIEM joins those five into a story.

### And the problem the framing stops one step short of

A reconstruction appears, and the analyst still has to decide whether to
believe it. In practice they ask three questions that most tools cannot answer:

1. *"Why do you think these events are the same intrusion?"*
2. *"What couldn't you see?"*
3. *"What do I do in the next ten minutes?"*

A tool that cannot answer those is a tool the analyst has to re-do by hand.
**That is what ChronoPath 2.0 is for.**

---

## What we built

Two layers, deliberately separated.

### ChronoPath 1.x — what happened

Streams the file with DuckDB (never loads it), applies 12 config-driven rules,
tags each hit with a MITRE ATT&CK technique and kill-chain stage, then
correlates the hits into incidents with union-find over shared entities.

### ChronoPath 2.0 — can I believe it, and what now

Five modules that read the finished incidents and add evidence *alongside*
them. They never edit the engine — a regression gate enforces that the 1.x
numbers come out identical.

| Module | Answers |
|---|---|
| `streams.py` | Can I trust the data? Coverage, provenance, which clock |
| `blind_window.py` | Was I blinded — *measured*, not assumed |
| `link_evidence.py` | Why does each step belong? Graded, with the raw line |
| `gaps.py` | What can't I see, and what should I request? |
| `respond.py` | What do I contain now? Is it still happening? |

---

## Results on the organisers' real data

```
python src/parser.py --input D:/firex-10G.log --db firex.db --memory-limit 6GB
python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log
python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json
```

| Metric | Result | PRD bar |
|---|---|---|
| **Detection rate** | **100%** ⚠️ | >90% = Great |
| **Correct ATT&CK labels** | **100%** ⚠️ | >85% = Great |
| **False alarm rate** | **0%** | <10% = Great |
| Open one incident | **4 ms** | <500 ms = Great |
| Peak memory, detection | **813 MB** | <8 GB = Great |
| Peak memory, 2.0 layer | **590 MB** | — |
| Events processed | **9,125,382** | — |
| Detections → incidents | **373,061 → 5** | — |

All four PRD accuracy metrics at the "Great" bar — **and we will tell you
ourselves why two of them deserve an asterisk.**

### ⚠️ The honest caveat, before you ask for it

The organisers gave us this file with **no answer key**. So we derived one by
rarity analysis (`scripts/discover_firex.py`) and then wrote rules to find
those events. The detection and labelling metrics therefore measure *"do the
rules we wrote find the things we wrote them for?"* — six of our twelve rules
map 1:1 onto the eight ground-truth steps.

We built a second scorer that cannot be gamed that way
(`scripts/validate_independent.py`). These are the numbers we will defend:

| Independent measurement | Result | Why it is independent |
|---|---|---|
| Detections from techniques **outside** our answer key | **99.997%** | Hold-out: 373,051 of 373,061 |
| Label precision vs **Fortinet's own signature names** | **100%** — 229,757 checked, **0** disagree | Fortinet wrote those strings, not us |
| Real threats left UNMAPPED | **0** | — |
| Coverage of real IPS signatures | **96%** (23/24) | Measured against the data's vocabulary |
| Coverage of antivirus signatures | **100%** (35/35) | Same |
| Input bytes accounted for | **100%** | 26% proved to be random padding |
| True **false-negative** rate on real intrusions | **unknown** | ❌ Needs labelled real data. Nobody has given us any. |

**This check paid for itself immediately — it found two real mislabels in our
own largest detection categories.** See the next section.

Full reasoning, including everything we cannot prove:
**[`docs/ACCURACY.md`](docs/ACCURACY.md)**

### 🔍 The independent check found two real errors in our own work

Checking our ATT&CK labels against Fortinet's signature names caught two
mislabels in the **two largest detection categories we produce** — 190,186
detections, which the headline 100% metric was completely blind to.

**1. Antivirus: `T1105` → `T1566`, "Execution" → "Delivery"** (135,623 detections)

Wrong on both axes, for two independent reasons:

- T1105 *(Ingress Tool Transfer)* describes an attacker who **already has
  access** pulling tooling onto a host they control. Antivirus intercepting a
  file at the perimeter is the delivery attempt itself.
- **"Execution" is contradicted by the data:** 135,620 of the 135,623 carry
  `action="blocked"`. The file never ran. Labelling it Execution tells an
  analyst a host was compromised *when the control worked* — a false sense of
  breach, 135,000 times over.

**2. App control: `T1071.001` → `UNMAPPED`** (54,563 detections)

Labelled *Command and Control*. Then we looked at which applications FortiGate
actually rates critical:

```
KakaoTalk, Instagram, Basecamp, GoogleHangouts, OneDrive,
Skype, Dropbox, GitLab, Telegram, Tinder, Chocolatey, SSH
```

Consumer software. Someone opening Instagram at work is a policy matter, not C2
infrastructure. That was **54,563 false C2 findings** sending an analyst to hunt
a beacon that never existed.

**Both fixes left the regression gate untouched** (5 incidents, 100%/100%/0%),
because they corrected *background noise* labelling rather than the planted
attack. That is the point worth taking away: **a metric that cannot see its own
largest error is not a metric to trust alone.** Which is why we built the second
one.

### 🔇 And one rule we wrote, measured, and switched off

The coverage check reports **0% of the webfilter stream** — 408,635 events in
categories named `Botnet`, `Ransomware`, `Phishing`, 90% of them *allowed*
rather than blocked. The largest apparent blind spot in the pipeline.

So we wrote the rule and measured whether enabling it would help:

| Measurement | Result |
|---|---|
| Internal hosts involved | **1,386** |
| Events per host | min 18, median 36, max 59 (mean 36.2, σ 6.1) |
| Worst host | **3.71σ** — exactly what the max of 1,386 noise samples looks like |
| Hosts we already detect on that appear here | **1,386 of 1,388** |
| Known attacker addresses in webfilter | **0** |

Uniform synthetic background. Enabling it would add ~368,000 detections and
over a thousand single-host incidents, taking the false-alarm rate from **0% to
~99%**, and find **no additional attacker**.

It ships `enabled: false` with those measurements recorded beside it in the
YAML. On a real estate this is a rule you *want* — one word turns it on. We
verified it fires correctly when the threshold is reachable, so it is documented
config, not dead config.

### Scale, honestly

Memory is **flat**, not proportional to the file — that is the whole point of
streaming. 6.54 GB processed in 813 MB means 15 GB should cost more *time*, not
more memory. We say "should" because we measured 6.54 GB and did not measure 15.

### And one thing the input accounting caught

The file is **6.09 GB, of which only 4.48 GB is syslog.** The trailing 1.61 GB
(26%) has entropy 7.998 bits/byte, is incompressible, and contains exactly one
`date=` occurrence — the truncated tail of the last real line. It is **random
padding**, so no events are missing.

But our pipeline had been silently skipping a quarter of the input while
reporting 100% accuracy on the rest. That is a true statement about an unstated
subset — the most dangerous failure mode a log tool has. It is now measured, and
a test fails if any region of any input is neither parsed nor positively
explained.

---

## 🥇 Our favourite result: the attacker's blinding **failed**, and we can prove it

In **INC-02**, the account `Tejas.Roy` disabled the firewall's disk logging at
16:31, then purged the firewall policy objects at 18:28 — textbook *Impair
Defenses* followed by action under cover.

The dramatic report writes itself: *the attacker went dark for two hours.* It
fits the kill chain, it demos beautifully, and **on this data it is false.**

### Why a careless check gets this wrong

Log volume follows a daily rhythm. It falls every evening whether or not anyone
touches the logs. So we slide the exact same window onto the other days in the
file as a **control**:

| Day | Before window | Inside window | Change |
|---|---|---|---|
| **2026-10-23** — *logging disabled* | 133,462 | 101,205 | **−24.2%** |
| 2026-10-24 | 133,562 | 101,630 | −23.9% |
| 2026-10-25 | 106,718 | 81,076 | −24.0% |
| 2026-10-26 | 107,164 | 81,255 | −24.2% |
| 2026-10-27 | 106,946 | 81,400 | −23.9% |

The day the attacker disabled logging is **indistinguishable from every control
day** — it is not even the steepest decline. 101,205 events were still recorded
inside the window.

A naive before/after test with a 20% threshold would have fired on **all five
days** and accused an attacker each time.

### Why the unexciting answer is the more useful one

It tells the analyst three things they can act on:

1. **The disable attempt failed.** The evidence of what the attacker did next
   is present — we can see the 18:28 policy purge *because* logging kept
   running.
2. **This file is a forwarded copy.** Disabling *disk* logging does nothing to
   a remote syslog or FortiAnalyzer stream. The data proves which one we have.
3. **The right request is specific:** the FortiAnalyzer copy for that window,
   to confirm independently, plus config backups from either side of it.

Classification: `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA`. The threshold was
not tuned to manufacture a drop.

---

## The principle that runs through the whole layer

### *Missing is not malicious.*

The easiest mistake in security tooling is reporting absence as attack, because
the malicious explanation is always more interesting. It is also usually wrong.
Logs go missing because the agent was never installed, the forwarder was down,
or nobody licensed that source.

So absence is classified `NOT_COLLECTED` or `COVERAGE_UNKNOWN` — **never** as
deletion — unless a *positive event* proves otherwise. The vocabulary is a
closed list, validated at the database boundary so a future contributor cannot
quietly add "possible log tampering".

On the organisers' data, out of 15 gaps:

| Classification | Count |
|---|---|
| `NOT_COLLECTED` | 13 |
| `COVERAGE_UNKNOWN` | 1 |
| `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA` | 1 |
| **`LOGGING_DISABLED_BY_ACTOR`** | **0** |

**Zero accusations**, because nothing in this data proves one. Likewise
"nothing before 23 October" is `COVERAGE_UNKNOWN`, not "retention expired" —
claiming expiry would need retention metadata nobody gave us.

---

## Every link graded — and every link we *refused*

1.x says three detections are one incident. 2.0 says why:

| Grade | Why | Gap |
|---|---|---|
| **HARD** | This event **created** the account `svc_backup30` that acts 6 min later | 6 min |
| **HARD** | Same account `Rakes` on both events | 12 min |
| **SOFT** | Same external address `203.228.177.117` — strong, not conclusive | 5 min |

The identity pivot's proof existed **only in the raw log line**. The detections
table records the creation as the useless `"Object attribute configured"`, while
the account name sits in `msg="Add system.admin svc_backup30"`. Rather than
widen the write path for 9.1 million rows, the evidence layer fetches the
original line for the reported incidents only.

### And the part most tools omit

Every **rejected** link is recorded too. On the EDR data, `SRV-DC-01` was
refused as a link because it is used by **10 different accounts** — a domain
controller is where everyone's activity meets. Linking on it would chain a
dozen strangers into one incident.

Silent refusal is its own trap: an analyst cannot tell *"these are genuinely
unrelated"* from *"the tool decided not to connect them and didn't say."* The
second is far more dangerous, because they will never know to ask.

### Which is why 5 incidents is the *correct* answer

All eight planted steps are found with the right technique — but they come back
as **five incidents**, because five accounts from five different external
addresses share nothing that would legitimately join them. So we state it, for
each of the 10 pairs, with **computed** counts:

> **INC-01 and INC-02 are not linked:** they share no account and no external
> source address. The only common value is `10.10.99.1` (used by **5**
> accounts), which exceeds the **3**-account limit and is therefore treated as
> infrastructure rather than as an actor. A shared firewall is where everyone's
> traffic meets, so it is not evidence that these two are one intrusion.

Fabricating a link to make one tidy incident would score better on a naive
metric and be a lie.

---

## The gap that changes what an analyst does

1.x showed INC-01's three detections and stopped. The silence read as *"that's
all that happened."*

> **`INC-01-GAP-LIFECYCLE`** · `NOT_COLLECTED` · `svc_backup30`
>
> **Basis:** The data records the account's creation, login and deletion — but
> FortiGate event logs state only that an attribute *changed*, never what the
> new value was. No configuration revision history was supplied for the window.
>
> **Impact:** Cannot determine what `svc_backup30` **did** while it existed. No
> answer on whether policies, VPN users, admin accounts or port forwards were
> added that would **survive the account's deletion**. Treat persistence as
> *unverified rather than absent*.
>
> **Request:** Firewall configuration revision history for the period the
> account existed, plus the identity-provider audit log for that account.

That is the first question a real incident responder asks about INC-01, and the
honest answer is that this data cannot answer it. Saying so is worth more than
a confident silence.

---

## 🧪 We proved the gap layer works — and it caught a bug in our own work

Claims about absence are the easiest to make and the hardest to check, because
the evidence for them is by definition missing. So we built a case where the
right answer is known in advance:

```
python scripts/experiment_remove_host.py
```

Delete `SRV-DC-01` from the EDR input and re-run. It holds the **identity
pivot** (`rkumar` creating `svc_helpdesk`) that carries the chain from the
workstation phase to the exfiltration phase — so removing it *severs* the
attack rather than merely shortening it.

| | Full data | Without `SRV-DC-01` |
|---|---|---|
| **Planted steps found** | **8/8** | **3/8** |
| Hosts in top incident | 20 | **1** |
| Stages in top incident | 7 | **4** |

**Three gaps appear only on the reduced data**, including one naming
`svc_helpdesk` as an account acting with no recorded origin:

> Cannot establish whether it was created by the attacker during this intrusion
> or is a legitimate pre-existing account that was compromised. **These call for
> opposite responses — delete versus reset.**

### The experiment found a genuine weakness in our own work

The first version of the gap ledger said **nothing** about the hole. It reasoned
only about telemetry *types*, never about an entity that is referenced but
unexplained. We added the actor-origin gap in response.

The asymmetry is the evidence it tracks reality: on the **reduced** data
`svc_helpdesk` raises the gap; on the **full** data it correctly does **not**,
because the creation event is present. A ledger that listed the same gaps either
way would have proved nothing.

### And note what it refuses to do

The gap **never names `SRV-DC-01`.** The tool never saw that host, and inventing
its name would be fabrication. It names the *consequence* and *infers* the
request — *"if a domain controller is missing from the supplied sources, that is
the host to request first."*

| Nothing-invented check | Result |
|---|---|
| Records for the removed host in the reduced input | **0** |
| Records for the removed host in the output database | **0** |

---

## Engineering decisions worth defending

| Decision | Why |
|---|---|
| **DuckDB streaming, not pandas** | 6.54 GB in 813 MB. pandas would need the file in RAM. Memory is flat, not proportional. |
| **Rules in YAML, not code** | A new detection is a config edit, not a deploy. (PRD bonus B-4.) |
| **Union-find over shared entities** | Transitive correlation in near-linear time. Adjacent-pair linking cut 21.8 s → 0.03 s on 5,000 detections. |
| **Accounts link; machines mostly don't** | Measured: treating a shared host as a link merged 28 hosts into one useless 3,600-step "incident". An account is the actor; a host is where strangers coincide. |
| **Placeholder `-` is not an identity** | Measured: treating it as a username collapsed 395,193 of 395,361 detections into one meaningless incident. |
| **2.0 in its own package, new tables** | Ground rule: don't touch a measured 100%/100%/0% engine. Rolling back 2.0 is dropping tables, not restoring a backup. |
| **Containment advice is rule-based, not LLM** | It must not vanish when an API key expires mid-demo, and a model should not improvise instructions someone may run on production infrastructure. |
| **The LLM is strictly optional** | It writes the narrative paragraph. Detection, correlation, evidence and gaps are fully deterministic and offline. |

### Cost: ₹0

Python, DuckDB, NetworkX, Streamlit, and the Groq free tier. No cloud, no
licence, no card. Runs on the 16 GB laptop in the room.

---

## What we did not build, and said so

| Not built | Why |
|---|---|
| B-5 live/streaming mode | Most work for fewest points; would risk the core demo. |
| Parquet normalisation layer | Out of scope for this build; noted as future work. |
| Entity registry / STIX loader | Same. |
| Neo4j, Postgres, FastAPI, Next.js | Each adds a service to install and demo. NetworkX, DuckDB and the stdlib do the job on one laptop. |

### Honest limitations

- **The ground truth for the real file is reconstructed, not supplied.** The
  organisers gave the file with no answer key, so we derived one from rarity
  analysis — 14 events out of 9,125,382, reproducibly
  (`scripts/discover_firex.py`). "100% detection" means *100% of the attack we
  identified as planted*.
- **Measured on 6.54 GB, not 15 GB.** Flat memory makes the extrapolation
  reasonable; it is still an extrapolation.
- **The blind-window control needs several days of data.** On a shorter file
  there is no control, and the check returns `COVERAGE_UNKNOWN` rather than
  guessing.
- **The gap ledger knows what it was told to look for.** A category of absence
  nobody anticipated would still be missed — which is exactly the failure the
  remove-host experiment caught in our own first version.
- **Rule-based detection misses novel attacks.** Mitigated by rules-as-config
  and by the rarity-based hunting view, which found all five attacker accounts
  on the real file with no rule describing them.
- **We cannot give a false-negative rate.** We only know about attacks we
  found. Establishing what we *missed* needs intrusions someone else confirmed.

### "Why not train a model on this data for exact accuracy?"

A fair question with a specific answer: **it would produce a number that looks
better and means less.**

- **There are no real-world labels to train on.** The file arrived with no
  answer key. Our ground truth is our own inference from rarity analysis.
  Training on self-derived labels and then scoring against those same labels is
  the circularity above, one level deeper and much harder to spot.
- **This file is demonstrably synthetic.** 22 near-duplicate webfilter
  categories ("Phishing Tactics", "Phishing Patterns", "Phishing Methods",
  "Fishing Attacks"), 45 vendor-word-salad IPS signatures, a perfectly uniform
  36-events-per-host distribution, and 1.61 GB of random padding. A model
  trained to fit those artefacts would get **worse** on real telemetry.
- **What would make it meaningful:** labelled intrusion data from a production
  estate, with incidents confirmed by the responders who handled them. We have
  none, and no amount of code substitutes for it.

So instead of a trained score we built a scorer that checks us against things
we did not author — the vendor's signature names, the data's own vocabulary,
and the bytes of the file. Those come out at **100%, 96% and fully accounted
for**, and they are the numbers we will defend under questioning.

---

## Verification — run it yourself

```bash
python tests/test_chronopath2.py                 # 12 tests, incl. the regression gate
python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json
python scripts/experiment_remove_host.py         # the controlled experiment
streamlit run src/app.py                         # 9 tabs
python src/api.py                                # REST: /evidence /gaps /sources
```

The regression gate is the one to check first. It asserts that the 1.x numbers
— 373,061 detections, 5 incidents, 100%/100%/0% — are **identical** after the
2.0 layer. The entire architecture exists to make that test pass.

**Full measured results, with method:** [`docs/results_2.0.md`](docs/results_2.0.md)
**Baseline the gate protects:** [`docs/baseline_before_2.0.md`](docs/baseline_before_2.0.md)
**New to the project?** [`START_HERE.md`](START_HERE.md)

---

## The close

Three sentences, in increasing order of what matters:

> **Hayabusa tells you what fired.**
> **ChronoPath 1.x tells you what happened.**
> **ChronoPath 2.0 tells you what you can prove, what you can't, and what to do about it.**

And the thing this build is most willing to say out loud: on the organisers'
data, **the attacker did not blind us** — and reporting that, rather than the
dramatic alternative, is the whole point.

---

*CyberForge 2026 · Mitigata · 9,125,382 events · 100% / 100% / 0% · ₹0*
