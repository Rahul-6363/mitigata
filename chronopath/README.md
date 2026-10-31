# 🕸️ ChronoPath 2.0 — Kill Chain & Attack Path Analysis

**CyberForge Hackathon · Mitigata · 31 Oct – 1 Nov 2026**
**Tier: Core (15 GB)**

[![Stack](https://img.shields.io/badge/Stack-Python%203.14%20%7C%20DuckDB%202.0%20%7C%20NetworkX%203.6-success.svg)]()
[![LLM](https://img.shields.io/badge/GenAI-Groq%20Free%20Tier%20(optional)-orange.svg)]()
[![Accuracy](https://img.shields.io/badge/Real%20data-100%25%20detection%20%7C%20100%25%20labels%20%7C%200%25%20false%20alarms-brightgreen.svg)]()
[![Scale](https://img.shields.io/badge/6.54GB%20%7C%209.1M%20events-590MB%20RAM-blue.svg)]()

Reads a large pile of security logs, finds the attack hidden inside, and shows
it as one story: where the attacker started, what they did, and where they can
go next.

**ChronoPath 2.0** adds the part that makes it usable by an analyst rather than
just impressive to a reviewer — it shows the **raw evidence behind every step**,
states **what it could not see**, and says **what to do next**:

> ChronoPath 2.0 reconstructs the attack, shows the raw evidence behind every
> step, detects when the attacker blinded your logging, and tells the analyst
> what they can't conclude, what to contain now, and what evidence to request
> next.

The headline 2.0 finding on the organisers' data is one most tools would get
wrong: the attacker **disabled the firewall's logging and it did not work.**
We can prove that, with a measurement, rather than guess either way —
see [§ What ChronoPath 2.0 adds](#-what-chronopath-20-adds).

---

> **New to this project?** Read **[START_HERE.md](START_HERE.md)** first — it
> explains the problem, the jargon and what we built, assuming no security
> background.

## 🔥 On the real data set (`firex-10G.log`)

```bash
python src/parser.py --input D:/firex-10G.log --db firex.db --memory-limit 6GB
python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log   # the 2.0 layer
python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json
streamlit run src/app.py        # or: python src/api.py
```

Format is detected automatically — it is FortiGate firewall syslog, a third
format alongside our flat JSON and the EDR generator's ECS JSON.

| Measurement | Result |
|---|---|
| File | 6.54 GB, **9,125,382 events** |
| Full detection run, 12 rules | **~99 s** |
| Peak memory, detection | **813 MB** (PRD "Great" bar: 8 GB) |
| Correlation of 373,061 detections | **2.0 s** |
| Open one incident | **4.0 ms** (bar: 500 ms) |
| **Detection rate** | **100%** |
| **Correct ATT&CK labels** | **100%** |
| **False alarm rate** | **0%** |
| Incidents reported | **5** |
| 2.0 evidence layer, added cost | **+51 s, 590 MB peak** |

**The attack it finds, ranked #1:** an administrator account `svc_backup30`
created at 03:55, used to log in at 04:02, and deleted at 04:07 — created, used
and destroyed inside twelve minutes. Preceded by disk logging being disabled
and the firewall policy base purged.

**How it was found:** rarity, not volume. Among 9.1 M events there are
1,272,524 *failed* admin logins — internet background noise — and only **5
successes**. The signal is four orders of magnitude rarer than the noise.

Full write-up, including the two metrics that do not pass and why:
**[FIREX_RESULTS.md](FIREX_RESULTS.md)**

---

## 🆕 What ChronoPath 2.0 adds

ChronoPath 1.x answers *"what happened?"* — and does it well: 100% detection
and 100% correct ATT&CK labels on 9.1 million real events. But an analyst
handed a ranked incident list still has three questions it cannot answer, and a
tool that cannot answer them is a tool they have to re-do by hand.

2.0 answers them, in the order an analyst actually works. **Full measured
results: [docs/results_2.0.md](docs/results_2.0.md).**

| Question | What 2.0 shows | Module |
|---|---|---|
| **Can I trust the data?** | Per-stream coverage, SHA-256 provenance, which clock was used | `streams.py` |
| **Was I blinded?** | Whether a logging-disable event actually cost us visibility — *measured* | `blind_window.py` |
| **Why does this step belong?** | A grade, a plain sentence and the raw log line behind every link | `link_evidence.py` |
| **What can't I see?** | A gap ledger with the basis, the impact, and the evidence to request | `gaps.py` |
| **What do I do now?** | Indicators, whether it is still happening, recommended containment | `respond.py` |

Everything is **additive**. The 2.0 modules write new `cp2_` tables and never
touch `suspicious_events`; the detection engine is not edited at all. A
regression gate enforces this — the 1.x numbers must come out byte-identical,
and [12 tests](tests/test_chronopath2.py) check it.

### 🥇 The finding we are most pleased with: the attacker's blinding *failed*

In INC-02, `Tejas.Roy` disabled the firewall's disk logging at 16:31, then
purged the firewall policy objects at 18:28. The dramatic report writes itself:
*the attacker went dark for two hours.* **On this data it is false**, and we
can prove it.

The trap is that log volume follows a daily rhythm — it drops every evening
whether or not anyone touches the logs. So the check slides its exact window
onto the other days in the file as a **control**:

| Day | Before window | Inside window | Change |
|---|---|---|---|
| **2026-10-23** (logging disabled) | 133,462 | 101,205 | **−24.2%** |
| 2026-10-24 | 133,562 | 101,630 | −23.9% |
| 2026-10-25 | 106,718 | 81,076 | −24.0% |
| 2026-10-26 | 107,164 | 81,255 | −24.2% |
| 2026-10-27 | 106,946 | 81,400 | −23.9% |

The blind-window day is **indistinguishable from the control days** — it is not
even the steepest. 101,205 events were still recorded inside the window, and
the `event/system` stream kept running, which is *why we can see the 18:28
policy purge at all.* The purge was logged.

Classification: **`LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA`**.

**Why this matters more than the dramatic version.** It tells the analyst three
actionable things: the disable attempt *failed*, the supplied file is therefore
a **forwarded** copy (disabling *disk* logging does nothing to a remote syslog
stream), and the right next step is the FortiAnalyzer copy to confirm
independently. A naive >20% threshold would have fired on all five days and
accused an attacker each time.

### 🧭 The rule that governs the whole layer: *missing is not malicious*

The easiest mistake in security tooling is reporting absence as attack, because
the malicious explanation is always more interesting. It is also usually wrong:
logs go missing because the agent was never installed, the forwarder was down,
or nobody licensed that source.

So absence is classified `NOT_COLLECTED` or `COVERAGE_UNKNOWN` — **never** as
deletion — unless a *positive event* proves otherwise. The vocabulary is a
closed list validated at the database boundary, and on the organisers' data the
ledger issues **zero** accusations:

| Classification | FortiGate | Meaning |
|---|---|---|
| `NOT_COLLECTED` | 13 | This telemetry is not in any supplied source |
| `COVERAGE_UNKNOWN` | 1 | We cannot tell whether it was collected |
| `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA` | 1 | Disabled, but still recording |
| `LOGGING_DISABLED_BY_ACTOR` | **0** | *Would require positive proof* |
| `PARSE_FAILURE` | **0** | *All 9,125,382 rows parsed cleanly* |

"Nothing before 23 October" is `COVERAGE_UNKNOWN`, **not** "retention expired"
— claiming expiry needs retention metadata nobody gave us.

### 🔗 Every link graded, including the ones we refused

1.x says five detections are one incident. 2.0 says *why*, with the raw line:

| Grade | Attribute | Value | Gap | Why |
|---|---|---|---|---|
| **HARD** | identity pivot | `svc_backup30` | 6 min | This event **created** the account that acts 6 min later |
| **HARD** | account | `Rakes` | 12 min | Same account |
| **SOFT** | source IP | `203.228.177.117` | 5 min | Same external address — strong, not conclusive |

The identity pivot's proof existed **only in the raw log line**: the detections
table records the creation as `"Object attribute configured"`, while the account
name sits in `msg="Add system.admin svc_backup30"`. Rather than widen the write
path for 9.1 M rows, the evidence layer fetches the original line for the
reported incidents only.

**And every *rejected* link is recorded too** — the part most tools omit. On the
EDR data, `SRV-DC-01` was refused as a link because it is used by **10**
different accounts: a domain controller is where everyone's activity meets.
Silent refusal is its own trap, because an analyst cannot distinguish *"these
are genuinely unrelated"* from *"the tool decided not to connect them and
didn't say."*

This is also why the FortiGate run reports **5 separate incidents** and that is
the *correct* answer. Each of the 10 incident pairs carries a statement with
**computed** counts:

> **INC-01 and INC-02 are not linked:** they share no account and no external
> source address. The only common value is `10.10.99.1` (used by **5**
> accounts), which exceeds the **3**-account limit and is treated as
> infrastructure rather than an actor.

### 🕳️ The single most useful gap we produce

1.x showed INC-01's three detections and stopped. The silence read as *"that's
all that happened."* It wasn't:

> **`INC-01-GAP-LIFECYCLE`** · `NOT_COLLECTED` · `svc_backup30`
>
> **Basis:** The data records the account's creation, login and deletion — but
> FortiGate event logs state only that an attribute *changed*, never what the
> new value was. No configuration revision history was supplied for the window.
>
> **Impact:** Cannot determine what `svc_backup30` **did** while it existed.
> No answer on whether policies, VPN users or port forwards were added that
> would **survive the account's deletion**. Treat persistence as *unverified
> rather than absent*.
>
> **Request:** Firewall configuration revision history for the period the
> account existed, plus the identity-provider audit log for that account.

That is the first question a real incident responder must answer about INC-01,
and the honest answer is that this data cannot answer it.

### 🧪 We proved the gap layer works — and it caught a bug in our own work

Claims about absence are the easiest to make and hardest to check. So
[`scripts/experiment_remove_host.py`](scripts/experiment_remove_host.py) builds
a case where the right answer is known: delete `SRV-DC-01` from the EDR input
and re-run. It holds the **identity pivot** (`rkumar` creating `svc_helpdesk`)
that carries the chain from the workstation phase to the exfiltration phase, so
removing it *severs* the attack rather than merely shortening it.

| | Full data | Without `SRV-DC-01` |
|---|---|---|
| **Planted steps found** | **8/8** | **3/8** |
| Hosts in top incident | 20 | **1** |
| Stages in top incident | 7 | **4** |

**Three gaps appear only on the reduced data**, including an actor-origin gap
naming `svc_helpdesk` as an account that acts with no recorded origin —
*"cannot establish whether it was created by the attacker or is a legitimate
pre-existing account that was compromised. These call for opposite responses —
delete versus reset."*

**The experiment found a real weakness in our own Task 4 work:** the first
version of the ledger said *nothing* about the hole, because it reasoned only
about telemetry *types*, never about an entity referenced but unexplained. The
actor-origin gap was added in response. The asymmetry is the evidence it tracks
reality — on the reduced data `svc_helpdesk` raises it; on the full data it
correctly does **not**, because the creation event is present.

**And note what it refuses to do:** the gap never names `SRV-DC-01`. The tool
never saw that host, and inventing its name would be fabrication. It names the
*consequence* and infers the request — *"if a domain controller is missing from
the supplied sources, that is the host to request first."*

| Nothing-invented check | Result |
|---|---|
| Records for the removed host in the reduced input | **0** |
| Records for the removed host in the output database | **0** |

### 🚨 And finally: what to do in the next ten minutes

Every indicator is looked up across the **whole data set**, not inside the
incident — because an incident's end time is the last time *those detections*
fired, not the last time the attacker was seen. That single widening turns a
historical report into a containment decision.

For INC-01: `Rakes`, `svc_backup30` and `203.228.177.117`, each with
first/last seen. `svc_backup30` is flagged *"created and deleted during this
incident, so it will not appear in the current configuration — the only record
is this log."*

**Preceding access reports an explicit negative**, which is a finding rather
than a blank: *no* credential-guessing burst preceded INC-01, so the credential
came from elsewhere — reuse, phishing or a legitimate holder. An empty section
reads as "not checked"; this reads as "checked, and the absence is informative."

Actions are **rule-based templates, never LLM output**, and every one is
labelled `RECOMMENDED`. Two reasons: containment advice must not vanish when an
API key expires mid-demo, and a model asked for containment steps will produce
fluent, occasionally wrong instructions that someone may run on production
infrastructure.

### Where to see it

```bash
streamlit run src/app.py     # 9 tabs: Evidence, What we can't see, Respond now, Sources
python src/api.py            # GET /evidence /gaps /separation /indicators /sources
python tests/test_chronopath2.py     # 12 tests, including the regression gate
```

---

## ⚡ Quick start

```bash
pip install -r requirements.txt
python run_demo.py                 # generate logs, detect, correlate, score
streamlit run src/app.py           # open the dashboard
python src/api.py                  # or the REST API on :8000
python src/pivot.py                # threat hunting: what looks anomalous?
```

```bash
# FR-7's worked example, verbatim:
curl http://localhost:8000/incidents/1/path
```

**For the AI-written report (optional):** get a free key at
[console.groq.com](https://console.groq.com), then create a file named `.env` in
this folder containing `GROQ_API_KEY=gsk_your_key_here` (copy `.env.example`).
Everything works without it — the report falls back to a built-in summary.

Full install instructions: **[SETUP.md](SETUP.md)**
Working with the organisers' EDR generator: **[EDR_DATA.md](EDR_DATA.md)**

### Using the organisers' `edr_log_generator.py`

```bash
python ../edr_log_generator.py --count 400000 --rate 0 --output file --file raw.json
python scripts/prepare_edr.py --input raw.json --output data/edr_ready.json
python src/parser.py --input data/edr_ready.json     # ECS format auto-detected
```

ChronoPath reads **both** the organisers' nested ECS format and our own flat
format, detecting which is which from the file itself. See
[EDR_DATA.md](EDR_DATA.md) for what that generator does and does not produce,
and why `prepare_edr.py` exists.
Learn the concepts and the code: **[READTHIS.md](READTHIS.md)**

---

## 🎯 The problem

Security tools raise alerts one at a time. So three lines in three different log
files —

```
09:14  35 failed logins on HR-07      ← looks like a forgotten password
09:22  new admin account created      ← looks like IT onboarding
09:31  250 MB uploaded from FS-02     ← looks like a backup job
```

— look like three unrelated events. They are one breach. Connecting them by hand
takes an analyst hours, while the attacker keeps moving.

**ChronoPath connects them automatically**, labels each step with MITRE ATT&CK,
rebuilds the path across hosts/users/time, and says what the attacker could
reach next.

---

## 🧠 How it works

The constraint: **15 GB of logs, 16 GB of RAM.** Loading the logs kills the
process. The architecture exists to solve exactly that.

```
   15 GB raw logs on disk
            │
            │  ❶ DuckDB STREAMS it — reads a chunk, filters, discards, repeats.
            │     Memory stays flat no matter how big the file is.
            ▼
   A handful of suspicious events  (~10,000× reduction)
            │
            │  ❷ NetworkX builds the attack graph from the SMALL set.
            ▼
   Attack path + look-ahead
            │
            │  ❸ Groq writes the plain-English report.
            ▼
   Streamlit dashboard
```

**The core idea:** the expensive thing (15 GB) is handled by a streaming SQL
engine built for it. The clever thing (reasoning about reachability) is handled
by a graph library — but only after the data is small enough to fit in memory.
Neither tool is asked to do the other's job. *That* is why it runs on a laptop.

---

## 📊 Results — measured, not estimated

### Accuracy (`python scripts/evaluate.py`)

Scored against a planted attack with known ground truth:

| PRD metric | ChronoPath | Good | Great |
|---|---|---|---|
| Detection rate | **100%** | >70% | >90% |
| Correct ATT&CK labels | **100%** | >60% | >85% |
| Attack path rebuilt | **YES** | half | all |
| False alarm rate | **0%** | <30% | <10% |

All four at the **Great** bar, and **verified stable at 50 MB, 200 MB, 600 MB
and 1 GB** — not just on one convenient sample.

### Four real bugs found by testing at scale

Worth telling judges, because it shows the accuracy numbers are earned rather
than fitted. All four were invisible on a small sample:

**1. Brute force counted totals, not rates.** The rule counted failed logins per
user across the *whole file*. At 1 GB, ordinary staff had accumulated **60+
failures spread over days** — more than the attacker's 35 in four minutes. The
rule was ranking innocent people above the intruder. Fixed by bucketing on time:
the question became "20 failures in ten minutes?" rather than "20 ever?".
Humans spread mistakes out; scripts do not.

**2. Fixed time buckets split the attack.** The first fix broke detection: the
attacker's burst straddled a bucket boundary and was divided into 18 + 17, both
under the threshold, so the real attack went **undetected** while false
positives stayed fixed — the worst possible trade. Fixed by evaluating two grids
offset by half a window, so a burst is always fully inside at least one.

**3. Deduplication hid repeat attacks.** Removing the duplicate rows the two
grids produce is easy to get wrong. Partitioning by `host, user` keeps one
detection per account *for the whole data set*, so an account attacked on Monday
and again on Friday reports once — the earlier attack silently discarded. Fixed
by merging on elapsed time (`LAG()`) rather than grid position. Verified across
20 window offsets and bursts 25 minutes and 3 days apart.

**4. Correlation was quadratic.** Grouping detections into incidents compared
every event against every other in its window: **21.8 s for 5,000 detections**,
against a 2-second PRD target. Union-find already makes connectivity transitive,
so linking only *adjacent* pairs gives identical output at O(n) instead of
O(n²) — **21.8 s → 0.03 s**, and 20,000 detections now take 0.12 s.

**The lesson:** volume alone is a weak signal; volume plus time plus context is
a strong one. Measuring accuracy *and* profiling at several scales is what
exposed all four. See `build_aggregate_query()` in [src/parser.py](src/parser.py),
`correlate_incidents()` in [src/graph_engine.py](src/graph_engine.py), and the
comments in [rules.yaml](rules.yaml).

### Memory & throughput (`python scripts/benchmark.py`)

| Measurement | Result |
|---|---|
| Data scanned | 402 MB |
| Hard memory cap | 1 GB |
| **Peak process RSS** | **323 MB** |
| Throughput | ~730–1030 MB/s |

**Peak memory came in below the file size.** That is only possible if the data
is genuinely streamed rather than loaded. Extrapolated, 15 GB is roughly
**20 seconds** of scan time against the PRD's 1-hour "Great" target.

End-to-end on ~1 GB: **9.8 s** to scan and detect, 8 rules, 8 detections, one
incident, zero false alarms.

> ⚠️ **Honest caveats.** Accuracy is measured against *our own* synthetic attack;
> real data will be messier. The benchmark is synthetic NDJSON on a warm cache —
> real logs on cold disk will be I/O-bound and slower. The *memory* behaviour,
> which decides whether the demo crashes, is the part that generalises.

---

## 💡 Innovation — what we add beyond a rule engine

We studied **[Hayabusa](https://github.com/Yamato-Security/hayabusa)**
(Yamato-Security), the leading open-source Windows event log forensics tool —
Rust, multi-threaded, full Sigma support including v2 correlation rules. It is
the state of the art for this problem, and it shaped three additions to
ChronoPath.

### What Hayabusa does that we learned from

| Hayabusa feature | The idea behind it |
|---|---|
| `pivot-keywords-list` | List every user, host and process, then look for the outliers. Analysts call these **pivot points** — find one, and you pivot on it to find everything else the attacker touched. |
| Detection frequency timeline | Attacks arrive in **bursts**. Seeing *when* detections cluster tells you where to look before reading a single event. |
| `logon-summary` | Success vs failure counts per account — the single highest-signal view in authentication data. |
| Rule-driven, config-based detection | Detection logic is *data*, not code. We already do this (`rules*.yaml`). |

### What we added — and why it matters

**1. Automatic anomaly ranking (`src/pivot.py`)**

Hayabusa *lists* pivot keywords for a human to eyeball. **We rank them
automatically**, because on 9.1 million events nobody can eyeball anything.
Each entity scores 0–100 on rarity (50%), worst severity (30%) and kill-chain
spread (20%).

*Why rarity dominates:* it is the one signal that needs **no prior knowledge of
what an attack looks like**. Counting how often each account appears in the
real `firex-10G.log` detections:

```
  155 events   "002"              <- noise
    3 events   Deepika.Khan       <- ATTACKER
    2 events   Rakes              <- ATTACKER
    2 events   Tejas.Roy          <- ATTACKER
    1 event    parul.sinha        <- ATTACKER
    1 event    svc_backup30       <- ATTACKER (created by the attacker)
    1 event    keerat.ghughal     <- ATTACKER
```

**Every attacker appears 1–3 times. The noise appears 155.** Running
`python src/pivot.py --db firex.db` puts **all five attacker accounts in the
top five**, and ranks the attacker's IP `203.228.177.117` first among source
addresses — spanning three kill-chain stages.

> **Why this matters:** our detection rules find what we *thought to describe
> in advance*. This finds what is *unusual*, including an attack nobody wrote
> a rule for. Rules are knowledge-based; this is statistics-based. Having both
> is the difference between a detection tool and a **hunting** tool.

**2. Detection frequency timeline**

Detections bucketed by hour, as a chart in the dashboard and a sparkline in
the terminal. One `GROUP BY` for a view that tells an analyst which hours to
investigate first — and a spike at 03:00 on a Sunday is itself a finding.

**3. A hunting view in every interface**

| Where | How |
|---|---|
| Terminal | `python src/pivot.py` |
| Dashboard | the **🔍 Threat hunting** tab |
| API | `GET /pivot` and `GET /timeline` |

Cached on the database's modification time: ranking 395,361 detections takes
~6.5 s cold, **0.28 ms** cached, so the hunting view never costs the PRD's
investigation-speed target.

### Where we go beyond Hayabusa

Said plainly, because the comparison is the point:

| | Hayabusa | ChronoPath |
|---|---|---|
| Input | Windows EVTX only | **Three formats** — FortiGate syslog, ECS JSON, flat JSON, auto-detected |
| Output | A ranked **timeline** of alerts | A reconstructed **attack path**: which alerts are one incident, in order |
| Correlation | Sigma rules within a time window | **Union-find across users, IPs and identity pivots** — follows an attacker who creates a new account and continues as it |
| "What next?" | — | **FR-6 blast radius** from observed activity *plus* standing privilege |
| Narrative | — | Plain-English incident report (Groq) |
| Hunting | Lists pivot keywords | **Ranks them automatically** |

Hayabusa is faster and far more mature at what it does — it is Rust, we are
Python, and it carries thousands of community Sigma rules. **The honest
framing: Hayabusa tells you *what fired*. ChronoPath tells you *what
happened*.** Hayabusa produces a timeline of alerts; we produce a story with a
beginning, a middle, and a prediction of the ending.

---

## ✅ Requirements coverage

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| **FR-1** | Read full data set without loading into memory | `src/parser.py` — DuckDB streaming | ✅ benchmarked |
| **FR-2** | Detect suspicious events | `src/parser.py` + `rules.yaml` | ✅ 8 rules |
| **FR-3** | Map to ATT&CK technique + kill chain stage | `rules.yaml` | ✅ every rule tagged |
| **FR-4** | Link events into one incident | `graph_engine.correlate_incidents()` | ✅ union-find |
| **FR-5** | Timeline **and** graph | `src/app.py` tabs 2 & 3 | ✅ |
| **FR-6** | What the attacker could reach next | `graph_engine.look_ahead()` + `assets.yaml` | ✅ observed + privilege |
| **FR-7** | Simple API **or** page + README | `src/api.py` (REST, incl. `GET /incidents/1/path`) **and** `src/app.py` (page) | ✅ both |
| **B-1** | Risk score per incident | `graph_engine.risk_score()` | ✅ 3-factor, sorted |
| **B-2** | Auto-written plain-English report | Groq in `src/app.py` | ✅ with offline fallback |
| **B-3** | Raw alerts merged per incident | `incident["raw_alert_count"]` | ✅ shown in UI |
| **B-4** | New rule via config, not code | `rules.yaml` | ✅ |
| B-5 | Live mode | — | ❌ out of scope (see below) |

**On B-5:** deliberately skipped. It is the most work for the fewest points and
would risk the core demo. Shipping the other four bonuses solidly beats shipping
five shakily.

### ChronoPath 2.0 additions

Beyond the PRD, because the PRD's own framing — *"analysts waste hours
reconstructing what happened"* — does not end when the reconstruction appears.
An analyst still has to decide whether to believe it.

| Adds | Implementation | Status |
|---|---|---|
| Telemetry coverage + SHA-256 provenance | `chronopath2/streams.py` | ✅ 12 streams, 9,125,382 events |
| Clock-ambiguity detection | `streams.py` fingerprint | ✅ caught a 5.5 h trap by measuring |
| Blind-window check with a daily-curve control | `chronopath2/blind_window.py` | ✅ measured, not assumed |
| Graded link evidence + raw log lines | `chronopath2/link_evidence.py` | ✅ 0 links without a reason |
| Rejected links recorded | `link_evidence.py` | ✅ with computed counts |
| "Why these incidents are separate" | `link_evidence.incident_separation()` | ✅ all 10 pairs |
| Gap ledger, closed vocabulary | `chronopath2/gaps.py` | ✅ 15 gaps, 0 unfounded accusations |
| Evidence requests per gap | `gaps.EVIDENCE_REQUESTS` | ✅ every gap actionable |
| Indicators with dataset-wide first/last seen | `chronopath2/respond.py` | ✅ answers "is it over?" |
| Rule-based containment actions | `respond.suggested_actions()` | ✅ LLM-independent |
| Controlled remove-a-host experiment | `scripts/experiment_remove_host.py` | ✅ 8/8 → 3/8, nothing invented |
| Regression gate | `tests/test_chronopath2.py` | ✅ 12/12, 1.x numbers identical |

---

## 🧱 The attack we reconstruct (INC-01)

Modelled on the 2013 retail breach the brief references — one stolen vendor
login, ending in mass data theft.

| # | Stage | ATT&CK | What happened |
|---|---|---|---|
| 1 | Initial Access | T1078 | Vendor account `svc_vendor_hvac` logs into HR-07 from an external IP |
| 2 | Credential Access | T1110 | 35 failed logins against `admin_jane`, then success |
| 3 | Credential Access | T1003.001 | LSASS memory read — credential dumping |
| 4 | Privilege Escalation | T1136 | Backdoor account `svc_helpdesk_adm` created |
| 5 | Privilege Escalation | T1078.003 | Admin privileges assigned |
| 6 | Lateral Movement | T1021.002 | Backdoor account reaches file server FS-02 |
| 7 | Collection | T1005 | 45 files swept up on FS-02 |
| 8 | Exfiltration | T1041 | 250 MB sent to an external IP |

**Actual output:** 86 raw alerts merged into 8 detections, one incident, risk
**97.3/100**, and a look-ahead warning that **both domain controllers** are
within reach.

---

## 📂 Project layout

```
chronopath/
├── README.md              This file
├── SETUP.md               Install, run, troubleshoot
├── READTHIS.md            Learning guide — concepts, code tour, judge Q&A
├── requirements.txt       Pinned, all verified on Python 3.14.2
├── EDR_DATA.md            Working with the organisers' EDR generator
├── START_HERE.md          Beginner's guide — read this first
├── FIREX_RESULTS.md       Results on the real 6.5 GB FortiGate file
├── rules.yaml             Detection rules, flat format       (B-4)
├── rules_ecs.yaml         Detection rules, EDR generator ECS format
├── rules_fortigate.yaml   Detection rules, real FortiGate syslog
├── assets.yaml            Host/privilege inventory           (FR-6)
├── run_demo.py            Whole pipeline in one command
├── data/                  Generated logs + ground truth (gitignored)
├── docs/                                                        ← 2.0
│   ├── baseline_before_2.0.md  The 1.x numbers the gate protects
│   └── results_2.0.md          Every 2.0 measurement, with method
├── tests/
│   └── test_chronopath2.py     12 tests incl. the regression gate  ← 2.0
├── scripts/
│   ├── generate_sample.py Logs with a planted attack + answer key
│   ├── prepare_edr.py     Makes organisers' EDR output realistic
│   ├── discover_firex.py  Finds the planted attack by rarity analysis
│   ├── benchmark.py       Proves the streaming/memory claim
│   ├── evaluate.py        Scores the four PRD metrics
│   ├── build_coverage.py       Telemetry coverage + provenance    ← 2.0
│   ├── run_cp2.py              The whole 2.0 layer, one command   ← 2.0
│   └── experiment_remove_host.py  Controlled remove-a-host test   ← 2.0
└── src/
    ├── parser.py          DuckDB streaming detection    (FR-1, 2, 3)
    ├── ecs_adapter.py     Reads ECS JSON as flat
    ├── fortigate_adapter.py  Reads FortiGate syslog as flat
    ├── graph_engine.py    Correlation, path, look-ahead (FR-4, 5, 6)
    ├── pivot.py           Anomaly ranking + frequency timeline (hunting)
    ├── api.py             REST API, stdlib only         (FR-7)
    ├── app.py             Streamlit dashboard + Groq    (FR-5, 6, 7, B-1/2/3)
    └── chronopath2/            The 2.0 evidence & gap layer      ← 2.0
        ├── streams.py          Coverage + provenance   (Task 1)
        ├── blind_window.py     Did the blinding work?  (Task 2)
        ├── link_evidence.py    Graded links + raw lines (Task 3)
        ├── gaps.py             The gap ledger          (Task 4)
        └── respond.py          Indicators + containment (Task 5)
```

**Why 2.0 lives in its own package.** Ground rule 1 of the build was *do not
change detection, correlation or scoring behaviour.* The safest way to keep a
measured 100%/100%/0% engine at those numbers is not to edit it. The 2.0
modules read the finished incidents and write new `cp2_` tables, so rolling the
layer back is dropping tables — not restoring a backup.

Every file opens with a docstring explaining **why it exists**; key decisions are
commented inline.

---

## 🛠️ Tech stack — and what we rejected

| Tool | Job | Why this one |
|---|---|---|
| **DuckDB 2.0** | Scan 15 GB | Embedded, streams natively, reads NDJSON directly |
| **NetworkX 3.6** | Attack graph | Pure Python; `descendants()` answers FR-6 in one call |
| **Streamlit 1.66** | Dashboard | Browser UI, no HTML/JS/build step |
| **Groq** | Narrative | Free tier, fast, `openai/gpt-oss-120b` |
| **PyYAML** | Config | Makes B-4 trivial |

| Rejected | Why |
|---|---|
| Pandas | Loads everything into RAM — the exact failure mode to avoid |
| Elasticsearch | Needs a server and hours of setup; overkill here |
| Neo4j | A database server for a few hundred nodes |
| Spark | Built for clusters; pure overhead on one laptop |

**Total cost: ₹0.** No Docker, no cloud, no credit card.

---

## 🎤 Demo script — 3 minutes

1. **The problem (20 s).** Show the raw log volume. *"Three alerts. No analyst links these."*
2. **The scale proof (30 s).** Run `python scripts/benchmark.py` live.
   *"402 MB scanned, 323 MB of RAM — less than the file. We stream; we never load."*
3. **Detection (30 s).** Run `python run_demo.py`. Logs → 8 tagged events, 100% accuracy.
4. **The story (60 s).** Open the dashboard. Timeline, then the graph lighting up
   `svc_vendor_hvac → HR-07 → FS-02 → external IP`. Read the Groq paragraph.
5. **Look-ahead (30 s).** *"They are not done. This account has admin rights on
   both domain controllers and four more file servers. No SIEM told you that."*
6. **Hunting (20 s).** Open the **🔍 Threat hunting** tab, or run
   `python src/pivot.py`. *"And this found the same attackers with no rules at
   all — purely because they touch 1-3 things each while normal accounts touch
   hundreds. That catches the attack nobody wrote a rule for."*
7. **Close (10 s).** *"Runs on this laptop. Costs nothing. New rules are one YAML edit."*

**If Groq fails live:** keep going — the dashboard shows a built-in summary.
Detection and correlation are deterministic and offline. Saying so out loud
reads as engineering maturity.

### The 2.0 demo — 2 extra minutes, and the strongest part

Run `python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log` first.

1. **Evidence (30 s).** 🔗 **Evidence** tab on INC-01. *"Every link says why.
   This one is HARD because this event created the account that acts six
   minutes later — and here is the raw log line that proves it. The detections
   table only said 'Object attribute configured'; the account name was in the
   original record, so we fetch it."*
2. **The refusals (20 s).** Scroll to *Links we deliberately refused* and *Why
   INC-01 is separate.* *"Five incidents is itself a claim. We state what was
   compared: they share one value, the firewall, used by five accounts against
   a limit of three — so it's infrastructure, not an actor. The count is
   computed, not typed in."*
3. **The blinding that failed (40 s).** 🕳️ **What we can't see** on INC-02.
   *"The attacker turned off the firewall's logging. Most tools would tell you
   you're blind for two hours. We measured it: volume fell 24.2%, and the same
   hours on every other day fall 24.0%. That's the daily curve, not an
   attacker. 101,205 events still recorded — the policy purge was logged. The
   disable failed, which means this file is a forwarded copy."* Then point at
   the gap ledger: *"And zero of our fifteen gaps accuse anyone of deleting
   anything, because nothing here proves that."*
4. **The gap that matters (20 s).** `INC-01-GAP-LIFECYCLE`. *"The account
   existed for twelve minutes. We can see it created, used and deleted — and we
   cannot see what it did. So we say so, and we say treat persistence as
   unverified rather than absent. That's the first question a responder asks."*
5. **Respond now (20 s).** 🚨 tab. *"Indicators with first and last seen across
   the whole dataset, not just the incident — that's how you answer 'is it
   still over?'. And no brute-force burst before this login, which tells you
   the credential came from somewhere else."*
6. **The proof (30 s, if asked).** `python scripts/experiment_remove_host.py`.
   *"We deleted a host from the data. 1.x went from 8 of 8 steps to 3 of 8. And
   three new gaps appeared, naming the account that now has no origin. On the
   full data that gap correctly doesn't fire. Zero records of the removed host
   anywhere in the output — we don't invent what we can't see."*

**The line to close on:** *"Hayabusa tells you what fired. ChronoPath 1.x tells
you what happened. ChronoPath 2.0 tells you what you can prove, what you
can't, and what to do about it."*

---

## 🧭 Why the 15 GB tier

The PRD offers 15 GB (1.0×), 30 GB (1.3×) and 50 GB (1.6×). We took 15 GB
deliberately:

- The multiplier is **accuracy-gated** — *"fast but sloppy does not win."*
- The PRD guarantees **the same planted attacks at every tier**, so there is no
  detection advantage in going bigger.
- 50 GB needs ~110 GB of free disk once spill and database are counted.
- The architecture is tier-agnostic: only the `--input` path changes. At the
  measured throughput, 50 GB would be under a minute of scan time.

---

## ⚠️ Known limitations

Stated plainly, because judges ask and honesty scores better than bluffing:

- **Rule-based detection misses novel attacks.** Any rule engine does. Mitigated
  by rules-as-config (new rule = YAML edit) and rule-agnostic correlation.
- **`assets.yaml` is declared, not discovered.** It stands in for Active
  Directory/BloodHound. Logs record what *did* happen, not what is *permitted* —
  that gap is exactly why the look-ahead needs an identity source.
- **Correlation window is a tuned constant** (120 min). Too small fragments an
  attack; too large merges unrelated activity.
- **The ground truth for the real file is reconstructed, not supplied.** The
  organisers gave us `firex-10G.log` without an answer key, so we derived one by
  querying for the rarest security-relevant events — 14 of 9,125,382. The
  derivation is reproducible (`scripts/discover_firex.py`) and documented, but
  "100% detection" means *100% of the attack we identified as planted*. If their
  key includes something our rarity analysis missed, that number would change.
- **Run on 6.54 GB, not the full 15 GB tier.** The memory behaviour is flat and
  measured, so 15 GB should cost more time and not more memory — but that is an
  extrapolation, not a measurement.

### 2.0-specific limitations

- **The blind-window control needs several days of data.** It compares the same
  clock hours on other days; on a file spanning less than about two days there
  is no control, and the check honestly returns `COVERAGE_UNKNOWN` rather than
  guessing.
- **Raw-line evidence costs a full file scan** (34 s on 6.54 GB) and matches on
  timestamp + account. That is specific enough on this data, where the planted
  events are the rarest records in the file, but a busier account could match
  more lines than intended.
- **The gap ledger knows what it was told to look for.** It reports absent
  telemetry *types* and unexplained actors. A category of absence nobody
  anticipated would still be missed — the remove-host experiment exists
  precisely because we found one such case in our own first version.
- **Evidence requests name artefact classes, not systems.** "Identity-provider
  audit log" is correct and actionable; it cannot know whether that means Entra
  ID, Okta or a local directory.

---

*Built for CyberForge 2026 · Mitigata · Stack cost: ₹0*
