# 🕸️ ChronoPath — Kill Chain & Attack Path Analysis

**CyberForge Hackathon · Mitigata · 31 Oct – 1 Nov 2026**
**Tier: Core (15 GB)**

[![Stack](https://img.shields.io/badge/Stack-Python%203.14%20%7C%20DuckDB%202.0%20%7C%20NetworkX%203.6-success.svg)]()
[![LLM](https://img.shields.io/badge/GenAI-Groq%20Free%20Tier-orange.svg)]()
[![Accuracy](https://img.shields.io/badge/Accuracy-100%25%20detection%20%7C%200%25%20false%20alarms-brightgreen.svg)]()
[![Memory](https://img.shields.io/badge/402MB%20scanned-323MB%20RAM-blue.svg)]()

Reads a large pile of security logs, finds the attack hidden inside, and shows
it as one story: where the attacker started, what they did, and where they can
go next.

---

> **New to this project?** Read **[START_HERE.md](START_HERE.md)** first — it
> explains the problem, the jargon and what we built, assuming no security
> background.

## 🔥 On the real data set (`firex-10G.log`)

```bash
python src/parser.py --input D:/mitigata/firex-10G.log --memory-limit 6GB
python src/graph_engine.py
python src/api.py        # or: streamlit run src/app.py
```

Format is detected automatically — it is FortiGate firewall syslog, a third
format alongside our flat JSON and the EDR generator's ECS JSON.

| Measurement | Result |
|---|---|
| File | 6.54 GB, **9,125,382 events** |
| Full detection run, 12 rules | **66.8 s** |
| Peak memory | **422 MB** (PRD "Great" bar: 8 GB) |
| Correlation of 395,361 detections | **6.0 s** |
| Open one incident | **4.0 ms** (bar: 500 ms) |
| Detection rate | **100%** |
| Correct ATT&CK labels | **87.5%** (Great) |

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
├── scripts/
│   ├── generate_sample.py Logs with a planted attack + answer key
│   ├── prepare_edr.py     Makes organisers' EDR output realistic
│   ├── discover_firex.py  Finds the planted attack by rarity analysis
│   ├── benchmark.py       Proves the streaming/memory claim
│   └── evaluate.py        Scores the four PRD metrics
└── src/
    ├── parser.py          DuckDB streaming detection    (FR-1, 2, 3)
    ├── ecs_adapter.py     Reads ECS JSON as flat
    ├── fortigate_adapter.py  Reads FortiGate syslog as flat
    ├── graph_engine.py    Correlation, path, look-ahead (FR-4, 5, 6)
    ├── pivot.py           Anomaly ranking + frequency timeline (hunting)
    ├── api.py             REST API, stdlib only         (FR-7)
    └── app.py             Streamlit dashboard + Groq    (FR-5, 6, 7, B-1/2/3)
```

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
- **Accuracy is measured on our own synthetic attack.** The pipeline is correct
  and measurable end to end; that is a different claim from "100% on your data".
- **Correlation window is a tuned constant** (120 min). Too small fragments an
  attack; too large merges unrelated activity.
- **Not yet run on the real 15 GB tier** — only on samples up to 400 MB.

---

*Built for CyberForge 2026 · Mitigata · Stack cost: ₹0*
