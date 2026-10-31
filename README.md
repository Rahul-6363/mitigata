# 🕸️ ChronoPath — Kill Chain & Attack Path Analysis

**CyberForge Hackathon by Mitigata · 31 Oct – 1 Nov 2026**
**Problem:** Kill Chain and Attack Path Analysis
**Tier chosen: Core (15 GB) · 1.0× multiplier**

[![Stack](https://img.shields.io/badge/Stack-Python%203.14%20%7C%20DuckDB%202.0%20%7C%20NetworkX%203.6-success.svg)]()
[![LLM](https://img.shields.io/badge/GenAI-Groq%20Free%20Tier-orange.svg)]()
[![Verified](https://img.shields.io/badge/Benchmark-1030%20MB%2Fs%20%40%20300MB%20RAM-blue.svg)]()

---

## 📌 Read this first — decisions already made and verified

Everything in this README was **tested on the actual demo machine** (16 GB RAM, 5-core
Dell, Windows 11, Python 3.14.2) before being written down. Numbers quoted are measured,
not estimated. Where something is an extrapolation, it says so.

| Decision | Choice | Why |
|---|---|---|
| **Data tier** | **15 GB (Core)** | See "Why 15 GB" below — it is the *only* tier that fits the demo box safely. |
| Language | Python 3.14.2 | Team knows Python; whole stack verified to install on it. |
| Scan engine | DuckDB 2.0.0 | Streams from disk. **Measured 1030 MB/s at 300 MB peak RAM.** |
| Graph | NetworkX 3.6.1 | Pure Python, no server, no Docker, no Neo4j licence. |
| UI | Streamlit 1.66.1 + streamlit-agraph | Browser UI in ~40 lines. |
| Narrative | Groq free API | `llama-3.3-70b-versatile` — confirmed live on Groq's model list. |
| Cost | **₹0** | Every component is free/open-source. No cloud, no card. |

---

## 🎯 Why 15 GB and not 30 or 50

The PRD offers 15 GB (1.0×), 30 GB (1.3×) and 50 GB (1.6×) score multipliers. **Take 15 GB.**
This is a deliberate trade, and here is the honest arithmetic:

- The multiplier is **gated on accuracy**. The PRD states plainly: *"a bigger tier earns more
  only if accuracy stays above the minimum bar. Fast but sloppy does not win."* A 1.6× on a
  broken run scores less than 1.0× on a clean one.
- **Disk, not RAM, is the binding constraint.** The 50 GB tier needs ~50 GB free plus spill
  space plus the DuckDB database — realistically 110 GB+ free on the laptop. Most dev laptops
  do not have that spare.
- **You have ~26 hours**, not a week. Every hour spent fighting a 50 GB download is an hour
  not spent on detection accuracy, which is what is actually scored.
- The PRD guarantees: *"every tier has the same formats and the same planted attack
  sequences."* **The attacks you must find are identical at 15 GB.** You lose nothing in
  detection quality by picking the smallest tier.

> **The winning play:** nail 15 GB with excellent accuracy and a clean demo. Then, if the
> architecture holds (it is tier-agnostic — only a file path changes), mention to judges that
> the measured 1030 MB/s throughput means 50 GB would finish in ~50 s of scan time. You get
> credit for the engineering without betting the demo on it.

---

## 🧪 Benchmark — measured on this laptop, not guessed

The central technical claim of this project is *"we process more data than we have RAM."*
That claim was tested before writing it down, because an unverified claim in front of judges
is a liability.

**Method:** generated a 360 MB newline-delimited JSON log file (1.2 M synthetic events),
capped DuckDB at a hard `memory_limit='1GB'`, and ran a real brute-force detection query
(filter + `GROUP BY` + `HAVING`) while sampling process RSS.

```
scanned_MB      360
elapsed_s       0.3
peak_RSS_MB     300        <- stayed under the 1 GB cap
throughput      1030 MB/s
result          top brute-force pairs returned correctly
```

**What this proves:** DuckDB never loaded the file into memory. It streamed it. Peak RSS
(300 MB) was *smaller than the file* (360 MB), which is only possible with streaming
execution.

**Extrapolated to the real tier:** 15 GB ÷ 1030 MB/s ≈ **~15 seconds of raw scan time**.
Even allowing a 20–50× slowdown for cold disk I/O, richer rules and JSON type-inference on
real data, this lands far inside the PRD's "Great" bar of **under 1 hour**, using a fraction
of the 8 GB "Great" memory bar.

⚠️ *Honest caveat:* this was synthetic data on warm cache. Real 15 GB logs on a spinning
disk will be slower and dominated by disk read speed, not CPU. The memory behaviour —
the part that decides whether the demo crashes — is the part that generalises.

### Reproduce it yourself
Run this after `pip install -r requirements.txt` to confirm on your own hardware:
```bash
python scripts/benchmark.py
```

---

## 🧠 How it works — the core insight

A 15 GB log file will not fit in a 16 GB laptop's RAM, and a graph of 15 GB of events will
not fit either. **ChronoPath separates the two problems:**

```
15 GB raw logs on disk
        │
        │  ❶ DuckDB streams it — never loads it all.
        │     SQL rules filter 15 GB ──▶ a few thousand suspicious rows (~ MB).
        ▼
  suspicious_events  (small, tagged with MITRE + kill chain stage)
        │
        │  ❷ NetworkX builds the graph from the SMALL set — fits in RAM easily.
        ▼
  Attack path + look-ahead
        │
        │  ❸ Groq writes the plain-English report.
        ▼
  Streamlit dashboard
```

**The trick:** the expensive thing (15 GB) is handled by a streaming SQL engine that is
designed for it. The clever thing (graph reasoning) is handled by a graph library, but only
after the data has been reduced ~10,000× to a size that trivially fits in memory. Neither
tool is asked to do the other's job. This is why it runs on a laptop.

---

## 🗂️ Mapping to the PRD requirements

Every "must have" is assigned to a specific file, so nothing is missed.

| ID | Requirement | Where it is implemented |
|---|---|---|
| **FR-1** | Read full data set without loading into memory | `src/parser.py` — DuckDB streaming scan ✅ *benchmarked above* |
| **FR-2** | Detect suspicious events | `src/parser.py` + `rules.yaml` |
| **FR-3** | Map to MITRE ATT&CK + kill chain stage | `rules.yaml` (every rule carries both tags) |
| **FR-4** | Link events into one incident by host/user/IP/time | `src/graph_engine.py` — correlation + time window |
| **FR-5** | Show attack path as timeline **and** graph | `src/app.py` — agraph view + timeline table |
| **FR-6** | Show what the attacker could reach next | `src/graph_engine.py::look_ahead()` ✅ *logic validated* |
| **FR-7** | Simple API or page + short README | `src/app.py` + this file |

### Bonus items targeted
| ID | Feature | Plan |
|---|---|---|
| **B-1** | Risk score per incident | Weighted sum of stage severity × event count → sort incidents |
| **B-2** | Auto-written plain-English report | Groq LLM (`src/app.py`) |
| **B-3** | Count of raw alerts merged per incident | Carried as an incident attribute |
| **B-4** | New rule via config file, not code | `rules.yaml` — **this is why rules are SQL-in-YAML** |
| B-5 | Live mode | *Stretch only. Skip unless everything else is done and demoed.* |

> **Scope discipline:** B-1 to B-4 are nearly free given the architecture. **B-5 (live mode)
> is a trap** — it is the most work for the fewest points and risks the core demo. Leave it.

---

## 🧱 The attack we are telling — INC-01

The hackathon framing references a **2013 retail breach: one stolen vendor login, weeks of
ignored alerts, up to 110 million customers affected.** This is the Target breach, and it is
the narrative spine of the demo. The kill chain to reconstruct:

| # | Stage | What it looks like in logs | ATT&CK |
|---|---|---|---|
| 1 | Initial Access | Vendor account logs in from an unusual IP | T1078 Valid Accounts |
| 2 | Credential Access | Many failed logins, then one success | T1110 Brute Force |
| 3 | Privilege Escalation | New admin account created / admin rights used | T1136 Create Account |
| 4 | Lateral Movement | That account reaches a file server it never touched before | T1021 Remote Services |
| 5 | Collection | Unusual access to many files on the server | T1005 Data from Local System |
| 6 | Exfiltration | Large outbound transfer to an external IP | T1041 Exfiltration over C2 |

**The money shot for judges:** six alerts that any SIEM would show as six unrelated rows,
rebuilt into one sentence — *"A stolen vendor login on HR-07 reached file server FS-02 and
sent 4 GB to an external IP; this account can still reach DC-01 and 3 more servers."*

---

## 📂 Project structure to build

```text
chronopath/
├── README.md                 # this file
├── requirements.txt          # pinned, all verified on Python 3.14
├── rules.yaml                # detection rules as config (Bonus B-4)
├── data/
│   └── sample.ndjson         # 100 MB dev sample from kickoff
├── scripts/
│   ├── generate_sample.py    # makes fake logs w/ a planted attack, for offline dev
│   └── benchmark.py          # reproduces the memory/throughput numbers above
└── src/
    ├── parser.py             # DuckDB: stream 15 GB -> tagged suspicious_events
    ├── graph_engine.py       # NetworkX: correlate -> path -> look-ahead
    └── app.py                # Streamlit UI + Groq narrative
```

---

## 🤖 Instructions for the AI coding agent

**Every Python file must carry `# [JUDGE EXPLANATION]` comments** explaining *why* the code
is written that way — the memory constraint it respects, and the FR-number it satisfies. The
team must be able to read any file and explain it aloud to a judge. Write comments for a
smart reader who has never seen the codebase.

Also open each file with a short docstring: **what this file does, and why it exists.**

### File 1 · `requirements.txt`
Pin the versions **verified to install on Python 3.14.2**:
```
duckdb==2.0.0
networkx==3.6.1
streamlit==1.66.1
streamlit-agraph==0.0.45
pyyaml
groq==1.7.0
psutil            # used by benchmark.py to measure peak RSS
```
> `streamlit-agraph` 0.0.45 is old and unmaintained but **was tested and imports cleanly**
> against Streamlit 1.66.1. If it ever breaks, fall back to `st.graphviz_chart` — keep the
> graph-drawing call behind one small function so the swap is a two-line change.

### File 2 · `rules.yaml`
Satisfies **B-4**: a new detection must be addable *without touching Python*.

Each rule carries `name`, `mitre_technique`, `mitre_name`, `kill_chain_stage`, `severity`
(1–10, feeds the B-1 risk score), and a `sql_condition` — a SQL `WHERE` fragment that DuckDB
pushes down into the streaming scan.

Write **at least 6 rules covering the full INC-01 chain above**, not 3 — detection recall is
directly scored (>70% Good, >90% Great). Include rules that need aggregation (brute force =
`count(*) >= N grouped by host,user`) as well as simple row filters; mark which is which with
a `type: aggregate | row` field so the parser knows how to run it.

⚠️ **Security note:** these SQL fragments are interpolated into queries. That is acceptable
*only* because `rules.yaml` is a trusted local config the team authors. Add a comment saying
so, so no one later exposes it to user input.

### File 3 · `src/parser.py`
The data cruncher. Must:
1. Load `rules.yaml`.
2. Connect DuckDB and **immediately** set the guard rails:
   ```python
   con.execute("SET memory_limit='8GB'")        # stay under the PRD 'Great' bar
   con.execute("SET temp_directory='./tmp_spill'")  # allow disk spill, never OOM
   con.execute("SET preserve_insertion_order=false") # lets DuckDB stream freely
   ```
   `[JUDGE EXPLANATION]`: these three lines are what make 15 GB on 16 GB RAM safe.
   `preserve_insertion_order=false` matters — it frees the engine to process out of order
   and keeps memory flat on big scans.
3. Read with **`read_ndjson`** and an **explicit `columns={...}` schema**.
   `[JUDGE EXPLANATION]`: an explicit schema skips type-inference sampling, which is both
   faster and avoids a whole class of "column changed type halfway through the file" errors
   on a 15 GB file. This was the exact form used in the benchmark.
4. Apply each rule, tagging matched rows with technique + stage + severity.
5. Write results to a **persistent DuckDB file** (`chronopath.db`), table `suspicious_events`.
   `[JUDGE EXPLANATION]`: persisting means the UI opens an incident in **milliseconds**
   without rescanning — that is the PRD's "under 500 ms investigation speed" target.
6. Print progress and a final count. Judges like seeing it work.

### File 4 · `src/graph_engine.py`
Takes the small suspicious set and makes it a story. Must:
1. Query `suspicious_events` from `chronopath.db`.
2. Build an `nx.DiGraph` with nodes for users, hosts and IPs; edges for actions, each edge
   carrying `timestamp`, `technique`, `stage`.
3. **Correlate into incidents (FR-4):** group events into one incident when they share a
   host, user or IP **and** fall within a time window (make the window a constant, e.g.
   `CORRELATION_WINDOW_MINUTES = 60`, and comment why it is tunable).
4. `get_attack_path(incident)` → ordered steps, **sorted by timestamp**.
   `[JUDGE EXPLANATION]`: ordering by time is what turns a set of alerts into a *kill chain*;
   the PRD scores "right steps in the right order".
5. `look_ahead(node)` → `nx.descendants()` for everything reachable from a compromised node.
   `[JUDGE EXPLANATION]`: a graph traversal answers "where can they go next" in one call;
   the SQL equivalent is an unbounded chain of self-joins. ✅ *This logic is validated —
   on a test graph it correctly returned `['DC-01','FS-09','FS-11']` as reachable from a
   compromised `FS-02`.*
6. `risk_score(incident)` for **B-1**, and carry `raw_alert_count` for **B-3**.

> Guard against cycles: real logs produce loops (A→B→A). Use `nx.descendants()` (cycle-safe)
> rather than hand-rolled recursion, and never assume the graph is a DAG.

### File 5 · `src/app.py`
The Streamlit dashboard. Must:
1. Sidebar to run the pipeline and pick an incident, **sorted by risk score** (B-1).
2. **Timeline view** — ordered table: time, host, user, technique, stage (FR-5).
3. **Graph view** — `streamlit-agraph`; compromised nodes **red**, look-ahead nodes
   **yellow**, clean nodes grey. Add a legend; judges should not have to ask.
4. **Look-ahead panel** — plain text: *"This account can still reach DC-01 and 3 more servers."*
5. **Groq narrative (B-2):**
   - Read the key with `os.environ.get("GROQ_API_KEY")`. **Never hardcode it.**
   - Model: **`llama-3.3-70b-versatile`** (confirmed on Groq's production model list
     31 Oct 2026). Fallback: `llama-3.1-8b-instant`, also production.
   - Prompt: *"You are a SOC analyst. Summarise this MITRE-tagged attack path as a short
     plain-English incident report: where it started, what the attacker did, and what they
     can reach next. Be concise and factual."*
   - **Wrap the call in `try/except` and cache the result.** If the network or the key fails
     mid-demo, show a pre-written summary instead of a stack trace.
     `[JUDGE EXPLANATION]`: the LLM writes the *narration*; the detection and graph are
     deterministic and work offline. Say this out loud to judges — it shows the AI is not
     load-bearing for correctness.

### File 6 · `scripts/generate_sample.py`
Makes a synthetic NDJSON log file with the **INC-01 attack deliberately planted** inside
noise. This matters more than it sounds: it lets the team build and test detection *before*
the real data finishes downloading, and gives a known ground truth to measure recall against.

### File 7 · `scripts/benchmark.py`
Reproduces the memory/throughput table above: generate volume, cap `memory_limit`, sample
peak RSS with `psutil` in a background thread, print MB/s and peak MB. **This is a demo
asset** — run it live to prove the memory claim instead of asserting it.

---

## 🚀 Running it

```bash
# 1 · install (verified on Python 3.14.2)
pip install -r requirements.txt

# 2 · free Groq key from https://console.groq.com  (no card needed)
#    PowerShell:
$env:GROQ_API_KEY="gsk_your_key_here"
#    CMD:        set GROQ_API_KEY=gsk_your_key_here
#    bash:       export GROQ_API_KEY=gsk_your_key_here

# 3 · make dev data (while the real tier downloads)
python scripts/generate_sample.py

# 4 · prove the memory claim
python scripts/benchmark.py

# 5 · run detection over the logs
python src/parser.py --input data/sample.ndjson

# 6 · dashboard
streamlit run src/app.py
```

---

## ⏱️ 26-hour plan (31 Oct → 1 Nov)

Build in this order. **Each stage ends with something demoable**, so if time runs out you
always have a working product rather than a half-finished better one.

| Block | Goal | Done when |
|---|---|---|
| **H0–2** | Scaffold + `generate_sample.py` + `rules.yaml` | Fake logs exist with a planted attack |
| **H2–6** | `parser.py` — streaming scan + tagging | Suspicious events table populates ✅ *core tech already proven* |
| **H6–10** | `graph_engine.py` — correlate, path, look-ahead | Printing a correct ordered attack path |
| **H10–14** | `app.py` — timeline + graph + legend | **A demoable product exists. Lock this in.** |
| **H14–17** | Groq narrative (B-2), risk score (B-1), merge count (B-3) | Bonuses land |
| **H17–20** | Run on the **real 15 GB tier**; tune rules for recall | Real data processed end-to-end |
| **H20–23** | Measure accuracy vs ground truth; cut false positives | Numbers you can quote |
| **H23–26** | Rehearse demo, write the one-slide story, buffer | Demo runs twice without a hitch |

**Do not** start B-5 live mode. **Do not** switch to 30/50 GB midway. Protect H10–14.

---

## 🎤 Demo script — 3 minutes

1. **The problem (20 s).** Show raw log volume. *"Six separate alerts. No analyst links these."*
2. **The scale proof (30 s).** Run `benchmark.py` live. *"1030 MB/s, 300 MB of RAM. We stream;
   we never load."* ← strongest technical moment, and it is measured.
3. **The detection (30 s).** Run the parser. 15 GB → a handful of tagged events.
4. **The story (60 s).** Open the incident: timeline, then the graph lighting up
   vendor → HR-07 → FS-02 → DC-01. Read the Groq paragraph aloud.
5. **The look-ahead (30 s).** Highlight yellow nodes. *"They are not done — this account can
   still reach three more servers. That is the part no SIEM told you."*
6. **Close (10 s).** *"Runs on this laptop. Costs nothing. New rules are one YAML edit."*

**If the Groq call fails live:** keep talking, show the cached summary. Detection and graph
are deterministic and offline — say so; it reads as engineering maturity, not an excuse.

---

## 📺 Learning resources

Short, relevant, watch at 1.5×. Search these titles on YouTube — links rot, titles do not.

**Concepts first (watch H0, ~25 min total)**
| Topic | Search for | Why |
|---|---|---|
| Kill chain | *"Cyber Kill Chain Explained"* — Gerald Auger / Simply Cyber | The 7 stages you are labelling |
| MITRE ATT&CK | *"MITRE ATT&CK Framework Explained in 10 Minutes"* | Techniques vs tactics — the T-numbers |
| The real breach | *"Target Data Breach Explained"* | INC-01 is this breach; know the story you are telling |
| SIEM basics | *"What is a SIEM?"* — IBM Technology | Why linking alerts is the hard part |

**Tools (watch as you build)**
| Topic | Search for | When |
|---|---|---|
| DuckDB | *"DuckDB in 100 Seconds"* (Fireship), then *"DuckDB Python tutorial"* | Before `parser.py` |
| Larger-than-memory | *"DuckDB out of core / larger than memory processing"* | Understand what you benchmarked |
| NetworkX | *"NetworkX Python Tutorial"* / *"Graph Theory in Python"* | Before `graph_engine.py` |
| Streamlit | *"Streamlit in 100 Seconds"* + *"Streamlit crash course"* | Before `app.py` |
| Groq | *"Groq API Python tutorial"* | Before the narrative step |
| Sigma rules | *"Sigma Rules Explained"* | Context for why rules live in YAML |

**Official docs (better than videos for exact syntax)**
- DuckDB JSON loading — `duckdb.org/docs/stable/data/json/loading_json`
- DuckDB memory management — `duckdb.org/2024/07/09/memory-management`
- NetworkX `descendants` / `all_simple_paths` — `networkx.org/documentation/stable`
- Groq models & limits — `console.groq.com/docs/models`
- MITRE ATT&CK matrix — `attack.mitre.org`

---

## ⚠️ Risks and how we handle them

| Risk | Mitigation |
|---|---|
| 15 GB download is slow / late | `generate_sample.py` lets all development proceed offline against planted ground truth |
| Groq key or network fails on stage | Cached summary + `try/except`; detection is deterministic and offline |
| `streamlit-agraph` breaks (old package) | Verified working today; graph call isolated behind one function, `st.graphviz_chart` fallback |
| Too many false positives | False-alarm rate is explicitly scored (<30% Good, <10% Great). Tune thresholds in H20–23; prefer precision over recall when forced to choose |
| Scope creep into B-5 | Explicitly out of scope. Protect the H10–14 demoable build |
| Disk fills from spill files | `tmp_spill/` is gitignored; check free space before the real run |

---

## ✅ What has been verified on the demo machine

Stated plainly so no one re-litigates settled questions:

- ✅ Python 3.14.2 present
- ✅ `duckdb 2.0.0`, `networkx 3.6.1`, `streamlit 1.66.1`, `groq 1.7.0`, `pyyaml`,
  `streamlit-agraph 0.0.45`, `psutil` — **all install and import cleanly**
- ✅ DuckDB streams 360 MB at **1030 MB/s with 300 MB peak RSS** under a hard 1 GB cap
- ✅ Detection SQL (filter → `GROUP BY` → `HAVING`) returns correct brute-force pairs
- ✅ NetworkX path reconstruction and `descendants()` look-ahead both behave correctly
- ✅ `llama-3.3-70b-versatile` and `llama-3.1-8b-instant` are **current production models**
  on Groq (checked against Groq's own docs, 31 Oct 2026 — contradicting several blog posts
  claiming they were deprecated)
- ⬜ Groq API call not yet executed — **no API key on the machine yet.** Add the key and run
  step 2 of the demo once before presenting.
- ⬜ Real 15 GB tier not yet processed — numbers above are measured at 360 MB and
  extrapolated.

---

*Built for CyberForge 2026 · Mitigata · Stack cost: ₹0*
