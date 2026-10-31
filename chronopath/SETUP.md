# SETUP — Getting ChronoPath running from scratch

Everything here was performed on the actual demo machine (Windows 11, Python
3.14.2, 16 GB RAM, Dell 5-core) before being written down. Total setup time is
about **five minutes**, and the only thing requiring the internet is installing
packages and getting the free Groq key.

---

## 0 · What you need before you start

| Requirement | Why | How to check |
|---|---|---|
| **Python 3.10+** (3.14.2 verified) | Everything is Python | `python --version` |
| **~2 GB free disk** for the demo | Logs + database + spill files | — |
| **~40 GB free disk** for the real 15 GB tier | Logs, DB and spill space | — |
| **Internet, once** | Install packages, get Groq key | — |
| **A Groq API key** (free, optional) | AI-written report (bonus B-2) | See step 3 |

> **No Docker, no database server, no cloud account, no credit card.** DuckDB is a
> file, NetworkX is a library, Streamlit is a local web server. Total cost: ₹0.

If `python` is not recognised on Windows, install from
[python.org/downloads](https://www.python.org/downloads/) and **tick "Add Python
to PATH"** on the first screen. That checkbox is the single most common setup
failure.

---

## 1 · Get the code and create a virtual environment

A virtual environment keeps these packages separate from the rest of your
system, so nothing you install here can break another project.

**Windows (PowerShell)**
```powershell
cd chronopath
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell refuses with *"running scripts is disabled on this system"*, run
this once and try again:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**macOS / Linux**
```bash
cd chronopath
python3 -m venv .venv
source .venv/bin/activate
```

You will know it worked when your prompt is prefixed with `(.venv)`.

---

## 2 · Install the dependencies

```bash
pip install -r requirements.txt
```

This pulls in six packages (about 150 MB, mostly Streamlit's frontend). The
attack graph uses Graphviz, which ships inside Streamlit:

| Package | Version | What it does here |
|---|---|---|
| `duckdb` | 2.0.0 | Streams the 15 GB log file without loading it into RAM |
| `networkx` | 3.6.1 | Builds the attack graph and computes reachability |
| `streamlit` | 1.66.1 | The browser dashboard |
| `pyyaml` | latest | Reads `rules.yaml` and `assets.yaml` |
| `groq` | 1.7.0 | Calls the free LLM API for the written report |
| `psutil` | latest | Measures peak memory in the benchmark |

**Verify the install:**
```bash
python -c "import duckdb, networkx, streamlit, yaml, groq, psutil; print('all good')"
```

---

## 3 · Get a free Groq API key *(optional but recommended)*

This powers the auto-written incident report (bonus B-2). **The tool works
without it** — it falls back to a built-in summary — so do not let this block you.

1. Go to **[console.groq.com](https://console.groq.com)**
2. Sign up (Google or email; **no credit card**)
3. **API Keys** → **Create API Key** → copy it (starts with `gsk_`)

Then give the key to ChronoPath. **Two ways — the first is recommended.**

### Option A — a `.env` file (persistent, recommended)

Create a file called **`.env`** in the `chronopath/` folder (next to
`README.md`) containing one line:

```
GROQ_API_KEY=gsk_your_key_here
```

There is a template to copy: `.env.example`. The app reads this automatically at
startup, so **you only do it once** — it survives closing the terminal,
restarting Streamlit and rebooting.

> `.env` is in `.gitignore` and will not be committed. `.env.example` (the
> template, with no real key) is committed on purpose.

### Option B — an environment variable (temporary)

Faster to type, but **lasts only for that one terminal window.** Open a new
window and you must set it again — an easy thing to forget right before a demo.

**PowerShell**
```powershell
$env:GROQ_API_KEY = "gsk_your_key_here"
```

**Windows CMD**
```cmd
set GROQ_API_KEY=gsk_your_key_here
```

**macOS / Linux**
```bash
export GROQ_API_KEY="gsk_your_key_here"
```

If both are present, the environment variable wins.

**How to tell it worked:** the Streamlit sidebar shows
`Groq API key: detected ✅`. If it says `not set ⚠️`, the dashboard still works
and shows a built-in summary instead.

**Confirm it is set:**
```powershell
# PowerShell
echo $env:GROQ_API_KEY
```
```bash
# bash
echo $GROQ_API_KEY
```

> ⚠️ **Never paste the key into a source file.** The code reads it from the
> environment only. A key committed to git is a leaked key.

**Model used:** `openai/gpt-oss-120b`, with `openai/gpt-oss-20b` and
`qwen/qwen3.8-27b` as automatic fallbacks. All three were verified working
against a real free-tier key on 31 Oct 2026.

> ⚠️ **Do not switch this to a Llama model without testing it first.** Groq's
> public documentation lists `llama-3.3-70b-versatile` as a production model,
> but calling it with an actual free-tier key returns **404 — "model does not
> exist or you do not have access to it"**. Asking the key itself
> (`client.models.list()`) shows no Llama chat models on the free tier at all.
> The only trustworthy model list is the one your own key returns:
>
> ```bash
> python -c "from groq import Groq; print([m.id for m in Groq().models.list().data])"
> ```

Free tier is rate-limited (roughly 30 requests/minute), far more than a demo
needs.

---

## 4 · Run it

### Fastest path — the whole pipeline in one command
```bash
python run_demo.py
```
This generates 50 MB of logs with an attack planted inside, detects it,
correlates it into an attack path, and scores accuracy against ground truth.
Takes about 15 seconds.

### Then open the dashboard
```bash
streamlit run src/app.py
```
Your browser opens at `http://localhost:8501`. Pick an incident in the sidebar
and explore the four tabs.

> If `streamlit` is not found as a command, use `python -m streamlit run src/app.py`.

### Or use the REST API (FR-7)

```bash
python src/api.py            # http://localhost:8000
python src/api.py --port 9000
```

| Endpoint | Returns |
|---|---|
| `GET /` | index of endpoints |
| `GET /incidents` | all incidents, worst first |
| `GET /incidents/1` | one incident in full |
| **`GET /incidents/1/path`** | **the attack path — the PRD's worked example** |
| `GET /incidents/1/graph` | nodes and edges |
| `GET /incidents/1/next` | what the attacker could reach next |
| `GET /incidents/1/report` | plain-English summary |
| `GET /pivot` | entities ranked by anomaly — threat hunting |
| `GET /timeline` | detections per hour |
| `GET /stats` | corpus summary |
| `GET /metrics` | timing vs the PRD investigation-speed target |

**ChronoPath 2.0 endpoints** (run `scripts/run_cp2.py` first):

| Endpoint | Returns |
|---|---|
| **`GET /evidence/1`** | **why each pair of events was linked, graded, plus the links we refused** |
| **`GET /gaps/1`** | **what the data cannot show: basis, impact, evidence to request** |
| `GET /separation` | for every pair of incidents, why they are not one incident |
| `GET /indicators/1` | indicators with first/last seen across the whole data set |
| `GET /sources` | provenance: SHA-256, format, time range, clock check, streams |

Ids are tolerant — `/gaps/1`, `/gaps/INC-01` and `/gaps/inc-1` all work.

```bash
curl http://localhost:8000/incidents/1/path
curl http://localhost:8000/metrics      # measured 4.0 ms; "Great" bar is 500 ms
curl http://localhost:8000/evidence/1   # the Rakes -> svc_backup30 identity pivot
curl http://localhost:8000/gaps/1       # what we cannot tell you about INC-01
```

The API uses only the Python standard library, so it adds no dependencies and
cannot fail to import during a demo. Run it alongside the dashboard — they read
the same database.

---

## 5 · Run the steps individually

Useful while developing, and for explaining each stage to judges.

```bash
# 1. Make test logs with a known attack inside (and the answer key)
python scripts/generate_sample.py --size-mb 50

# 2. Stream the logs, apply rules.yaml, write suspicious events to DuckDB
python src/parser.py --input data/sample.ndjson

# 3. Correlate into incidents and print the attack path
python src/graph_engine.py

# 4. Score accuracy against the planted ground truth
python scripts/evaluate.py

# 5. Prove the memory claim
python scripts/benchmark.py
```

---

## 6 · Running on the real data set

Nothing in the code changes — only the input path and, optionally, the memory cap.
The format is auto-detected (FortiGate syslog, ECS JSON, or flat JSON).

### The organisers' `firex-10G.log` — the full run, as measured

```bash
# 1. Detection: 6.54 GB, 9,125,382 events -> 373,061 detections  (~99 s, 813 MB)
python src/parser.py --input D:/firex-10G.log --db firex.db --memory-limit 6GB

# 2. The ChronoPath 2.0 evidence layer: coverage, links, gaps, indicators (~51 s)
python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log

# 3. Score it against the reconstructed ground truth
python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json
#    -> 100% detection / 100% labels / 0% false alarms, 5 incidents

# 4. Look at it
streamlit run src/app.py        # 9 tabs
python src/api.py               # or the REST API
```

**Note the `--db firex.db`.** Each input gets its own database so runs cannot
overwrite each other. The dashboard and API open the **most recently written**
database automatically, or you can be explicit:

```bash
CHRONOPATH_DB=firex.db streamlit run src/app.py      # bash
$env:CHRONOPATH_DB="firex.db"; streamlit run src/app.py   # PowerShell
```

### The 2.0 layer, step by step

`run_cp2.py` does all of this in the right order, but the steps work alone:

```bash
# Coverage + provenance only (Task 1): 12 streams, SHA-256, the clock check
python scripts/build_coverage.py --input D:/firex-10G.log --db firex.db

# The controlled experiment (Task 6): remove a host, measure the degradation
python scripts/experiment_remove_host.py

# The test suite, including the regression gate
python tests/test_chronopath2.py
```

**Order matters** if you run them by hand: `build_coverage.py` must come before
the gap ledger, because the blind-window check reads its volume table and the
gap ledger reads its fingerprint. `run_cp2.py` exists so you do not have to
remember that.

### Scaling to the full 15 GB tier

**Before you start a 15 GB run, check three things:**

1. **Disk space.** You need the 15 GB of logs, plus room for `chronopath.db` and
   `tmp_spill/`. Budget 40 GB free.
2. **The log format.** If the real data is not newline-delimited JSON, or uses
   different field names, edit `LOG_SCHEMA` at the top of `src/parser.py` and the
   field names in `rules.yaml`. Everything downstream is schema-agnostic.
3. **Run a slice first.** Do not debug on 15 GB:
   ```bash
   head -n 100000 real_logs.ndjson > data/slice.ndjson
   python src/parser.py --input data/slice.ndjson
   ```

---

## 7 · Adding a detection rule without writing code

This is bonus **B-4**, and it is a good thing to demo live. Open `rules.yaml`,
append a block, re-run the parser:

```yaml
  - name: "PowerShell Encoded Command"
    type: row
    mitre_technique: "T1059.001"
    mitre_name: "Command and Scripting Interpreter: PowerShell"
    kill_chain_stage: "Execution"
    severity: 8
    sql_condition: "process = 'powershell.exe' AND message LIKE '%-enc%'"
    description: >
      PowerShell run with a base64-encoded command, a common way to hide
      malicious scripts from casual log review.
```

```bash
python src/parser.py --input data/sample.ndjson
```

No Python was edited. For an `aggregate` rule, add `group_by` and `having`
instead — see the brute-force rule in `rules.yaml` for the pattern.

> ⚠️ **After adding a rule, test at more than one size.** Two real bugs in this
> project passed at 20 MB and failed badly at 1 GB (see READTHIS.md §2.9b).
> Volume-based thresholds are especially prone to this, because noise grows with
> the data while your threshold stays fixed:
> ```bash
> python run_demo.py --size-mb 50
> python run_demo.py --size-mb 600
> ```
> If a rule counts occurrences, give it `bucket_minutes` so it measures a *rate*
> rather than a lifetime total.

---

## 8 · Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `python: command not found` | Not on PATH | Reinstall Python, tick "Add to PATH" |
| `Activate.ps1 cannot be loaded` | PowerShell execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `streamlit: command not found` | venv not active, or Scripts not on PATH | Activate the venv, or use `python -m streamlit run src/app.py` |
| `No module named duckdb` | venv not active | Re-activate, re-run `pip install -r requirements.txt` |
| `Log file not found` | No sample generated yet | `python scripts/generate_sample.py` |
| `No analysis yet` in the UI | Parser has not run | Click **Run detection** in the sidebar |
| Report says "built-in summary" | `GROQ_API_KEY` not set | Create `.env` with the key (step 3), restart Streamlit |
| `.env` ignored | Wrong folder, or named `.env.txt` | It must sit beside `README.md` and be exactly `.env` (Windows hides known extensions — check with `dir /a`) |
| Groq 401 / invalid key | Key wrong or expired | Regenerate at console.groq.com |
| Groq 429 | Free-tier rate limit | Wait a minute; the fallback summary still works |
| `Out of Memory Error` on big files | Cap too high for the machine | `--memory-limit 4GB` — spilling is slower but safe |
| Disk fills during a 15 GB run | Spill files | Clear `tmp_spill/`, free space, re-run |
| Garbled characters in terminal | Windows legacy code page | Cosmetic only; `chcp 65001` fixes it |
| Port 8501 already in use | Another Streamlit running | `streamlit run src/app.py --server.port 8502` |
| Accuracy suddenly reads 0% | **The answer key does not match the database** | See the note below — the most confusing failure in this project |
| Dashboard shows the wrong data | It opens the most recent database | Set `CHRONOPATH_DB=firex.db` explicitly |
| 2.0 tabs say "layer has not been built" | `run_cp2.py` not run for this database | `python scripts/run_cp2.py --db <db> --input <log>` |
| Blind-window check returns `COVERAGE_UNKNOWN` | No coverage pass, or the file spans too few days to form a control | Run `build_coverage.py`; on a short file this is the honest answer |

### ⚠️ The answer-key trap

**`scripts/generate_sample.py` and `scripts/prepare_edr.py` both write
`data/ground_truth.json`.** Running one overwrites the other's answer key. The
symptom is alarming and misleading: accuracy drops to **0% detection with 100%
false alarms**, as though the detector broke, when in fact it is being graded
against a different data set's attack.

Each input needs its database *and* its truth file paired correctly:

| Input | Database | Truth file |
|---|---|---|
| `firex-10G.log` | `firex.db` | `data/ground_truth_firex.json` |
| `data/edr_ready.json` | `edr.db` | `data/ground_truth.json` *(written by `prepare_edr.py`)* |
| Flat sample | `chronopath.db` | `data/ground_truth.json` *(written by `generate_sample.py`)* |

If you regenerate the flat sample and then want to re-score the EDR run, re-run
`prepare_edr.py` to restore its key — or keep a copy first.

---

## 9 · Checking everything works

### The one command

```bash
python verify.py
```

That is the whole test. It runs five groups of checks and prints PASS, FAIL or
SKIP for each, with the reason:

```
1. Python syntax          all 24 Python files parse
2. Detection rules        3 rule files load, 31 rules, 1 documented-but-off
3. Test suite             16 tests, including the regression gate
4. Accuracy vs ground truth   FortiGate and EDR, each against ITS OWN key
5. Independent validation     the numbers we did not grade ourselves
```

Expected output when everything is in place:

```
  [PASS] all 24 Python files parse
  [PASS] rules_fortigate.yaml  14 rules, 13 enabled, 1 documented-but-off
  [PASS] test suite  all 16 passed
  [PASS] FortiGate (the organisers' real 6.5 GB file)  373,239 detections ->
         5 incidents, 100.0% detection, 100.0% labels, 0.0% false alarms
  [PASS] EDR / ECS (the organisers' generator)  26,119 detections ->
         1 incidents, 100.0% detection, 100.0% labels, 0.0% false alarms
  [PASS] label precision vs vendor signatures  100.0% (0 disagreements)
  [PASS] hold-out detection  100.0% of detections from techniques outside
         our answer key

  ALL CHECKS PASSED -- 9 of 9
```

**Why this script exists.** Testing used to mean five commands with the right
`--db` and `--truth` pairings, and getting a pairing wrong produces the most
misleading failure in this project: 0% detection with 100% false alarms, as
though the detector were broken, when it is being graded against another data
set's answer key. The pairings now live in `verify.py` instead of in your head.

**SKIP is not FAIL.** The script checks its own prerequisites and skips what it
cannot run, saying why. On a machine without the 6.5 GB source log, almost
everything still runs:

```bash
python verify.py --quick                      # skip the independent validation
python verify.py --log E:/firex-10G.log       # log in a non-standard place
```

### Testing one thing at a time

If `verify.py` reports a failure, these are the individual commands behind it:

| What | Command |
|---|---|
| The test suite | `python tests/test_chronopath2.py` |
| FortiGate accuracy | `python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json` |
| EDR accuracy | `python scripts/evaluate.py --db edr.db --truth data/ground_truth_edr.json` |
| Flat-sample accuracy | `python scripts/evaluate.py --db chronopath.db --truth data/ground_truth_flat.json` |
| Independent validation | `python scripts/validate_independent.py --db firex.db --input <log>` |
| The remove-a-host experiment | `python scripts/experiment_remove_host.py` |

**Each data set has its own answer key.** This is not optional bookkeeping:

| Input | Database | Answer key |
|---|---|---|
| `firex-10G.log` | `firex.db` | `data/ground_truth_firex.json` |
| `data/edr_ready.json` | `edr.db` | `data/ground_truth_edr.json` |
| Flat sample | `chronopath.db` | `data/ground_truth_flat.json` |

### Rebuilding from scratch

If a database is missing, rebuild it and then re-verify:

```bash
# FortiGate: detection, then the evidence layer
python src/parser.py --input firex-10G.log --db firex.db --memory-limit 6GB
python scripts/run_cp2.py --db firex.db --input firex-10G.log

# EDR
python src/parser.py --input data/edr_ready.json --db edr.db
python scripts/run_cp2.py --db edr.db --input data/edr_ready.json

python verify.py
```

Note that `src/parser.py` **rewrites** the database, which drops the `cp2_`
tables — so always re-run `run_cp2.py` after a re-parse. `verify.py` will tell
you if you forget.

### Seeing it, not just testing it

```bash
streamlit run src/app.py        # 9 tabs; set CHRONOPATH_DB=firex.db to pick the data
python src/api.py               # REST API on :8000
curl http://localhost:8000/gaps/1        # what we cannot tell you about INC-01
curl http://localhost:8000/evidence/1    # why INC-01's events belong together
```

### The end-to-end demo run

Separately from `verify.py`, this runs the whole flat-sample pipeline from
generation to scoring -- useful as a live demo because it starts from nothing.
All four metrics should read `GREAT`:

```bash
python run_demo.py
```

Expected tail:
```
  Detection rate            100.0%   [GREAT]
  Correct ATT&CK labels     100.0%   [GREAT]
  Attack path rebuilt         YES    [GREAT]
  False alarm rate            0.0%   [GREAT]
```

And the benchmark, which should show peak memory **below** the data scanned:
```bash
python scripts/benchmark.py
```
```
  Data scanned             402 MB
  Peak process RSS         323 MB
  RESULT: peak memory is BELOW the file size. Streamed, not loaded.
```

### Checking the ChronoPath 2.0 layer

```bash
python tests/test_chronopath2.py
```

Expected tail — **all 12 must pass**, and the last two are the regression gate
that proves 2.0 did not change the 1.x results:

```
  test_regression_gate_unchanged
    firex.db: 373,061 detections, 5 incidents -- matches baseline
    edr.db: 26,119 detections, 1 incidents -- matches baseline
  test_rejected_values_are_not_accepted_links
    edr.db: 3 rejected value(s), none reused as an accepted link
==============================================================
  all 12 passed
```

The tests skip gracefully where a database is missing, so run the pipeline for
at least one input first. If `test_regression_gate_unchanged` fails, the
expected numbers are in [`docs/baseline_before_2.0.md`](docs/baseline_before_2.0.md)
— a mismatch means something in the 2.0 layer touched the engine, which it must
never do.

---

## 10 · File map

```
chronopath/
├── README.md              Problem, architecture, benchmarks, demo script
├── PITCH.md               The pitch for judges                       ← 2.0
├── SETUP.md               This file
├── READTHIS.md            Learning guide — concepts + YouTube links
├── START_HERE.md          Beginner's guide, no security background needed
├── requirements.txt       Pinned dependencies
├── rules.yaml             Detection rules (edit to add detections — B-4)
├── rules_ecs.yaml         Rules for the EDR generator's ECS format
├── rules_fortigate.yaml   Rules for real FortiGate syslog
├── assets.yaml            Host/privilege inventory (powers look-ahead — FR-6)
├── verify.py              ONE COMMAND TO TEST EVERYTHING
├── run_demo.py            Runs the whole pipeline in one command
├── data/                  Generated logs + ground truth (gitignored)
├── docs/                                                             ← 2.0
│   ├── baseline_before_2.0.md  The 1.x numbers the regression gate protects
│   └── results_2.0.md          Every 2.0 measurement, with its method
├── tests/
│   └── test_chronopath2.py     12 tests incl. the regression gate    ← 2.0
├── scripts/
│   ├── generate_sample.py Makes logs with a planted attack
│   ├── prepare_edr.py     Makes the organisers' EDR output realistic
│   ├── discover_firex.py  Derives ground truth by rarity analysis
│   ├── benchmark.py       Proves the streaming/memory claim
│   ├── evaluate.py        Scores accuracy against ground truth
│   ├── build_coverage.py       Telemetry coverage + provenance       ← 2.0
│   ├── run_cp2.py              The whole 2.0 layer, one command      ← 2.0
│   └── experiment_remove_host.py  Controlled remove-a-host test      ← 2.0
└── src/
    ├── parser.py          DuckDB streaming detection      (FR-1,2,3)
    ├── ecs_adapter.py     Reads ECS JSON as flat columns
    ├── fortigate_adapter.py  Reads FortiGate syslog as flat columns
    ├── graph_engine.py    Correlation, path, look-ahead   (FR-4,5,6)
    ├── pivot.py           Anomaly ranking (threat hunting)
    ├── api.py             REST API, stdlib only           (FR-7)
    ├── app.py             Streamlit dashboard + Groq      (FR-5,6,7)
    └── chronopath2/            The 2.0 evidence & gap layer          ← 2.0
        ├── streams.py          Coverage + provenance      (Task 1)
        ├── blind_window.py     Did the blinding work?     (Task 2)
        ├── link_evidence.py    Graded links + raw lines   (Task 3)
        ├── gaps.py             The gap ledger             (Task 4)
        └── respond.py          Indicators + containment   (Task 5)
```

---

## 11 · Resetting to a clean state

```bash
# Windows PowerShell
Remove-Item -Force chronopath.db, data\sample.ndjson, data\ground_truth.json -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force tmp_spill -ErrorAction SilentlyContinue

# macOS / Linux
rm -f chronopath.db data/sample.ndjson data/ground_truth.json
rm -rf tmp_spill
```

Then `python run_demo.py` rebuilds everything from scratch.
