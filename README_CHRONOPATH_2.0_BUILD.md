# ChronoPath 2.0 — Build Brief for Claude Code

> **Read this whole file before writing any code.** This is an implementation brief for a 4-hour build. It upgrades the existing, working ChronoPath engine to ChronoPath 2.0 by **adding** an evidence-and-gap layer on top. It does **not** rewrite the engine.

The product name stays **ChronoPath**. "2.0" is the version. Do not rename anything to Lacuna.

---

## 0. Ground rules (non-negotiable)

1. **Do not change detection, correlation, or scoring behaviour.** `parser.py` rules, the Union-Find grouping, the prevalence split, anchor-and-expand, triage and the six-factor risk score must produce the same incidents as before. 2.0 adds metadata *alongside* them.
2. **Regression gate.** Before any change, and after every task, run the evaluation. The FortiGate result must stay **100% detection / 100% correct labels / 0% false alarms, 5 incidents**, and the EDR result must stay **8/8 steps in one incident, ranked #1**. If a number changes, revert that change.
3. **Inspect the repo first.** Function names, column names and file paths below are expectations, not facts. Read `src/parser.py`, `src/graph_engine.py`, `src/app.py`, `scripts/evaluate.py` and the rule YAML files before editing. Adapt to what exists.
4. **Never fabricate.** Every gap, link reason and number shown in the UI must be computed from the data. No hard-coded demo values. If something can't be determined, display `UNKNOWN` / `COVERAGE_UNKNOWN`.
5. **Missing is not malicious.** Absent logs are never reported as deletion unless there is a positive event proving it (e.g., a "logging disabled" admin event).
6. **The LLM stays optional.** Nothing in this brief may depend on the Groq call.
7. **Small commits.** One commit per task, so any task can be reverted alone.

---

## 1. Context — what already exists (ChronoPath 1.x, measured)

- DuckDB streams the organisers' 6.54 GB FortiGate file: 9,125,382 events in ~99 s, peak 813 MB RAM, 16 GB laptop.
- 12 YAML rules (row + aggregate, overlapping time grids, LAG() dedup), per-signature `technique_map`, `UNMAPPED` for unknown signatures, outcome per detection: `prevented` / `attempted` / `observed`.
- Correlation: prevalence split (>20% of machines/accounts = ambient), anchor-and-expand (account ≤120 min, machine ≤15 min), Union-Find over shared entities with adjacent-pair linking, infrastructure cut-off (entity with >3 distinct accounts is not a link), `-` placeholder is not an identity, identity pivot on account creation, triage.
- Result: 373,061 detections → 5 incidents (INC-01…INC-05), 158 blocked threats, estate-wide summary.
- Three formats: FortiGate key=value syslog, Elastic ECS JSON (EDR), flat JSON.
- Streamlit dashboard (`src/app.py`) reads `chronopath.db`.

Known incidents in the FortiGate file (for checking your output):

| Incident | What happened |
|---|---|
| INC-01 | `Rakes` created admin `svc_backup30` (03:55), it logged in (04:02), `Rakes` deleted it (04:07), all from 203.228.177.117 |
| INC-02 | `Tejas.Roy` disabled firewall disk logging (16:31), purged firewall policies (18:28), from 78.120.139.0 |
| INC-03 | `Deepika.Khan`, three admin logins from the internet |
| INC-04 | `parul.sinha`, admin login from the internet |
| INC-05 | `keerat.ghughal`, VPN from two countries 7 minutes apart |

Commands (verify paths before running):

```bash
python src/parser.py --input <path-to-firex-10G.log> --memory-limit 6GB
python src/parser.py --input data/edr_ready.json --db edr.db
python src/graph_engine.py
python src/graph_engine.py --db edr.db
python scripts/evaluate.py --truth data/ground_truth_firex.json
streamlit run src/app.py
```

**Step zero:** run the commands, record the baseline numbers in `docs/baseline_before_2.0.md`, back up `chronopath.db` and `edr.db`, and `git tag baseline-1.x`.

---

## 2. What ChronoPath 2.0 adds (this build)

ChronoPath 2.0 answers four questions per incident, in the order an analyst works:

1. **Can I trust the data?** → Telemetry streams and coverage (Task 1)
2. **Why does each step belong here?** → Link evidence (Task 3)
3. **What can't we see?** → Gap ledger + evidence requests (Tasks 2 and 4)
4. **What do I do now?** → Respond-now panel (Task 5)

Plus one controlled experiment proving the gap layer works (Task 6).

All new code goes in new modules. Suggested layout (adapt to the repo):

```
src/
  chronopath2/
    __init__.py
    streams.py        # Task 1
    blind_window.py   # Task 2
    link_evidence.py  # Task 3
    gaps.py           # Task 4
    respond.py        # Task 5
scripts/
  experiment_remove_host.py   # Task 6
tests/
  test_chronopath2.py
docs/
  baseline_before_2.0.md
  results_2.0.md
```

Persist all 2.0 outputs as new tables in the same DuckDB file (prefix `cp2_`), so `app.py` can read them and the old tables are untouched.

---

## 3. Tasks

### Task 1 — Telemetry streams and coverage (≈45 min)

**Why:** A FortiGate log is not one source. It mixes event (admin/system), traffic and UTM (IPS, antivirus, app-control) streams. Treating each as its own telemetry stream lets the coverage view show real information with a single file.

**Build:**
- Identify the stream field in the FortiGate data (expected: `type`, optionally `subtype`). Confirm the actual field name and values from the data first.
- One DuckDB pass (or reuse the existing scan if a cheap hook exists) producing table `cp2_stream_volume`: `stream`, `hour_bucket` (UTC), `event_count`.
- Table `cp2_source_fingerprint` per input file: file name, SHA-256 hash (stream it in chunks — never read the whole file into memory), detected format, earliest/latest timestamp, total rows, parsed rows, rejected rows, rows with unparseable timestamps.
- Note the FortiGate time trap: logs may carry both a `date`/`time` pair and an `eventtime`/device time. Record which one the pipeline uses and whether a timezone is present. Store this in the fingerprint.

**Acceptance:**
- Fingerprint row exists for each input with real values.
- Volume table covers the full file time range.
- Peak memory stays under the existing 6 GB cap; record the extra runtime.

---

### Task 2 — The INC-02 blind-window check (≈30 min) — **verify, don't assume**

**Why:** In INC-02 the attacker disabled firewall disk logging at 16:31 and purged policies at 18:28. This is a visibility gap with **positive evidence** — the strongest real 2.0 example in the organisers' data.

**Build (`blind_window.py`):**
- For any detection whose technique is T1562 (Impair Defenses) with a "logging disabled" meaning, take the window from that event to the next "logging enabled" event for the same device (or to the end of the incident / +3 h if none).
- Compare per-stream volume inside that window with the same streams in the equal-length window before it.
- Classify the result **from the data**:
  - Volume drops significantly (define the threshold as a named constant, e.g. >50% drop) → gap `LOGGING_DISABLED_BY_ACTOR`, with the disable event as the basis.
  - Volume does not drop → gap record states: *"Disk logging was disabled, but this file kept recording, so it likely comes from a remote/forwarded stream; activity in the window remains visible."* Classification `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA`.
- Store in `cp2_gaps` (see Task 4 schema).

**Acceptance:**
- The outcome is whatever the data shows. **Report which case occurred in `docs/results_2.0.md`.** Do not tune the threshold to force a dramatic result.
- The INC-02 timeline in the dashboard shows the window shaded, labelled with the classification.

---

### Task 3 — Link evidence and grades (≈60–75 min) — **the core 2.0 feature**

**Why:** An analyst never trusts a summary until they see the raw line. Every link must say *why* in one plain sentence and open the original records.

**Build (`link_evidence.py`):**
- Hook into the place in `graph_engine.py` where Union-Find links two events (and where anchor-and-expand attaches ambient detections). **Record, do not change**, each link:

| Column | Content |
|---|---|
| `link_id` | stable ID |
| `incident_id` | |
| `event_a`, `event_b` | event IDs |
| `link_attribute` | `account` / `src_ip` / `machine` / `identity_pivot` |
| `attribute_value` | e.g. `Rakes` |
| `time_delta_s` | seconds between the two events |
| `window_s` | the window that applied |
| `grade` | see below |
| `reason` | one plain sentence |

- Grades, mapped to what this data actually has:

| Grade | When |
|---|---|
| `HARD` | identity pivot (account created → that name used) or same account |
| `SOFT` | shared source IP or shared machine within the window |
| `INFERRED` | ambient detection attached to an anchor only by machine within 15 min |
| `UNRESOLVED` | a candidate link that was **rejected**: infrastructure entity (>3 accounts), `-` placeholder |

- Also record **rejected** candidate links (the ones the infrastructure cut-off and placeholder rule block) in `cp2_rejected_links`, with the reason. Keep this bounded: aggregate per rejected entity value (one row per value with a count and a sample of event IDs), not one row per pair.
- Produce a "why these incidents are separate" record: for each pair of reported incidents, check whether they share any entity value; if the only shared values are rejected infrastructure/placeholder values, state that. Example output: *"INC-01 and INC-02 are not linked: they share no account or source IP; the only common value, the firewall management IP, is used by N accounts and is treated as infrastructure."* Compute N.
- Reason sentences are templates filled from data, e.g. `"Linked: same account ({value}), {minutes} min apart."`

**Dashboard:** Clicking edges inside a Streamlit graph is hard — instead add an **"Evidence" tab**: a selectbox or table of links for the chosen incident; selecting one shows the grade, the reason sentence and both **raw log lines** (from the stored raw text or source locator). If raw text isn't stored today, store the raw line (or file offset) for detections only — never for all 9 M rows.

**Acceptance:**
- Every edge in every reported incident has a row with a non-empty reason.
- INC-01 shows the identity pivot `Rakes → svc_backup30` as `HARD`.
- The incident-separation record exists for INC-01…INC-05.
- **Regression gate passes unchanged.**

---

### Task 4 — Gap ledger and evidence requests (≈45 min)

**Build (`gaps.py`), table `cp2_gaps`:**

| Column | Content |
|---|---|
| `gap_id` | |
| `incident_id` | or `GLOBAL` |
| `asset_or_entity` | |
| `telemetry` | e.g. `endpoint_process`, `firewall_event` |
| `time_start`, `time_end` | |
| `classification` | one of the list below |
| `basis` | the facts that justify the classification |
| `impact` | what this prevents the analyst from concluding |
| `evidence_request` | what to request next |

Classifications (use exactly these; when unsure, `COVERAGE_UNKNOWN`):

- `NOT_COLLECTED` — telemetry type not present in any supplied source (e.g., no endpoint logs for the admin workstations behind INC-01…05).
- `PARSE_FAILURE` — rows rejected or timestamps unparseable (from the Task 1 fingerprint). Also: rows with unparseable timestamps must be **flagged** in the timeline, not silently sorted to the start.
- `LOGGING_DISABLED_BY_ACTOR` / `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA` — from Task 2.
- `COVERAGE_UNKNOWN` — e.g. anything before the file's first timestamp. **Do not** claim retention expired without retention metadata.

Evidence-request mapping (a fixed dictionary in code is fine):

| Gap | Request |
|---|---|
| no endpoint telemetry for an account's workstation | EDR process timeline for that workstation |
| firewall logging disabled | FortiAnalyzer / remote syslog copy for the window; firewall config backups before and after |
| admin account created/deleted | firewall config revision history; identity-provider audit log for the account |
| parse failure | original export of the affected rows |
| coverage unknown before file start | earlier log archive for the same device |

**Dashboard:** a **"What we can't see"** section per incident listing its gaps (impact + request), plus a global gaps view.

**Acceptance:** each reported incident has ≥1 gap with a non-empty basis; nothing is classified more strongly than its basis supports.

---

### Task 5 — Respond-now panel (≈40 min)

**Build (`respond.py`)**, computed per incident from its detections:

- **Indicators**: accounts, source IPs, created/deleted accounts — copyable list.
- **First seen / last seen** for each indicator across the **whole** dataset (not just inside the incident) — answers "is it still happening?"
- **Preceding access**: for the incident's accounts, the successful logins and failed-login bursts from the same source IP in the hours before the first detection (query the stored detections/blocked threats; if the data isn't retained, say so rather than inventing it).
- **Suggested actions** (rule-based templates, clearly labelled *recommended*, never *done*):
  - account created then deleted → audit config changes made by that account; check for persistence (new VPN users, policies, port forwards)
  - internet admin login → disable/reset the account; restrict admin interface to management network
  - logging disabled / policies purged → compare current config with last backup; re-enable and forward logging
  - VPN from two countries → reset credentials; review MFA
  - always → block source IPs at the edge if not known-good

**Dashboard:** a **"Respond now"** tab with indicators, first/last seen, preceding access, actions.

**Acceptance:** INC-01 shows `Rakes`, `svc_backup30`, 203.228.177.117 with first/last seen; actions are labelled as recommendations.

---

### Task 6 — Controlled experiment: remove a host (≈40 min)

**Why:** Proves the 2.0 layer with a measured before/after, using the EDR dataset whose 8-step attack is known.

**Build (`scripts/experiment_remove_host.py`):**
1. Read the EDR ground truth (find the existing truth file used by `evaluate.py` for EDR).
2. Pick one host that holds a middle step of the attack. Write a copy of the EDR input with **all records for that host removed** (stream it; don't load the file whole).
3. Run the pipeline on the reduced copy into `edr_removed.db`.
4. Report, in `docs/results_2.0.md`:
   - **1.x behaviour:** incidents/path produced (does it shorten, split, or rank lower?).
   - **2.0 behaviour:** supported steps retained; a `NOT_COLLECTED` gap for the removed host covering the missing step's time; the missing transition shown as `UNRESOLVED`; an evidence request for that host's EDR timeline.
   - Confirm **no event for the removed host appears anywhere** (nothing invented).

**Acceptance:** the experiment runs from one command and writes its results to the doc.

---

## 4. Tests (`tests/test_chronopath2.py`)

Minimum:
- Every link row for a reported incident has a grade and reason.
- Rejected infrastructure/placeholder values never appear as accepted links.
- Gap classifications are only from the allowed list; every gap has a basis.
- Unparseable timestamps are flagged, not sorted to the epoch/start.
- Experiment: removed-host events count = 0 in output; a `NOT_COLLECTED` gap exists for that host.
- Regression: incident count and evaluation numbers equal the baseline.

---

## 5. Out of scope for this build (say "future work" if asked)

Parquet normalization layer, multi-source common schema, full entity registry, ATT&CK STIX loader and mitigations library, evidence validator, Next.js frontend, PostgreSQL/FastAPI, multi-source clock-skew handling, full multi-source coverage matrix, fusing rules into a single scan pass.

---

## 6. Time plan and checkpoint

| Time | Work |
|---|---|
| 0:00–0:15 | Step zero: baseline, backups, tag |
| 0:15–1:00 | Task 1 streams + fingerprint |
| 1:00–1:30 | Task 2 blind-window check |
| 1:30–2:45 | Task 3 link evidence + Evidence tab |
| **2:30** | **Checkpoint: anything not working is cut. Regression gate must pass.** |
| 2:45–3:15 | Task 4 gaps + Task 5 respond-now (reduce Task 5 to indicators + first/last seen if short on time) |
| 3:15–3:40 | Task 6 experiment |
| 3:40–4:00 | Final regression run, `docs/results_2.0.md`, `git tag chronopath-2.0` |

Priority if time runs short: **Task 3 > Task 4 > Task 2 > Task 5 > Task 1 > Task 6.**

---

## 7. Final deliverable checklist

- [ ] Baseline numbers recorded; regression numbers identical after 2.0
- [ ] `cp2_` tables populated from real data
- [ ] Dashboard tabs: Sources, Evidence, What we can't see, Respond now
- [ ] INC-02 blind-window result documented truthfully (whichever case occurred)
- [ ] "Why incidents are separate" shown for INC-01…05
- [ ] Experiment results in `docs/results_2.0.md`
- [ ] Extra runtime and peak memory of the 2.0 layer measured and recorded
- [ ] Nothing hard-coded for the demo; works with the LLM switched off

---

## 8. The one-line description

> **ChronoPath 2.0 reconstructs the attack, shows the raw evidence behind every step, detects when the attacker blinded your logging, and tells the analyst what they can't conclude, what to contain now, and what evidence to request next.**
