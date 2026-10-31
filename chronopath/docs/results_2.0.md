# ChronoPath 2.0 — measured results

> Every number here comes from a run on the organisers' data, on the target
> machine (Dell laptop, 5 cores, 16 GB RAM, Windows 11). Nothing is estimated
> and nothing is hard-coded for a demo. Where the data did not support a
> dramatic conclusion, the undramatic one is reported — see the INC-02
> blind-window result, which is the most instructive finding in this document.

Run date: 2026-10-31 · Tag: `chronopath-2.0` · Baseline: [`baseline_before_2.0.md`](baseline_before_2.0.md)

---

## 1. The regression gate — did 2.0 break 1.x?

This is ground rule 2 of the build, and the whole architecture of 2.0 (new
modules, new tables, no edits to the engine) exists to make the answer *no*.

| Metric | Baseline 1.x | After 2.0 | Verdict |
|---|---|---|---|
| **FortiGate** — detections | 373,061 | **373,061** | identical |
| FortiGate — incidents | 5 | **5** | identical |
| FortiGate — detection rate | 100.0% | **100.0%** | identical |
| FortiGate — correct ATT&CK labels | 100.0% | **100.0%** | identical |
| FortiGate — false alarm rate | 0.0% | **0.0%** | identical |
| **EDR** — detections | 26,119 | **26,119** | identical |
| EDR — incidents | 1 | **1** | identical |
| EDR — path rebuilt | YES, #1 | **YES, #1** | identical |
| `suspicious_events` schema | 17 columns | **17 columns** | untouched |

Verified by `tests/test_chronopath2.py` (12 tests, all passing), two of which
exist solely to guard this: `test_regression_gate_unchanged` and
`test_cp2_tables_do_not_touch_suspicious_events`.

---

## 2. Cost of the 2.0 layer

Measured on the real 6.54 GB FortiGate file, one command:

```
python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log
```

| Step | Time | Note |
|---|---|---|
| Correlate (1.x engine) | 2.0 s | unchanged, shown for context |
| **Coverage pass** (Task 1) | 14.1 s | second scan of 6.54 GB |
| **Raw-line evidence** (Task 3) | 34.3 s | third scan, fetches the original lines |
| **Link evidence** (Task 3) | 0.0 s | works from detections, not the log |
| **Gap ledger** (Tasks 2 + 4) | 0.1 s | |
| **Respond-now** (Task 5) | 0.1 s | |
| **Total wall clock** | **51.3 s** | |
| **Peak RSS (process tree)** | **590 MB** | cap was 6 GB |

The two expensive steps are the only ones that touch the source file. The
evidence layer itself runs in **under half a second** because it works from the
373,061 stored detections rather than the 9.1 million log lines — which is why
the dashboard stays interactive on a 6.54 GB investigation.

For comparison, 1.x detection on the same file takes ~99 s at 813 MB peak. The
2.0 layer therefore adds about half the runtime of detection and *less* memory
than it.

---

## 3. Task 2 — the INC-02 blind-window result

**This is the finding to read first, because the honest answer is not the
exciting one.**

In INC-02 the account `Tejas.Roy` disabled the firewall's disk logging at
16:31:43 on 2026-10-23, then purged the firewall policy objects at 18:28:52.
The obvious report writes itself: *the attacker turned off logging and operated
in the dark for two hours.* It is dramatic, it fits the kill chain, and **on
this data it is false.**

### What was measured

| | Result |
|---|---|
| Window | 2026-10-23 16:31:43 → 18:28:52 (1 h 57 m 09 s) |
| Events **inside** the window | **101,205** |
| Events in the equal period **before** it | 133,462 |
| Volume change | **−24.2%** |
| Same clock hours on the other days in the file | **−24.0%** (mean) |
| **Difference** | **+0.2 percentage points** |
| Classification | **`LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA`** |

### Why a naive check would have got this wrong

Log volume follows a daily rhythm. The check slides its exact window
(1 h 57 m 09 s, with the equal-length period before it as the baseline) onto
each of the other days in the file. Volume falls about 24% every one of them,
whether or not anyone touched the logs:

| Day | Before the window | Inside the window | Change |
|---|---|---|---|
| **2026-10-23** (blind window) | 133,462 | 101,205 | **−24.2%** |
| 2026-10-24 | 133,562 | 101,630 | −23.9% |
| 2026-10-25 | 106,718 | 81,076 | −24.0% |
| 2026-10-26 | 107,164 | 81,255 | −24.2% |
| 2026-10-27 | 106,946 | 81,400 | −23.9% |

The blind-window day sits **inside** the spread of the control days — it is not
even the steepest. The mean control drop is 24.0% against the window's 24.2%.

A before/after test with a 20% threshold would have fired on **all five days**
and accused an attacker each time. That is why the check uses a control rather
than a bare threshold, and why `CURVE_TOLERANCE_PCT` exists.

### What this means operationally

Three conclusions, all better than the dramatic version:

1. **The disable attempt failed.** Whatever the attacker intended, the
   evidence of what they did next is present — the 18:28 policy purge is
   visible *because* `event/system` kept recording.
2. **The supplied file is a forwarded copy.** Disabling *disk* logging does
   nothing to a remote syslog or FortiAnalyzer stream. The data proves we were
   reading the forwarded copy.
3. **The right evidence request is specific:** the FortiAnalyzer copy for the
   window, to confirm independently what the on-box log would have held, plus
   configuration backups from before and after.

The threshold was **not** tuned to manufacture a drop. Per ground rule 4, the
classification is whatever the data showed.

---

## 4. Task 3 — link evidence on the real data

### INC-01, fully explained

The create–use–delete admin cycle, with every link graded:

| Grade | Attribute | Value | Gap | Reason |
|---|---|---|---|---|
| **HARD** | `identity_pivot` | `svc_backup30` | 6 min | The account was created by this event, and is the account acting 6 min later |
| **HARD** | `account` | `Rakes` | 12 min | Same account, 12 min apart |
| **SOFT** | `src_ip` | `203.228.177.117` | 5 min | Same external address — strong but not conclusive |

The identity pivot is the brief's acceptance criterion and it required two
fixes to produce honestly:

1. **The proof was only in the raw line.** The adapter prefers FortiGate's
   `logdesc` for the `message` column, so the creation event reaches the engine
   as the useless `"Object attribute configured"`, while the account name sits
   in `msg="Add system.admin svc_backup30"`. Rather than widen the detection
   path for 9,125,382 rows, `enrich_from_source()` fetches the original line
   for the reported incidents only — which the Evidence tab needed anyway.
2. **The pivot needed a second pass.** The creator and the created account live
   in *different* events, so indexing the creation under the new name left a
   bucket of one, which forms no pair.

### Link totals

| | FortiGate | EDR |
|---|---|---|
| Links recorded | 6 | 62 |
| HARD | 5 | 53 |
| SOFT | 1 | 6 |
| INFERRED | 0 | 3 |
| Links with an empty reason | **0** | **0** |
| Rejected candidate links | 0 | 3 |

One pair of events gets **one best reason**. Showing "same account" *and* "same
machine" *and* "same address" for the same two events is three rows that say
one thing and bury the grade that matters — INC-01 went from 11 links to 6 when
this was fixed.

### Rejected links — the section most tools omit

On the EDR data, three candidate links were refused and recorded:

| Value | Distinct accounts | Why refused |
|---|---|---|
| `SRV-DC-01` | 10 | Exceeds the 3-account limit — a domain controller is where everyone's activity meets |
| `198.51.100.23` | 7 | Exceeds the limit |
| `192.0.2.88` | 4 | Exceeds the limit |

Silent refusal is its own trap: an analyst cannot tell *"genuinely unrelated"*
from *"the tool decided not to connect them and didn't say"*. The second is far
more dangerous, because they will never know to ask.

### Why the five FortiGate incidents are separate

This is the honest form of a 5-incident result on data whose actors share
nothing. All 10 pairs carry a statement with **computed** counts:

> **INC-01 and INC-02 are not linked:** they share no account and no external
> source address. The only common value is `10.10.99.1` (used by **5**
> accounts), which exceeds the **3**-account limit and is therefore treated as
> infrastructure rather than as an actor. A shared firewall is where everyone's
> traffic meets, so it is not evidence that these two are one intrusion.

| Verdict | Pairs |
|---|---|
| `SEPARATED_BY_INFRASTRUCTURE_CUTOFF` | 6 |
| `NO_SHARED_ENTITY` | 4 |

This is also why the baseline's *"Attack path rebuilt: NO"* is the correct
result rather than a defect. The eight planted steps were carried out by five
accounts from five different addresses; fabricating a link to score that metric
would violate ground rule 4.

---

## 5. Task 4 — the gap ledger

| | FortiGate | EDR |
|---|---|---|
| Total gaps | **15** | 6 |
| `NOT_COLLECTED` | 13 | 5 |
| `COVERAGE_UNKNOWN` | 1 | 1 |
| `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA` | 1 | 0 |
| `LOGGING_DISABLED_BY_ACTOR` | **0** | **0** |
| `PARSE_FAILURE` | **0** | **0** |
| Gaps with an empty basis | **0** | **0** |
| Incidents with ≥1 gap | **5 of 5** | 1 of 1 |

Two zeros are worth pointing at:

- **No `LOGGING_DISABLED_BY_ACTOR`.** Nothing in this data supports accusing
  anyone of destroying evidence, so nothing does. Ground rule 5, enforced at
  the database boundary by a closed classification vocabulary.
- **No `PARSE_FAILURE`.** All 9,125,382 rows were read with a parseable
  timestamp. The ledger raises that gap only when there is something to raise,
  rather than emitting a reassuring row.

### The single most useful gap in the build

`INC-01-GAP-LIFECYCLE` names the exact question an incident responder has to
answer about INC-01, and states honestly that this data cannot answer it:

> **Basis:** The data records the lifecycle of the administrative account
> `svc_backup30` — its creation, its login and its deletion — but FortiGate
> event logs state only that a configuration attribute changed, never what the
> new value was. No configuration revision history or diff was supplied for
> 2026-10-29T03:55:43 to 2026-10-29T04:07:25.
>
> **Impact:** Cannot determine what `svc_backup30` actually did while it
> existed. Specifically: no answer on whether firewall policies, VPN users,
> administrative accounts or port forwards were added that would survive the
> account's deletion. **Treat persistence as unverified rather than absent.**
>
> **Request:** Firewall configuration revision history for the period the
> account existed, plus the identity-provider audit log for that account.

1.x showed three detections and stopped. The silence read as *"that's all that
happened"*. It wasn't.

---

## 6. Task 5 — respond-now

### INC-01 indicators (first/last seen across the **whole** data set)

| Type | Value | First seen | Last seen | Detections |
|---|---|---|---|---|
| account | `Rakes` | 2026-10-29T03:55:43 | 2026-10-29T04:07:25 | 2 |
| account | `svc_backup30` | 2026-10-29T04:02:01 | 2026-10-29T04:02:01 | 1 |
| account_created | `svc_backup30` | — | — | 1 |
| source_ip | `203.228.177.117` | 2026-10-29T03:55:43 | 2026-10-29T04:07:25 | 3 |

`svc_backup30` carries the note: *"Created during this incident. Also deleted
during it, so it will not appear in the current configuration — the only record
is this log."*

**Is it still happening?** No indicator in any of the five incidents appears
after its incident's last event. The tool says so plainly rather than
manufacturing urgency.

#### The still-active flag needed three conditions, each found by measuring

This started as a one-line test — *last seen is after the incident ended* — and
that version was technically true and operationally useless. It was caught by
**rendering the dashboard against `edr.db`** rather than reasoning about it.

The EDR data holds seven days of ambient estate activity while the incident
covers four hours of one day, so every ordinary account and internal address
trivially "appears afterwards". It flagged **30 indicators**, including
`10.10.1.11` — a workstation that simply exists.

| Condition added | Reason | False flags |
|---|---|---|
| *(naive: last seen > incident end)* | — | **30** |
| **1. Specificity** | An internal address is a place, not an actor | 11 |
| **2. Not ambient** | ← the one that mattered | **0** |
| **3. Grace period** | Absorb continuation within the same burst | 0 |

Condition 2 is the real discriminator, and the data makes the case plainly:

| Account | Detections | Distinct days | |
|---|---|---|---|
| `svc_helpdesk` | **5** | **1** | ← the attacker |
| `asharma` | 1,929 | 7 | ordinary staff |
| `rkumar` | 1,937 | 7 | ordinary staff |
| `svc_backup` | 3,260 | 7 | ordinary staff |

An indicator present on most days of the file *was never absent*, so "it
appeared again" says nothing about it. The discriminator is **rarity** — the
same principle the detection engine already relies on.

**The grace period was initially wrong, in the dangerous direction.** At 60
minutes it suppressed a real case: `Deepika.Khan`'s third external admin login
lands **57.9 minutes** after the second. It is now 30 minutes, which is correct
because the ambient test does the noise rejection — this only has to span a
burst.

**Verified in both directions**, which matters more than either number alone:

```
A. the 57.9-minute real case      -> 2 indicators FLAGGED   ✅
B. the ambient EDR accounts       -> 0 indicators flagged   ✅
```

**The cost of this precision, stated in the code:** a compromised *internal*
host still beaconing would not be flagged. That is the right trade for a field
whose job is to say *"drop everything"* — one that cries wolf thirty times is a
field an analyst learns to ignore, which is strictly worse than not having it.

### Preceding access — an explicit negative

For INC-01:

> No activity was recorded for these indicators in the 6 hours before the first
> detection (2026-10-28 21:55:43 → 2026-10-29 03:55:43). **That is a finding,
> not a blank:** there is no credential-guessing burst here to explain the
> access, so the credential was most likely obtained elsewhere — reuse,
> phishing, or a legitimate holder.

An empty section reads as *"not checked"*. This reads as *"checked, and the
absence is informative"* — and it redirects the investigation away from brute
force.

### Actions

17 recommended actions across the 5 incidents, every one labelled
**`RECOMMENDED`** and carrying the observation that selected it. For INC-01:

| Priority | Observation |
|---|---|
| 🔴 IMMEDIATE | `svc_backup30` was created *and deleted* inside this incident |
| 🔴 IMMEDIATE | Administrative authentication succeeded from an external address |
| 🟠 HIGH | Activity consistent with indicator removal was observed |
| 🟡 STANDARD | External address `203.228.177.117` involved |
| ⚪ FOLLOW-UP | 3 open gaps require evidence from other teams |

These are rule-based templates, **not** LLM output — per ground rule 6, and
because containment advice should not vanish when an API key expires nor be
improvised by a model when someone may execute it on production infrastructure.

---

## 7. Task 6 — the controlled experiment

```
python scripts/experiment_remove_host.py
```

Removed **`SRV-DC-01`** from the EDR input: 17,940 lines dropped, 382,192 kept.
Chosen because it holds steps 4–6 *including the identity pivot* (`rkumar`
creating `svc_helpdesk`) — the one record carrying the chain from the
workstation phase to the file-server phase. Removing it **severs** the attack
rather than merely shortening it.

### 1.x behaviour — it degrades, measurably

| | Full data | Without `SRV-DC-01` |
|---|---|---|
| Incidents reported | 1 | 1 |
| **Planted steps found** | **8/8** | **3/8** |
| Top incident risk | 92.8 | 83.7 |
| Hosts in top incident | 20 | **1** |
| Stages in top incident | 7 | **4** |

| Step | Technique | Host | Full data | Reduced |
|---|---|---|---|---|
| 1 | T1059.001 | WS-FIN-012 | INC-01 | **MISSING** |
| 2 | T1071.001 | WS-FIN-012 | INC-01 | **MISSING** |
| 3 | T1547.001 | WS-FIN-012 | INC-01 | **MISSING** |
| 4 | T1110 | SRV-DC-01 | INC-01 | **MISSING** |
| 5 | T1136.002 | SRV-DC-01 | INC-01 | **MISSING** |
| 6 | T1078.003 | SRV-DC-01 | INC-01 | INC-01 |
| 7 | T1041 | SRV-FILE-01 | INC-01 | INC-01 |
| 8 | T1486 | SRV-FILE-01 | INC-01 | INC-01 |

Steps 1–3 are *orphaned on the workstation* — the account that linked them to
the rest is gone. This is exactly the failure mode 2.0 exists to surface.

### 2.0 behaviour — the ledger reacts

**Three gaps appear only on the reduced data:**

| Gap | Classification | Entity |
|---|---|---|
| `INC-01-GAP-ACTOR-ORIGIN` | `NOT_COLLECTED` | `svc_backup`, `svc_helpdesk` |
| `INC-01-GAP-IDP` | `NOT_COLLECTED` | `svc_backup`, `svc_helpdesk` |
| `GLOBAL-BEFORE-…` | `COVERAGE_UNKNOWN` | the reduced file |

The actor-origin gap reads:

> The account(s) `svc_backup`, `svc_helpdesk` act in this incident from
> 2026-10-22T21:27:00, but nothing in the supplied data records where they came
> from — no creation event, and no earlier activity establishing them as
> pre-existing.
>
> **Impact:** Cannot establish whether they were created by the attacker during
> this intrusion or are legitimate pre-existing accounts that were compromised.
> These call for **opposite responses** — delete versus reset. The chain of
> custody from the initial foothold to this account is broken here.
>
> **Request:** Directory or endpoint audit records covering the creation and
> prior activity of these accounts, and the process telemetry from whichever
> host created it. **If a domain controller is missing from the supplied
> sources, that is the host to request first.**

### This experiment found a real weakness in my own Task 4 work

The first version of the gap ledger **said nothing** about the hole. It reasoned
only about telemetry *types*, never about an entity that is referenced but
unexplained. The actor-origin gap was added in response.

The asymmetry is the evidence it tracks reality: on the **reduced** data
`svc_helpdesk` raises the gap; on the **full** data it correctly does **not**,
because the creation event is present. A ledger that listed the same gaps
either way would have proved nothing.

### What the gap deliberately does *not* do

**It does not name `SRV-DC-01`.** The tool never saw that host, and inventing
its name would be fabrication. It names the *consequence* and *infers* the
request. That is the line between a useful inference and a made-up fact.

### Nothing invented

| Check | Result |
|---|---|
| Records for `SRV-DC-01` in the reduced input | **0** |
| Records for `SRV-DC-01` in the output database | **0** |
| Verdict | **PASS** |

---

## 8. Task 1 — telemetry coverage and provenance

### The insight: a FortiGate log is not one source

It looks like one file, so the naive reading is *"one telemetry source, nothing
to compare"*. In fact FortiGate multiplexes independent subsystems into one
syslog stream, and `type`/`subtype` names them — **12 streams**, measured over
the full file:

| Stream | Events | Share | Active hours |
|---|---|---|---|
| `traffic/forward` | 5,852,421 | 64.13% | 169 |
| `event/system` | 1,439,293 | 15.77% | 169 |
| `utm/webfilter` | 408,635 | 4.48% | 169 |
| `utm/dns` | 273,937 | 3.00% | 169 |
| `utm/ips` | 273,176 | 2.99% | 169 |
| `utm/app-ctrl` | 272,902 | 2.99% | 169 |
| `event/vpn` | 136,307 | 1.49% | 169 |
| `utm/virus` | 135,623 | 1.49% | 169 |
| `event/sdwan` | 83,520 | 0.92% | 169 |
| `event/ha` | 83,321 | 0.91% | 169 |
| `event/connector` | 83,238 | 0.91% | 169 |
| `event/dhcp` | 83,009 | 0.91% | 169 |
| **Total** | **9,125,382** | 100% | |

All 9,125,382 events are accounted for — the same total 1.x reports, so nothing
is lost between the two passes. This per-stream view is what makes Task 2's
comparison possible from a single supplied file.

### The FortiGate time trap — found by measuring, not assuming

Every line carries **two clocks and a timezone**:

```
date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530"
```

| Interpretation | Result |
|---|---|
| `eventtime` decoded as **UTC** | `2026-10-23 08:48:26` ✅ matches `date`/`time` |
| `eventtime` decoded as **+0530** | `2026-10-23 14:18:26` ❌ 5.5 hours out |

Measured on 200,000 probed lines: **agreement on all of them** when read as
UTC. So the wall-clock fields are effectively UTC and the `tz` tag does **not**
describe them. Our pipeline uses `date`/`time`, which is internally consistent
and agrees with `eventtime`-as-UTC.

This would have been a silent catastrophe. A 5.5-hour shift crashes nothing —
it just moves the attack to the wrong day and breaks every correlation against
another source. It is recorded in the fingerprint rather than buried in a regex.

### Provenance

| Field | Value |
|---|---|
| Source | `firex-10G.log` |
| SHA-256 | `b71fc95eb5fef198912ba12a03f363c2…` |
| Size | 6.54 GB |
| Format | `fortigate` (auto-detected) |
| Time range | 2026-10-23 08:00 → 2026-10-30 08:00 (169 h) |
| Rows read / rejected / bad timestamp | 9,125,382 / **0** / **0** |

The digest matters: a finding citing *"firex-10G.log"* is not reproducible,
because any file can be called that. A hash pins the exact bytes.

---

## 9. Tests

```
python tests/test_chronopath2.py
```

**12 of 12 passing.** They target the properties that must hold for the output
to mean anything, rather than line coverage — a gap ledger that drifts into
boilerplate still looks right, and a link grader that calls everything HARD
still fills the Evidence tab. Neither failure announces itself.

| Test | Guards |
|---|---|
| `test_every_link_has_grade_and_reason` | An ungraded link is worse than none — it looks like evidence |
| `test_rejected_values_are_not_accepted_links` | The filter holding the false-alarm rate at 0% |
| `test_gap_classifications_and_basis` | Closed vocabulary; every gap has basis, impact and a request |
| `test_absence_is_never_called_deletion` | **Ground rule 5** — the most important test here |
| `test_blind_window_needs_a_positive_event` | A blind window cannot be opened by an absence |
| `test_blind_window_classification_is_measured` | The classification rests on numbers, not narrative |
| `test_bad_timestamps_are_counted_not_hidden` | Unparseable timestamps flagged, not sorted to the epoch |
| `test_removed_host_absent_from_experiment_output` | Nothing invented |
| `test_regression_gate_unchanged` | **Ground rule 2** |
| `test_cp2_tables_do_not_touch_suspicious_events` | The 1.x schema is read-only to 2.0 |
| `test_actions_are_labelled_recommended` | Nothing implies an action was taken |
| `test_indicators_span_whole_dataset` | First/last seen is dataset-wide, not incident-scoped |

Note `test_blind_window_classification_is_measured` deliberately does **not**
assert a particular classification. Baking in today's answer would defeat the
purpose; it asserts the classification is one of the two legitimate outcomes
and that its basis cites measured numbers.

---

## 10. Interfaces

All three carry the same facts, computed once by `scripts/run_cp2.py`.

### Dashboard — 9 tabs

`streamlit run src/app.py` · verified by headless render against the real
`firex.db`: **0 exceptions, 0 errors, 0 warnings**, 9 dataframes, 20 expanders.

| Tab | Answers |
|---|---|
| 📝 Report / 🕐 Timeline / 🕸️ Attack graph | 1.x — what happened |
| **🔗 Evidence** | Why do these events belong together? |
| **🕳️ What we can't see** | What couldn't you see, and what should I request? |
| **🚨 Respond now** | What do I do in the next ten minutes? |
| 🎯 What's next / 🔍 Threat hunting | 1.x — blast radius and anomaly ranking |
| **📡 Sources** | Can I trust the data underneath all of this? |

### REST API — 5 new endpoints

`python src/api.py` · all verified HTTP 200 in ~0.25 s each.

| Endpoint | Returns |
|---|---|
| `GET /evidence[/{id}]` | Graded links plus the refused ones |
| `GET /gaps[/{id}]` | The gap ledger with basis, impact, request |
| `GET /separation` | Why each pair of incidents is separate |
| `GET /indicators[/{id}]` | Indicators with estate-wide first/last seen |
| `GET /sources` | Provenance and per-stream coverage |

Ids are tolerant: `/gaps/1`, `/gaps/INC-01` and `/gaps/inc-1` all work.

### Terminal

```
python scripts/run_cp2.py --db firex.db --input D:/firex-10G.log
python scripts/build_coverage.py --input D:/firex-10G.log --db firex.db
python scripts/experiment_remove_host.py
python tests/test_chronopath2.py
```

---

## 11. Deliverable checklist

| | Item | Evidence |
|---|---|---|
| ✅ | Baseline recorded; regression identical after 2.0 | §1, `baseline_before_2.0.md` |
| ✅ | `cp2_` tables populated from real data | 7 tables, §4–8 |
| ✅ | Dashboard tabs: Sources, Evidence, What we can't see, Respond now | §10 |
| ✅ | INC-02 blind-window documented truthfully | §3 — `NO_LOSS_IN_SUPPLIED_DATA`, the undramatic truth |
| ✅ | "Why incidents are separate" for INC-01…05 | §4, all 10 pairs |
| ✅ | Experiment results | §7 — 8/8 → 3/8, 3 new gaps, nothing invented |
| ✅ | Extra runtime and peak memory measured | §2 — 51.3 s, 590 MB |
| ✅ | Nothing hard-coded; works with the LLM off | Actions are rule-based templates (§6) |

### Out of scope (future work, per §5 of the brief)

Parquet normalisation layer, multi-source common schema, full entity registry,
ATT&CK STIX loader and mitigations library, evidence validator, Next.js
frontend, PostgreSQL/FastAPI, multi-source clock-skew handling, full
multi-source coverage matrix, fusing rules into a single scan pass.

---

## 12. The one-line description

> **ChronoPath 2.0 reconstructs the attack, shows the raw evidence behind every
> step, detects when the attacker blinded your logging, and tells the analyst
> what they can't conclude, what to contain now, and what evidence to request
> next.**

And the thing this build is most willing to say out loud: on the organisers'
data, **the attacker did not blind us** — and reporting that, rather than the
dramatic alternative, is the whole point.
