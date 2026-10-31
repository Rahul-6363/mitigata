# Baseline — ChronoPath 1.x, measured before the 2.0 build

> **Why this file exists.** The 2.0 build adds an evidence-and-gap layer *on top of*
> a working detection engine. Ground rule 2 of the build brief makes the regression
> gate non-negotiable: if any number below changes after a 2.0 task, that task is
> reverted. Numbers recorded from opinion are worthless, so they are recorded here
> from actual runs, before a single line of 2.0 code was written.

Recorded: 2026-10-31. Git tag: `baseline-1.x`.

## Measurement environment

| | |
|---|---|
| Machine | Dell laptop, 5 cores, 16 GB RAM, Windows 11 |
| Python | 3.13 in `chronopath/.venv` |
| Input (FortiGate) | `D:\firex-10G.log` — 6.54 GB, 9,125,382 events |
| Input (EDR) | `data/edr_ready.json` — 0.36 GB, Elastic ECS JSON |

## Regression gate — the numbers that must not change

### FortiGate (`firex.db`, 373,239 detections → 5 incidents)

```
python scripts/evaluate.py --db firex.db --truth data/ground_truth_firex.json
```

| Metric | Baseline | Grade |
|---|---|---|
| Planted attack steps | 8 | — |
| **Incidents produced** | **5** | — |
| Detection rate | **100.0%** | GREAT |
| Correct ATT&CK labels | **100.0%** | GREAT |
| Attack path rebuilt | NO | (expected — see note) |
| False alarm rate | **0.0%** | GREAT |

**Note on "path rebuilt: NO".** This is the expected and correct result, not a
defect. The eight planted steps were carried out by five accounts from five
different source addresses that share no linking attribute, so the engine
reports them as five separate incidents rather than inventing a connection
between them. The metric asks whether all eight steps appear inside *one*
incident; here they truthfully do not. Fabricating a link to score this metric
would violate ground rule 4. Task 3 of the 2.0 build makes this explicit by
recording *why* the incidents are separate.

### EDR (`edr.db`, 26,119 detections → 1 incident)

```
python src/parser.py --input data/edr_ready.json --db edr.db
python scripts/evaluate.py --db edr.db --truth data/ground_truth.json
```

| Metric | Baseline | Grade |
|---|---|---|
| Planted attack steps | 8 | — |
| Incidents produced | 1 | — |
| Detection rate | **100.0%** | GREAT |
| Correct ATT&CK labels | **100.0%** | GREAT |
| Attack path rebuilt | **YES, ranked #1** | GREAT |
| False alarm rate | **0.0%** | GREAT |

All 8 steps in one incident, ranked #1 — exactly as the build brief predicted.

## Parse performance (for comparing 2.0's added cost)

| | FortiGate | EDR |
|---|---|---|
| Parse time | ~99 s (12 rules) | 4.6 s (10 rules) |
| Throughput | ~68 MB/s with rules | 79 MB/s |
| Peak RSS | 813 MB (6 GB cap) | < 500 MB |
| Detections written | 373,239 | 26,119 |

## Database state before 2.0

Both databases hold exactly one table, `suspicious_events`, with 17 columns:

```
timestamp, host, user, event_id, src_ip, dest_ip, status, process,
bytes_out, message, rule_name, mitre_technique, mitre_name,
kill_chain_stage, severity, event_count, outcome
```

All 2.0 tables are new and prefixed `cp2_`, so this table is never touched.

Backups taken before the build: `chronopath.db.bak`, `firex.db.bak`.

## Two facts verified from the data before building

Both were assumptions in the build brief that it explicitly said to confirm.

**1. The stream field is `type` + `subtype`** (Task 1). Measured over the first
300,000 lines of the real file — 12 distinct streams:

| type | subtype | count | share |
|---|---|---|---|
| traffic | forward | 192,051 | 64.0% |
| event | system | 47,230 | 15.7% |
| utm | webfilter | 13,577 | 4.5% |
| utm | ips | 9,171 | 3.1% |
| utm | dns | 9,083 | 3.0% |
| utm | app-ctrl | 9,069 | 3.0% |
| utm | virus | 4,502 | 1.5% |
| event | vpn | 4,475 | 1.5% |
| event | ha / connector / sdwan / dhcp | 10,842 | 3.6% |

**2. The FortiGate time trap is real** (Task 1). Every line carries *both* a
`date`/`time` pair *and* an `eventtime` nanosecond epoch, plus `tz="+0530"`:

```
date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530"
```

Decoding `eventtime` as **UTC** gives `2026-10-23 08:48:26` — identical to the
`date`/`time` pair. Decoding it as `+0530` would give `14:18:26`, a 5.5-hour
error. So the wall-clock fields are effectively UTC and the `tz` tag does not
apply to them. Our pipeline uses `date`/`time`, which is internally consistent
and agrees with `eventtime`-as-UTC. This is recorded in the source fingerprint
rather than silently assumed.


---

## Baseline revision — 2026-10-31, after the accuracy review

The FortiGate detection count moved from **373,061 to 373,239 (+178)** and the
EDR top incident's risk score from **92.8 to 92.5**. Both changes are
deliberate, and both are improvements; the gate was updated only after
establishing why each number moved.

### +178 detections: a technique we could not previously express

`T1110.003 Password Spraying` was added. The existing brute-force rule groups
by source address and counts attempts, which answers *"is one address hammering
us?"* It cannot answer the more diagnostic question *"is one address trying many
different accounts?"* -- a different ATT&CK technique with the opposite
response, because spraying is designed to stay under per-account lockout
thresholds.

Measured on this file: **264 external addresses, ~8,000 failed admin logins
each, against 956 distinct usernames**, with up to **839 distinct usernames
from one address in a single hour**. The distribution of distinct usernames per
(address, hour) breaks cleanly -- p99 is 43, then it jumps to 825 -- so the
threshold of 50 sits in the gap rather than being tuned. It is stable: 50, 100,
200, 400 and 600 all yield 157 buckets.

All four accuracy metrics are unchanged (100% / 100% / 0%, 5 incidents): the new
detections carry `outcome: attempted`, so triage correctly keeps them out of the
incident list as blocked threats rather than inventing 178 false incidents.

### Risk 92.8 → 92.5: `event_count` was holding a byte count

`event_count` was being set to the rule's reporting metric rather than the row
count. For rules with a custom metric this was badly wrong, in the direction
that misleads:

| Rule | metric | `event_count` before | after |
|---|---|---|---|
| EDR exfiltration (T1041) | `SUM(bytes_out)` | **58,800,000** | **14** |
| FortiGate VPN (T1133) | `COUNT(DISTINCT src_ip)` | 2 | **4** |

The first reported 58.8 million "raw alerts merged" for a single detection --
bonus B-3 inflated by six orders of magnitude. The second understated the
evidence: `keerat.ghughal` has four VPN tunnels from two countries, and the
analyst was told two events.

The risk score consumes `raw_alert_count`, so correcting the input moved the EDR
score slightly. The metric still reaches the analyst through `message`
("Bytes transferred: 58800000"), which is where a number that is not a row count
belongs.

### The numbers the gate now protects

| | FortiGate | EDR |
|---|---|---|
| Detections | **373,239** | **26,119** |
| Incidents | **5** | **1** |
| Detection rate | 100.0% | 100.0% |
| Correct ATT&CK labels | 100.0% | 100.0% |
| False alarm rate | 0.0% | 0.0% |
| Path rebuilt | NO *(expected -- five unlinked actors)* | YES, ranked #1 |
