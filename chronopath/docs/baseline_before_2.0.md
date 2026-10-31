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

### FortiGate (`firex.db`, 373,061 detections → 5 incidents)

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
| Detections written | 373,061 | 26,119 |

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
