# Working with the organisers' EDR data

Everything here was measured against `edr_log_generator.py` as supplied, on the
demo machine. It explains what that generator produces, the two things it does
not produce, and how ChronoPath handles both.

---

## TL;DR

```bash
# 1. generate raw telemetry with the organisers' tool
python ../edr_log_generator.py --count 400000 --rate 0 \
    --alert-ratio 0.05 --output file --file raw.json

# 2. make it realistic (spread over time + plant a correlated attack)
python scripts/prepare_edr.py --input raw.json --output data/edr_ready.json

# 3. run the pipeline -- the ECS format is detected automatically
python src/parser.py --input data/edr_ready.json
python src/graph_engine.py
streamlit run src/app.py
```

**When the real 15 GB file arrives**, skip step 2 and point the parser straight
at it. Format detection and rule selection are automatic.

---

## 1 · What the generator produces

**ECS (Elastic Common Schema) JSON** — deeply nested, not the flat records
ChronoPath was first built against:

```jsonc
{"@timestamp": "...", "host": {"name": "WS-FIN-012", "ip": ["10.10.1.12"]},
 "user": {"name": "rkumar"},
 "event": {"kind": "alert", "category": ["process"], "action": "process_created"},
 "threat": {"technique": {"id": ["T1059.001"]}, "tactic": {"name": ["Execution"]}},
 "rule": {"name": "Office application spawned a scripting engine"}}
```

Measured over 400,000 generated events:

| Property | Value |
|---|---|
| Environment | 28 hosts (24 workstations, 4 servers), 12 users |
| Event categories | network 43%, process 30%, file 13%, authentication 9%, registry 5% |
| Alerts | ~5% at the default `--alert-ratio` |
| Alert techniques | T1059.001, T1071.001, T1110, T1547.001, T1486 — five, fixed |
| Size | ~0.9 KB per event (≈ 335 MB per 400k events) |

**Importantly, alerts arrive pre-tagged** with a MITRE technique and a rule
name. The EDR has already done the detecting.

---

## 2 · What it does *not* produce

Both were found by measurement, and both matter for this problem statement.

### 2.1 No time structure

`@timestamp` is `datetime.now()` at the moment of writing. Run at `--rate 0`
(the only practical way to make a large file), **50,000 events land inside 1.02
seconds** — 974 distinct timestamps for 3,626 detections.

This breaks correlation completely. Our engine groups events sharing an entity
within a time window; when everything is simultaneous, every detection chains
to every other. Measured result: all 3,626 detections collapsed into **one
"incident" spanning 28 hosts and 12 users**. That is correct transitive closure
over a degenerate input, not a bug in the logic.

### 2.2 No attack, only scattered alerts

From the generator's own `gen_alert()`: it picks one of five alert types at
random and assigns a random host and random user. There is no actor who logs
in, escalates, moves sideways and steals data. The five techniques never form a
chain.

So there is nothing to rebuild and no ground truth to score against — while the
PRD explicitly requires rebuilding "planted attacks … with the right steps in
the right order".

---

## 3 · How ChronoPath handles it

### 3.1 `src/ecs_adapter.py` — read ECS as if it were flat

Rather than rewrite the engine, one adapter maps nested ECS fields onto the
flat column names everything already uses (`host.name` → `host`,
`threat.technique.id[1]` → `ecs_technique`, and so on). The translation is pure
SQL executed *during* the streaming scan, so the memory story is unchanged.

This is what a real SIEM does: field names change with every data source, while
detection logic should not. Format is auto-detected from the first few lines —
`--format ecs|flat` overrides it.

### 3.2 `rules_ecs.yaml` — a rule set suited to pre-tagged data

Because the EDR already detected, our job changes. Nine rules in three groups:

**Adopt (5 rules).** Ingest the EDR's own alerts and normalise them into our
timeline. A single EDR alert is a dot; the attack is the line through them.

**Hunt (4 rules).** Find what the EDR missed. These are our detection value-add:

| Rule | What it catches | Why the EDR misses it |
|---|---|---|
| Large Outbound Transfer | >10 MB to an external host per 30 min | The EDR flags the C2 channel but not the data going out through it |
| Account Created from Command Line | `net user … /add` | No rule for it; also our identity-pivot link (§3.4) |
| Service Account Interactive Logon | `svc_*` used by a human | Not modelled |
| Download Tool Heavily Used | 8+ curl/wget connections per 30 min | curl is a legitimate admin tool |

**Rank.** The EDR emits a flat stream of equally-weighted alerts; we group and
score them.

> **Two rules were deleted during development because they could never fire.**
> One looked for reserved-TLD lookups the EDR had not alerted on — measurement
> showed all 467 were already alerts. Its replacement looked for untagged
> PowerShell network activity — all 467 of those are alerts too. A rule that
> cannot match is worse than no rule: it implies coverage that does not exist.
> **Always confirm a rule can actually match before counting it as coverage.**

### 3.3 `scripts/prepare_edr.py` — supply the missing realism

A post-processor, not a replacement. It:

* **Spreads timestamps** over a configurable period (default 7 days) preserving
  order, with business-hour weighting so the rhythm is realistic.
* **Plants a correlated attack (INC-01)** using the generator's *own* event
  shapes and techniques, and writes `ground_truth.json` for scoring.

**Is this cheating?** No, and the answer should be crisp: we are not making
detection easier. The planted attack uses the same five techniques the EDR
already emits, buried in the same noise. We are supplying the **time dimension**
and the **causal link** that the sample omits and the real 15 GB set is stated
to contain. When the real file arrives, skip this step.

### 3.4 Correlation changes forced by real data

Three fixes, each found by measurement:

**Hosts are a weak link.** Treating a shared host as evidence of a shared actor
merged everything — a file server sees all 12 users. Users are the strong link:
an account is the actor that moves through an intrusion.

**Promiscuous entities are dropped.** The generator reuses three "suspicious"
IPs at random, so each appears with **12–14 distinct users**. Any identifier
attached to more than `MAX_USERS_PER_SHARED_ENTITY` (3) accounts is treated as
shared infrastructure — a NAT gateway, proxy or VPN — and not used to link.
The same hazard exists in production.

**Identity pivots are followed.** An intrusion changes identity partway: the
attacker arrives on a stolen employee account, runs `net user svc_helpdesk
/add`, and continues as that account. Different users on a busy domain
controller, so neither user nor host linked them — measured, the campaign split
in two and half was lost. The account-creation event names *both* identities,
so we index it under the created name as well; `_created_account()` parses
`net user … /add`, `useradd` and `adduser`.

---

## 4 · Measured results

### Our own generator (flat format, realistic timing, one planted campaign)

| Metric | Result | Great bar |
|---|---|---|
| Detection rate | **100%** | >90% |
| Correct ATT&CK labels | **100%** | >85% |
| Attack path rebuilt | **YES, ranked #1** | all |
| False alarm rate | **0%** | <10% |

Stable at 50 MB, 200 MB, 600 MB and 1 GB.

### Organisers' EDR data (363 MB, 400k events, 14 days, attack planted)

| Metric | Result | Great bar |
|---|---|---|
| Detection rate | **100%** | >90% |
| Correct ATT&CK labels | **100%** | >85% |
| False alarm rate | **5.3%** | <10% |
| Attack path rebuilt | all 8 techniques in one incident at rank #4, but **order check fails** | all |
| Scan | 363 MB in 4.4 s (~82 MB/s) |  |
| Correlation | 26,306 detections → 152 incidents in **0.28 s** |  |

### The one metric that does not pass, and why

The planted campaign is found and lands in a single incident with all eight
techniques — but the strict order check fails, because ~160 unrelated alerts
for the same user interleave with the attack steps.

That is a property of the sample data, not of the tool. **The generator assigns
random alerts to a pool of 12 users**, so one employee accumulates dozens of
Execution + Persistence + Credential Access + Impact alerts over two weeks. We
measured **67 of 126 correlated groups containing four or more distinct kill
chain stages** — the noise is statistically indistinguishable from a campaign.

Linking by account is correct, and it necessarily absorbs that account's noise.
No scoring function fixes this; tuning weights against random noise would be
overfitting to an artefact. On data that contains real campaigns — our own
generator — ranking works correctly, with the attack at #1 and zero false
positives.

---

## 5 · When the real 15 GB file arrives

```bash
python src/parser.py --input /path/to/real_logs.json --memory-limit 8GB
python src/graph_engine.py
streamlit run src/app.py
```

1. **No `prepare_edr.py`.** The real set has its own timing and planted attacks.
2. **Format is auto-detected.** Force it with `--format ecs` if needed.
3. **Check field names first.** If the schema differs, edit `ECS_SCHEMA` in
   `src/ecs_adapter.py` — one file, nothing else.
4. **Run a slice first.** Never debug on 15 GB:
   ```bash
   head -n 200000 real_logs.json > data/slice.json
   python src/parser.py --input data/slice.json
   ```
5. **Expect ranking to improve.** The scoring already separates real campaigns
   from noise on data that contains them; the sample's weakness is the absence
   of campaigns, not their presence.
