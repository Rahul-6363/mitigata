# READTHIS — Understand everything ChronoPath does

A learning guide for the team. By the end you will be able to explain **any file
in this project to a judge**, including why each design choice was made.

> **A note on the links below.** Rather than hardcode video IDs that can rot,
> break, or turn out to be the wrong video, every link is a **YouTube search URL**
> for a specific topic, with the channel to look for named next to it. Click it
> and pick the top result from the named channel. This was a deliberate choice
> after several video IDs found in search results could not be verified as live —
> a dead link in the middle of a hackathon is worse than no link.

---

## 🚦 If you only have one hour

| Order | Topic | Time | Why it matters |
|---|---|---|---|
| 1 | [Cyber Kill Chain explained](https://www.youtube.com/results?search_query=cyber+kill+chain+explained) | 10 min | The 7 stages you are labelling |
| 2 | [MITRE ATT&CK in 10 minutes](https://www.youtube.com/results?search_query=MITRE+ATT%26CK+framework+explained+beginners) | 10 min | Where the T-numbers come from |
| 3 | [Target 2013 breach explained](https://www.youtube.com/results?search_query=Target+2013+data+breach+explained) | 10 min | The exact story the demo tells |
| 4 | [DuckDB in 100 Seconds](https://www.youtube.com/results?search_query=DuckDB+in+100+Seconds+Fireship) — *Fireship* | 3 min | Why we can scan 15 GB on a laptop |
| 5 | Read **Part 2** below | 20 min | How our pipeline fits together |

That is enough to present the project. Everything else deepens it.

---

# PART 1 · The security concepts

## 1.1 What is the Cyber Kill Chain?

A model from Lockheed Martin describing an intrusion as a sequence of stages.
The insight: an attacker must complete *every* stage to succeed, so a defender
who breaks *any* stage stops the attack.

| # | Stage | Plain English | In our data |
|---|---|---|---|
| 1 | Reconnaissance | Scouting the target | — |
| 2 | Weaponization | Building the payload | — |
| 3 | Delivery | Getting it in | Vendor login from outside |
| 4 | Exploitation | Running it | Brute force succeeds |
| 5 | Installation | Making it stick | New admin account created |
| 6 | Command & Control | Remote steering | Beaconing out |
| 7 | Actions on Objectives | The theft itself | 250 MB uploaded |

**We use ATT&CK's stage names** (Initial Access, Credential Access, Lateral
Movement, Collection, Exfiltration) because they are finer-grained and map
cleanly onto log events. See `STAGE_ORDER` in [src/graph_engine.py](src/graph_engine.py).

📺 [Search: Cyber Kill Chain explained](https://www.youtube.com/results?search_query=cyber+kill+chain+explained+7+stages) — look for **Simply Cyber** or **IBM Technology**

## 1.2 What is MITRE ATT&CK?

A free, public catalogue of what attackers actually do, observed in real
intrusions. Structured as:

- **Tactic** = the attacker's goal ("I need credentials") → *Credential Access*
- **Technique** = how they achieve it ("guess passwords") → *T1110, Brute Force*
- **Sub-technique** = a specific variant → *T1110.001, Password Guessing*

Every rule in [rules.yaml](rules.yaml) carries a technique ID. That is requirement
**FR-3**, and it is why our output is comparable to any other security tool —
T1110 means the same thing everywhere.

Browse the real thing: **[attack.mitre.org](https://attack.mitre.org)**. Look up
the techniques we use: T1078, T1110, T1136, T1003.001, T1021.002, T1005, T1041.

📺 [Search: MITRE ATT&CK explained](https://www.youtube.com/results?search_query=MITRE+ATT%26CK+framework+explained+10+minutes)

## 1.3 Why linking alerts is the hard problem

A SIEM (Security Information and Event Management system) collects logs and
raises alerts. The flaw, which this project exists to fix, is that **alerts
arrive one at a time with no memory of each other**:

```
09:14  Failed logins on HR-07        ← looks like someone forgot a password
09:22  New account created            ← looks like IT onboarding
09:31  Large upload from FS-02        ← looks like a backup job
```

Individually: ignorable. In sequence, sharing a host and an account: a breach.
In the 2013 retail breach, alerts *did* fire and were *not* connected. That gap
is the entire problem statement.

📺 [Search: What is a SIEM](https://www.youtube.com/results?search_query=what+is+a+SIEM+IBM+Technology) — **IBM Technology** explains it well

## 1.4 The 2013 retail breach (our INC-01)

The hackathon brief references *"a 2013 retail breach: one stolen vendor login,
weeks of ignored alerts, up to 110 million customers"*. This is the Target
breach, and our planted attack mirrors it:

1. Attackers phished an **HVAC contractor** with network access.
2. Used those valid credentials to get in — nothing looked "hacked".
3. Moved laterally to payment systems.
4. Exfiltrated 40 M card numbers and 70 M customer records.
5. Alerts fired. Nobody connected them.

**Why this matters for the demo:** it proves the problem is not detection — the
alerts existed. The problem is *correlation*. That is exactly what
`correlate_incidents()` does.

📺 [Search: Target data breach explained](https://www.youtube.com/results?search_query=Target+2013+data+breach+case+study)

## 1.5 Windows Event IDs you will see

Our synthetic logs use real Windows Security Log codes, so the rules look like
rules a real SOC would write.

| Event ID | Meaning | Why an attacker triggers it |
|---|---|---|
| 4624 | Successful logon | Using stolen credentials |
| 4625 | Failed logon | Guessing passwords (many in a row = brute force) |
| 4672 | Special privileges assigned | Admin rights granted at logon |
| 4688 | New process created | Running tools like Mimikatz |
| 4720 | User account created | Building a backdoor account |
| 5140 | Network share accessed | Moving to a file server |
| 5145 | File share object checked | Reading lots of files before theft |

---

# PART 2 · How ChronoPath works

## 2.1 The core problem and the core trick

**The constraint:** 15 GB of logs, 16 GB of RAM. Loading the logs kills the
process. This is the single most likely way the project fails.

**The trick — separate the two problems:**

```
   15 GB raw logs on disk
            │
            │  ❶ DuckDB STREAMS it. Reads a chunk, filters, discards, repeats.
            │     Peak memory stays flat regardless of file size.
            ▼
   ~8 suspicious events  (a few KB — a 10,000× reduction)
            │
            │  ❷ NetworkX builds a graph from the SMALL set.
            │     Graphs are memory-hungry; that is fine on KB of data.
            ▼
   Attack path + look-ahead
            │
            │  ❸ Groq writes the prose.
            ▼
   Streamlit dashboard
```

**Say this to judges:** *"The expensive thing — 15 GB — is handled by a streaming
SQL engine built for it. The clever thing — reasoning about reachability — is
handled by a graph library, but only after the data is small enough to fit. We
never ask either tool to do the other's job."*

## 2.2 Why streaming works (the key insight)

A normal program reads a file like this:

```python
data = json.load(open("logs.json"))    # 15 GB now in RAM → crash
```

DuckDB reads it like this:

```
read 100 MB chunk → apply WHERE → keep 3 matching rows → discard chunk → repeat
```

Only the chunk and the matches are ever in memory. **We proved this**:
scanning 402 MB used 323 MB of RAM — *less than the file*, which is only
possible if the data never fully lands in memory. Run `python scripts/benchmark.py`.

Three settings in [src/parser.py](src/parser.py) make it safe:

| Setting | What it does |
|---|---|
| `memory_limit='8GB'` | Hard ceiling. DuckDB spills rather than exceeding it. |
| `temp_directory='./tmp_spill'` | Where it spills. **Without this, exceeding the limit is a crash.** |
| `preserve_insertion_order=false` | Lets the engine emit rows as it finds them instead of buffering. |

📺 [Search: DuckDB in 100 Seconds](https://www.youtube.com/results?search_query=DuckDB+in+100+Seconds+Fireship) — **Fireship**, ~2 min
📺 [Search: DuckDB larger than memory](https://www.youtube.com/results?search_query=DuckDB+larger+than+memory+out+of+core+processing)
📖 [DuckDB memory management](https://duckdb.org/2024/07/09/memory-management)

## 2.3 Why NDJSON, not JSON

This is a format choice that *is* a memory strategy.

```jsonc
// JSON array — must be parsed as ONE document. Parser cannot stop early.
[ {"a":1}, {"a":2} ]

// NDJSON — one object per line. Can be split at ANY newline.
{"a":1}
{"a":2}
```

NDJSON can be cut into chunks at line boundaries, which is precisely what lets
DuckDB parallelise and stream it. A 15 GB JSON array would have to be
materialised. See [scripts/generate_sample.py](scripts/generate_sample.py).

## 2.4 Detection rules as config (bonus B-4)

All detection logic lives in [rules.yaml](rules.yaml) — no Python. Two kinds:

**`type: row`** — one line is enough:
```yaml
sql_condition: "event_id = 4688 AND process = 'lsass.exe'"
```
Any process touching `lsass.exe` (where Windows caches passwords) is Mimikatz-ish.

**`type: aggregate`** — suspicious only in bulk:
```yaml
sql_condition: "event_id = 4625 AND status = 'failed'"
group_by: ["host", "user"]
having: "COUNT(*) >= 20"
```
One failed login is a typo. Twenty is an attack. **This distinction is why the
false-positive rate stays at 0%** — our noise generator deliberately includes
occasional failed logins, and the threshold ignores them.

📺 [Search: Sigma rules explained](https://www.youtube.com/results?search_query=sigma+rules+detection+engineering+explained)

## 2.5 Correlation — the heart of it (FR-4)

**The question:** given 8 unrelated-looking detections, which belong to the same
attack?

**The answer:** union-find (disjoint set) over shared entities. Two events are
linked if they share a host, user or IP **and** fall within
`CORRELATION_WINDOW_MINUTES` (120).

The crucial property is **transitivity**:

```
Event A (HR-07, svc_vendor)  ──shares host──  Event B (HR-07, admin_jane)
Event B (HR-07, admin_jane)  ──shares user──  Event C (FS-02, admin_jane)
∴ A, B and C are ONE incident — even though A and C share nothing directly.
```

That chain is what connects "vendor logged in" to "data left the building"
through intermediate steps. It is the hours of manual analyst work the brief
describes, done in milliseconds.

**Why union-find:** comparing every event to every other is O(n²). Union-find is
near-linear and about fifteen lines. See `correlate_incidents()` in
[src/graph_engine.py](src/graph_engine.py).

📺 [Search: Union find data structure](https://www.youtube.com/results?search_query=union+find+disjoint+set+explained)

## 2.6 The attack graph (FR-5)

**Nodes** are entities (users, hosts, external IPs). **Edges** are actions,
pointing the way the attacker moved, each carrying a timestamp, technique and
stage.

```
svc_vendor_hvac → HR-07 → FS-02 → 203.0.x.x
     (T1078)      (T1003)  (T1021)   (T1041)
```

Why a graph rather than a table? Because the question "where else can they
reach?" has an unknown number of hops. In SQL that is an open-ended chain of
self-joins. In a graph it is one function call.

📺 [Search: NetworkX tutorial](https://www.youtube.com/results?search_query=NetworkX+python+tutorial+graph+theory)

## 2.7 Look-ahead — two kinds of reachability (FR-6)

The PRD's example output is *"this account has admin rights on 3 more servers"*.

**Logs cannot answer that**, and understanding why is the most interesting part
of this project. Logs record what *did* happen, not what is *permitted*. A
compromised account with admin on twelve servers that has only used one appears
in the logs as exactly one server — the other eleven are the real danger and are
invisible.

So we combine two sources:

| Source | Where from | Means |
|---|---|---|
| **observed** | `nx.descendants()` over the event graph | "A path we actually saw" |
| **privilege** | [assets.yaml](assets.yaml) inventory | "Standing admin rights, never yet used" |

In the demo this turns a weak answer (*one external IP*) into the real one:
**both domain controllers and four more file servers**, sorted by criticality.

**Why `nx.descendants()`:** it is breadth-first and cycle-safe. Real attack
graphs contain loops (A→B→A when an attacker moves back and forth); a
hand-written recursive walk would hang forever.

**Be honest with judges:** `assets.yaml` is declared context standing in for
Active Directory or BloodHound. Saying so is *more* impressive than pretending
the logs contained it — it shows you understand the difference between observed
behaviour and standing privilege, which is the exact gap that made the 2013
breach so damaging.

## 2.8 Risk scoring (bonus B-1)

Three factors, because severity alone misleads:

| Factor | Weight | Reasoning |
|---|---|---|
| Peak severity | 50% | The worst single thing that happened |
| Kill chain depth | 30% | Reaching Exfiltration ≫ stopped at Initial Access |
| Technique breadth | 20% | Many techniques = real intrusion; one repeated = noise |

Our planted attack scores **97.3/100** and sorts to the top. See `risk_score()`.

## 2.9 Measuring accuracy

`generate_sample.py` writes `ground_truth.json` — the answer key. `evaluate.py`
grades against it on the PRD's four metrics.

**Why this matters more than it sounds:** without it you are guessing whether a
rule change helped. With it, you edit a rule, re-run, and see instantly.

Current results, all at the **GREAT** bar, verified at 50 MB, 200 MB, 600 MB and
1 GB:

| Metric | Ours | Good | Great |
|---|---|---|---|
| Detection rate | 100% | >70% | >90% |
| Correct labels | 100% | >60% | >85% |
| Path rebuilt | YES | half | all |
| False alarms | 0% | <30% | <10% |

**Always re-run `evaluate.py` at more than one size after changing a rule.**
Both bugs in §2.9b passed at 20 MB and failed at 1 GB. A single-sample pass
proves very little.

> ⚠️ **Caveat to state plainly:** these are measured against *our own* synthetic
> attack. Real data will be messier. The honest claim is "the pipeline is correct
> and measurable end to end", not "we will score 100% on the judges' data".

## 2.9b Two bugs that only appeared at scale ⭐

**This is the most interesting part of the project. Learn it — judges love it.**

Both bugs were invisible on a 20 MB sample and glaring at 1 GB.

### Bug 1 — counting totals instead of rates

The brute-force rule counted failed logins per user across the **whole file**:

```yaml
group_by: ["host", "user"]
having: "COUNT(*) >= 20"      # 20 failures... ever?
```

At 20 MB this looked flawless. At 1 GB the false-alarm rate hit **80%**. Why?

```
Ordinary employee:  64 failed logins spread over several days  → flagged
Our actual attacker: 35 failed logins in four minutes          → flagged
```

Everyone mistypes passwords. Given enough time, innocent users **out-score the
attacker**. The rule was ranking innocent people above the intruder.

**The fix — recognise what brute force actually is.** It is a *rate*, not a
total. Adding `bucket_minutes: 10` groups by time as well as identity, so the
question becomes *"20 failures in ten minutes?"* Humans spread mistakes out
across days; a script does 20 in seconds.

### Bug 2 — the fix broke detection

After bucketing, false alarms dropped to 0% — and brute force detection dropped
to **zero hits**. The attack was now missed entirely.

The attacker's burst crossed a bucket boundary:

```
   |-------- bucket 1 --------|-------- bucket 2 --------|
                    18 failures ┊ 17 failures
                                ┊
   Threshold is 20. Neither side reaches it. Attack invisible.
```

We had traded a false-positive problem for a **false-negative** problem, which
is strictly worse: a noisy tool wastes time, a silent one gives false comfort.

**The fix — two overlapping grids.** Evaluate the data on two time grids offset
by half a window, and keep the higher count per group:

```
   grid A:  |------|------|------|
   grid B:     |------|------|------|
               ↑ any burst shorter than half a window
                 sits fully inside at least one grid
```

See `build_aggregate_query()` in [src/parser.py](src/parser.py).

### Bug 3 — deduplication hid repeat attacks

The overlapping grids from Bug 2 mean one burst is usually reported twice, so
duplicates must be removed. The obvious way is wrong:

```sql
PARTITION BY host, user          -- keep one row per account
```

This keeps **one detection per account for the entire data set**. An account
brute-forced on Monday *and* again on Friday reports once, and the earlier
attack is silently discarded. On 15 GB spanning weeks that hides most repeat
attacks — a false negative.

The second attempt partitioned by `host, user, floor(start/window)`, which also
failed: a burst straddling a window edge produces two start times that floor to
different keys, so one burst reported twice. Measured failing at a 270-second
offset.

**The fix — merge by elapsed time, not grid position.** `LAG()` compares each
detection with the previous one for that account and keeps it only if it starts
a full window after the one before. This depends on real elapsed time rather
than where grid lines happen to fall, so it is correct at every offset. Verified
across 20 offsets, plus separate bursts 25 minutes and 3 days apart.

### Bug 4 — correlation was quadratic

`correlate_incidents()` compared every event in a bucket against every later
event inside the time window. Measured on detections sharing one host:

| Detections | Time |
|---|---|
| 500 | 0.16 s |
| 2,000 | 2.69 s |
| 5,000 | **21.81 s** |

The PRD's target for opening an incident is **under 2 seconds**. A busy server
in a 15 GB data set can easily produce 5,000 detections, so this would have hung
the demo.

**The fix — link only adjacent pairs.** Union-find already makes connectivity
transitive: if A joins B and B joins C, then A and C share a set without ever
being compared. Linking each event only to its neighbour gives *the same
grouping* at O(n) instead of O(n²):

| Detections | Before | After |
|---|---|---|
| 5,000 | 21.81 s | **0.03 s** |
| 20,000 | (minutes) | **0.12 s** |

A 700× speed-up with identical output. This is the most satisfying kind of fix:
the slow version was not more correct, just slower.

### What to say about this

> *"Our first rules scored perfectly on a small sample. We tested at 1 GB and
> found an 80% false-alarm rate — ordinary users accumulate more failed logins
> over days than an attacker generates in minutes. We fixed it by detecting on
> rate rather than total. That fix then split bursts across bucket boundaries
> and hid the attack, so we moved to two overlapping grids. Deduplicating those
> grids naively then hid repeat attacks. And profiling found correlation was
> quadratic — 22 seconds for 5,000 detections, which we got to 0.03 seconds.
> None of these were findable without measuring at several scales."*

**The general lesson:** volume alone is a weak signal; volume + time + context
is a strong one. A detection rule that has not been tested at scale has not been
tested — and neither has an algorithm that has not been profiled.

## 2.10 The LLM's actual job (bonus B-2)

Groq writes **only the prose summary**. Detection, correlation, pathfinding and
look-ahead are all deterministic and run offline. If the API fails the dashboard
still shows the complete attack — it just loses a paragraph.

**This is a design decision worth voicing:** the AI is a presentation layer, not
a load-bearing component. `temperature=0.2` keeps it faithful rather than
creative, and it receives the *structured* path, never raw logs, so it has
little room to invent.

📺 [Search: Groq API Python tutorial](https://www.youtube.com/results?search_query=Groq+API+python+tutorial)

---

# PART 3 · The tech stack

| Tool | Job | Why this one |
|---|---|---|
| **DuckDB** | Scan 15 GB | Embedded (no server), streams natively, reads NDJSON directly |
| **NetworkX** | Attack graph | Pure Python, no server, `descendants()` solves FR-6 in one call |
| **Streamlit** | Dashboard | Browser UI with no HTML/JS/build step |
| **Groq** | Narrative | Free tier, very fast, good free models |
| **PyYAML** | Config | Makes B-4 (rules without code) trivial |

**What we deliberately did NOT use, and why:**

| Rejected | Reason |
|---|---|
| **Pandas** | Loads everything into RAM. Precisely the failure we must avoid. |
| **Elasticsearch** | Needs a server, lots of RAM, hours of setup. Overkill. |
| **Neo4j** | A whole database server for a graph of a few hundred nodes. |
| **Spark** | Built for clusters. On one laptop it is pure overhead. |

📺 [Search: Streamlit crash course](https://www.youtube.com/results?search_query=streamlit+python+crash+course+tutorial)

---

# PART 4 · Reading the code

Read in this order — each file builds on the last:

| # | File | What to look for |
|---|---|---|
| 1 | [rules.yaml](rules.yaml) | Detection logic as data. Note `row` vs `aggregate`. |
| 2 | [scripts/generate_sample.py](scripts/generate_sample.py) | `generate_attack()` — the 7 planted steps. |
| 3 | [src/parser.py](src/parser.py) | `configure_connection()` and `source_expr()` — the memory story. |
| 4 | [src/graph_engine.py](src/graph_engine.py) | `correlate_incidents()` (union-find) and `look_ahead()`. |
| 5 | [src/app.py](src/app.py) | Four tabs; `render_graph()` has the colour logic. |
| 6 | [scripts/evaluate.py](scripts/evaluate.py) | How the four PRD metrics are computed. |

Every file opens with a docstring explaining **why it exists**, and key decisions
are commented inline.

---

# PART 5 · Questions judges will ask

**"How do you handle 15 GB on a 16 GB laptop?"**
> We never load it. DuckDB streams the file in chunks and filters during the
> scan. We measured it: 402 MB scanned using 323 MB of RAM — less than the file
> size, which is only possible with streaming. Run `python scripts/benchmark.py`
> and it prints that live.

**"How do you know your detections are right?"**
> We plant a known attack and score against it. 100% detection, 100% correct
> labels, 0% false alarms on our test set. `python scripts/evaluate.py`. We are
> also clear that this is our own synthetic data — the point is that accuracy is
> measured, not asserted.

**"What if the attacker does something your rules don't cover?"**
> We miss it — any rule-based detector would. Mitigations: rules are config, so
> a new one is a YAML edit, not a deploy; and correlation is rule-agnostic, so a
> new rule's hits automatically join existing attack paths.

**"Why not machine learning?"**
> Rules are explainable, and an analyst must be able to justify an action. An ML
> score saying "0.87 suspicious" cannot be put in an incident report. Rules also
> map directly to ATT&CK IDs, which is requirement FR-3.

**"Is the AI making up the attack?"**
> No. Detection, correlation and pathfinding are deterministic. The LLM only
> rewrites the finished structured path as prose, at temperature 0.2. Pull the
> network cable and the tool still finds the attack.

**"What breaks first at 50 GB?"**
> Disk I/O, not memory — memory stays flat by design. At 1000 MB/s, 50 GB is
> under a minute of scan time. We chose the 15 GB tier because the multiplier is
> accuracy-gated and the planted attacks are identical at every tier, so there
> was no detection advantage in going bigger.

---

# PART 6 · Glossary

| Term | Meaning |
|---|---|
| **ATT&CK** | MITRE's public catalogue of attacker techniques |
| **Technique (T1110)** | A specific attacker method |
| **Tactic** | The goal behind a technique (e.g. Credential Access) |
| **Kill chain** | The staged model of an intrusion |
| **Lateral movement** | Spreading from one machine to another |
| **Exfiltration** | Stealing the data out |
| **SIEM** | The log-collection/alerting platform this augments |
| **IOC** | Indicator of Compromise — evidence of a breach |
| **Dwell time** | How long an attacker goes unnoticed (often months) |
| **Blast radius** | Everything a compromised account could reach |
| **NDJSON** | One JSON object per line — streamable |
| **Out-of-core** | Processing data larger than RAM |
| **Union-find** | Algorithm for grouping transitively related items |
| **DAG** | Directed Acyclic Graph — a graph with no cycles |

---

**You now know enough to explain every line of this project.** If one concept is
still fuzzy, the file that uses it opens with a docstring saying why it exists —
start there.
