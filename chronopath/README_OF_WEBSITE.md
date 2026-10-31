# ChronoPath — guide to the website

This guide walks through every part of the ChronoPath dashboard: what each
section shows, how to read it, and a real example taken from the organisers'
`firex-30G.log` (19.6 GB, 37 million firewall events), analysed into
`firex30.db`.

No security background is assumed. Terms are explained the first time they
appear, and there is a [glossary](#glossary) at the end.

---

## Contents

1. [Starting the website](#1-starting-the-website)
2. [Page layout](#2-page-layout)
3. [The sidebar](#3-the-sidebar)
4. [The incident header](#4-the-incident-header)
5. [Report](#5-report)
6. [Investigator](#6-investigator)
7. [Timeline](#7-timeline)
8. [Attack graph](#8-attack-graph)
9. [Evidence](#9-evidence)
10. [What we can't see](#10-what-we-cant-see)
11. [Respond now](#11-respond-now)
12. [What's next](#12-whats-next)
13. [Threat hunting](#13-threat-hunting)
14. [Sources](#14-sources)
15. [Live mode](#15-live-mode)
16. [The same features without the website](#16-the-same-features-without-the-website)
16. [Glossary](#glossary)

---

## 1. Starting the website

From the `chronopath` folder:

```powershell
# Analyse a log file (only needed once per file)
python src/parser.py --input firex-30G.log --db firex30.db --memory-limit 4GB

# Start the website
streamlit run src/app.py
```

Open **http://localhost:8501** in a browser.

The first command reads the whole log, applies the detection rules, groups the
results into incidents and builds the evidence layer. On the 30 GB file this
takes a few minutes. After that, the website opens the stored results and needs
no re-analysis.

**Optional — AI-written text.** Create a file named `.env` next to `README.md`
containing `GROQ_API_KEY=gsk_...` (a free key from console.groq.com) and
restart. Without it, every part of the site still works and shows built-in
summaries instead.

---

## 2. Page layout

```
┌──────────────┬──────────────────────────────────────────────────────┐
│  SIDEBAR     │  ChronoPath            Kill chain and attack path ... │
│              │  CYBERFORGE 2026 · DATA SET: FIREX30.DB              │
│  Database    │──────────────────────────────────────────────────────│
│  Log file    │  RISK SCORE   RAW ALERTS   ATTACK STEPS   HOSTS       │  ← incident header
│  Run         │  65.9/100     3            3              1           │
│  detection   │  notes on blocked threats / estate-wide activity      │
│              │──────────────────────────────────────────────────────│
│  Groq key    │  Report  Investigator  Timeline  Attack graph  ...    │  ← tabs
│  Legend      │                                                      │
│  Incident ▾  │  (contents of the selected tab)                      │
└──────────────┴──────────────────────────────────────────────────────┘
```

* **The sidebar** chooses *what* you look at: which data set and which incident.
* **The header** summarises the chosen incident in four numbers.
* **The tabs** answer one question each, in the order an analyst works:
  understand it → question it → see the evidence → find what is missing →
  act → look ahead → hunt for more → check the data.

Everything below the sidebar always refers to the **incident selected in the
sidebar**.

---

## 3. The sidebar

| Control | What it does |
|---|---|
| **Database** | Picks which analysed data set to show. Every log file gets its own database (`firex30.db`, `chronopath.db`, ...), so results never overwrite each other. |
| **Log file** | The log that **Run detection** will analyse. It defaults to the file the current database was built from. |
| **Run detection** | Runs the whole pipeline on that log, then switches the page to the new database. Its output appears below the button. Click it **once** and wait — two runs at the same time halve the speed of both. |
| **Groq API key** | Shows whether the AI key was found, and how to add one. |
| **Legend** | Colours used in the attack graph (see [section 8](#8-attack-graph)). |
| **Incident** | The list of incidents, **worst first**. Choosing one changes everything on the page. |

**Example.** With `firex30.db` selected, the incident list shows:

```
INC-01 — risk 65.9/100 (3 steps)
INC-02 — risk 58.3/100 (2 steps)
INC-03 — risk 57.0/100 (3 steps)
INC-04 — risk 37.0/100 (1 steps)
INC-05 — risk 37.0/100 (1 steps)
```

An **incident** is a group of detections that ChronoPath believes are one
attack. 1.5 million detections in this file were reduced to these five.

---

## 4. The incident header

Four figures for the selected incident:

| Figure | Meaning | INC-01 |
|---|---|---|
| **Risk score** | 0–100, how urgent the incident is. Combines severity, how far along the attack got, how many machines and accounts are involved, and whether steps succeeded. Incidents are ranked by it. | 65.9/100 |
| **Raw alerts merged** | How many original log events stand behind the incident. One detection can summarise many events (for example "200 failed logins"). | 3 |
| **Attack steps** | Distinct detections in the incident. | 3 |
| **Hosts involved** | Machines touched. | 1 (`10.10.99.1`, the firewall) |

Below the figures, two notes may appear:

* **Blocked threats.** *"2689 blocked threat(s) covering 4041 detection(s) are
  not shown as incidents"* — groups where every step was stopped by a security
  control or was only an attempt (failed logins with no success). They are
  counted rather than hidden, so "nothing found" is never confused with
  "found and filtered".
* **Estate-wide activity** (click to open). Techniques that appear on most
  machines, so they cannot point at any one victim. They are summarised in one
  line each instead of being turned into thousands of incidents. Example:

  | Technique | Name | Machines | Accounts | Detections | Allowed through |
  |---|---|---|---|---|---|
  | UNMAPPED | Policy violation with no ATT&CK mapping | 1386 | 0 | 585,211 | 295,275 |
  | T1190 | Exploit Public-Facing Application | 1386 | 0 | 198,803 | 39,847 |
  | T1210 | Exploitation of Remote Services | 1386 | 0 | 36,156 | 7,254 |

  "Accounts" is 0 because firewall intrusion-prevention and antivirus records
  carry no user name — that is a property of the data, not an error.

---

## 5. Report

**Question it answers:** *What happened, in plain English?*

A short written account of the incident: how it started, how it progressed,
and what is now at risk.

* With a Groq key, an AI model writes it from the structured facts.
* Without one, a built-in summary is shown (marked *"Built-in summary"*).
* **Structured data sent to the model** (expander) shows exactly what the model
  was given, so any sentence can be checked against it. The AI only receives
  facts ChronoPath established — including the proven links between steps — so
  it cannot "discover" anything that is not in the data.

**Example (INC-01, structured data):**

```
Incident INC-01
Risk score: 65.9/100
Window: 2026-10-28T06:13:50 to 2026-10-28T06:24:37
Accounts: chirag._Team, svc_backup57

Attack steps in order:
  1. [Persistence] T1136 Create Account - Firewall Admin Account Created ... by user chirag._Team
  2. [Initial Access] T1078 Valid Accounts - Admin Login Successful from External IP ... by user svc_backup57
  3. [Defense Evasion] T1070 Indicator Removal - Firewall Admin Account Deleted ... by user chirag._Team

How the steps are linked (from the evidence):
  - [HARD] Linked: the account svc_backup57 was created by this event, and
    svc_backup57 is the account acting 5 min later ...
```

In words: *chirag._Team created a new administrator account svc_backup57;
eleven minutes of activity later, svc_backup57 logged in from outside the
company and chirag._Team deleted the account again.*

---

## 6. Investigator

**Question it answers:** *What am I missing, and what should I check next?*

A sceptical second reader. Where the other tabs report what ChronoPath found,
this one questions it: what does not fit, what correlation left out, what else
could explain it, and what to investigate next. It works without an API key.

**Its rule: it never invents evidence.** Every statement cites the item it
rests on, using these IDs:

| ID | Meaning |
|---|---|
| **E** | a detection in this incident (E1 = first step) |
| **L** | a link between two detections |
| **G** | a gap — evidence that was never supplied |
| **X** | the same account, address or machine elsewhere in the data |
| **I** | an indicator (account, IP) with first and last sighting |
| **S** | a comparison with another incident |
| **C** | a measurement of the whole file's coverage — e.g. *70% of all events are stamped within one hour*, a clock that stopped |
| **P** | a system that *could* be reached next — a prediction |

Each statement is also labelled **fact**, **inference**, **hypothesis**,
**prediction** or **recommendation**, so you can see what is observed and what
is reasoning.

The tab has six parts:

### 6.1 Next moves

A ranked to-do list, each with the reason and the evidence behind it, and
**Done** / **Dismiss** buttons. Completed moves are not suggested again —
unless the evidence they rest on changes, in which case they come back marked
*revisit*. Nothing is ever carried out automatically.

```
90  Get the configuration change history covering 2026-10-28T06:13:50 onwards,
    and list every other account chirag._Team has created [G2].
85  Retrieve authentication records for chirag._Team on 10.10.99.1 before
    2026-10-28T06:13:50 [G1, G3].
85  Review chirag._Team's detections from 2026-10-25T09:35:41 up to the incident
    start, oldest first, and decide which belong to this incident.
```

### 6.2 What caught my attention

Observations, each written in seven parts:

| Part | Label | Example (INC-01) |
|---|---|---|
| Observation | fact | Admin Login Successful from External IP (Initial Access) at 06:19:01 comes after Firewall Admin Account Created (Persistence) at 06:13:50. [E1, E2] |
| Reasoning | inference | Initial access normally comes before persistence. Either an earlier access was missed, or the actor's access predates the incident. |
| Connection | fact | chirag._Team also logged in from an external IP on 2026-10-25T09:35:41, outside this incident. [X1] |
| Hypothesis | hypothesis | The real entry point predates 06:13:50 and was not detected. |
| Counterargument | inference | Stage labels come from rules, not intent; E2 may be a second way in. |
| Unknowns | fact | How the actor of E1 authenticated before 06:13:50. [G1, G3] |
| Next move | recommendation | Retrieve authentication records for chirag._Team before 06:13:50. |

That *Connection* is a genuine lead: the account that created the backdoor had
logged in from outside **three days earlier**, and correlation had left that
login out of the incident.

The checks it runs: kill-chain steps out of order; accounts created, used and
deleted; logins with or without failed attempts before them; out-of-hours and
machine-speed timing; links that are weak; one outside address behind several
accounts; other incidents sharing an account; and everything the data does not
cover. **Mark evidence examined** records that you have looked.

### 6.3 Theories

Six competing explanations for every incident, each with the evidence **for**
and **against**, what is missing, how to tell it from its closest rival, what
would disprove it, and a seven-question self-review (*Am I assuming causation
from correlation? Is there a legitimate explanation? ...*).

| Theory | INC-01 status | Why |
|---|---|---|
| H6 The attack began before the first detection | **leading** | Steps out of order; the account was active before |
| H1 Outside attacker with a stolen credential | plausible | External login, evidence deleted, short-lived account |
| H2 Insider misusing legitimate access | plausible | Established account; no password guessing |
| H4 Automated tool | unsupported | Creating and deleting a named account is deliberate work |
| H5 Two unrelated activities merged | **abandoned** | Every step is joined by a HARD link |
| H3 Routine administrative work | **abandoned** | Logging was disabled and administration came from outside |

A theory is **abandoned** automatically when two strong contradictions
appear, and the reason is shown. Confidence never reaches *high* while
evidence the conclusion depends on was not supplied. You can **Accept** or
**Reject** a theory yourself (with a reason); the decision is kept.

### 6.4 Ask the investigator

Eight standard questions as buttons, plus a free-text box:

* What am I missing in this investigation?
* Find something unusual that has not been investigated.
* Challenge my current attack theory.
* Think of another explanation for this incident.
* What would an attacker likely have done next?
* Which evidence should I investigate first?
* Find connections I may have overlooked.
* Try to disprove this attack hypothesis.

**Example.** *"Try to disprove this attack hypothesis."* → *"Trying to disprove
H6: The attack began before the first detection. The data does not disprove
it."*, followed by the evidence for and against, the self-review, and the test
that would disprove it: *complete logs for the period before show no activity
by the actor.*

Free text works too, e.g. *"Is 7.39.133.59 involved anywhere else?"* finds the
observations that mention that address.

Answers about the future are always labelled **prediction** and say that
nothing in the data shows them happened. With a Groq key, the AI may phrase the
answer — but its answer is **thrown away** if it cites an ID, timestamp or IP
address that is not in the evidence, or claims to have done something; the
reasons are shown and the built-in answer is used instead.

### 6.5 Investigation memory

Your decisions, completed and dismissed moves, open questions and rejected
theories for this incident, plus a box to **record a decision**. Stored under
`investigations/` and kept between sessions, even if the incidents are
renumbered by a new run.

### 6.6 Evidence pack

Every citable item (E1, L1, G1, ...) in one table, so any citation can be looked
up.

---

## 7. Timeline

**Question it answers:** *In what order did it happen?*

The incident's steps in time order. Time order is what turns separate alerts
into a story.

| # | Time | Kill chain stage | ATT&CK | Detection | Host | Account | Sev |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-28 06:13:50 | Persistence | T1136 Create Account | Firewall Admin Account Created | 10.10.99.1 | chirag._Team | 10 |
| 2 | 2026-10-28 06:19:01 | Initial Access | T1078 Valid Accounts | Admin Login Successful from External IP | 10.10.99.1 | svc_backup57 | 10 |
| 3 | 2026-10-28 06:24:37 | Defense Evasion | T1070 Indicator Removal | Firewall Admin Account Deleted (Anti-Forensics) | 10.10.99.1 | chirag._Team | 10 |

* **Kill chain stage** — where the step sits in a typical attack (reconnaissance
  → access → persistence → ... → impact).
* **ATT&CK** — the standard MITRE code and name for the technique.
* **Sev** — severity 1–10 from the detection rule.

---

## 8. Attack graph

**Question it answers:** *Who and what is connected, and where can it spread?*

A diagram read left to right: outside addresses → accounts → machines →
systems reachable next.

| Shape and colour | Meaning |
|---|---|
| Purple diamond | External IP address (outside the company) |
| Red ellipse | Account involved in the attack |
| Red box | Compromised machine |
| Dashed amber box | Reachable next, not yet touched |
| Number on an arrow | Step number from the Timeline |
| Thick red arrow | Severity 9 or higher |

**Example (INC-01):** `7.39.133.59` (purple) → `chirag._Team` and
`svc_backup57` (red) → firewall `10.10.99.1` (red box).

---

## 9. Evidence

**Question it answers:** *Why do these events belong together?*

ChronoPath groups detections that share an account, address or machine within
a time window. This tab explains every connection.

**Links, graded by strength:**

| Grade | Meaning |
|---|---|
| **HARD** | The same account acted in both events, or one event created the account that acted in the other. |
| **SOFT** | A shared outside address or machine — good evidence, but an address can be a VPN or NAT shared by strangers. |
| **INFERRED** | Context only: same machine within 15 minutes. |
| **UNRESOLVED** | A candidate link that was refused (see below). |

**Example (INC-01):**

| Grade | Linked by | Gap | Why |
|---|---|---|---|
| HARD | identity pivot: svc_backup57 | 5 min | step 1 created svc_backup57, the account acting in step 2 |
| HARD | account: chirag._Team | 11 min | the same account in steps 1 and 3 |
| SOFT | source IP: 7.39.133.59 | 6 min | the same outside address in steps 2 and 3 |

The tab also has:

* **Links we deliberately refused** — values that were *not* used as links,
  usually shared infrastructure (an address used by many accounts), with the
  counts that triggered the refusal.
* **Original log lines** — enter the log file and click **Fetch raw lines for
  this incident** to see the exact records from the source file.
* **Why INC-01 is separate from the others** — a check against every other
  incident. Example: *vs INC-04 — SHARED_ENTITY_PRESENT: INC-01 and INC-04 DO
  share account chirag._Team. They are reported separately because the shared
  activity falls outside the correlation window, so review them together.*

---

## 10. What we can't see

**Question it answers:** *What could not have been detected, and what should I
ask for?*

Most tools only report what they found; silence then reads as "nothing
happened". This tab lists the gaps. Each one says **what establishes it**,
**what you therefore cannot conclude**, and **what to request next**.

**Missing is not malicious.** A gap is never called deletion unless an event
proves it. Classifications:

| Class | Meaning |
|---|---|
| `NOT_COLLECTED` | No supplied source contains this kind of data. |
| `COVERAGE_UNKNOWN` | We cannot tell whether it was collected. |
| `LOGGING_DISABLED_BY_ACTOR` | Someone disabled logging **and** data measurably stopped. |
| `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA` | Logging was disabled but the data kept arriving. |
| `PARSE_FAILURE` | Rows that could not be read. |

**Example (INC-01, `NOT_COLLECTED` — identity provider):** *What you cannot
conclude: whether MFA was satisfied, bypassed or not configured, and whether
the same credentials worked elsewhere. Request: identity-provider audit log for
chirag._Team, svc_backup57 covering 06:13:50 to 06:24:37.*

**Example (INC-02, the blind window):** harshit.verma disabled logging on the
firewall at 2026-10-28 09:04:06. The chart compares log volume during that
window with the hours around it. Volume did **not** drop, so the gap is
classified `LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA`: the attempt to blind
the logging did not work — a measured result, not a guess.

**Estate-wide gaps** cover the whole data set, for example *COVERAGE_UNKNOWN —
nothing covers the period before 2026-10-23 08:48:37, the first event in the
file.*

---

## 11. Respond now

**Question it answers:** *What do I do in the next ten minutes?*

**Indicators** — the accounts, addresses and created accounts in the incident,
looked up across the **whole** data set:

| Type | Value | First seen | Last seen | Detections | Note |
|---|---|---|---|---|---|
| account | chirag._Team | 2026-10-25T09:35:41 | 2026-10-28T06:24:37 | 3 | |
| account | svc_backup57 | 2026-10-28T06:19:01 | 2026-10-28T06:19:01 | 1 | |
| source_ip | 7.39.133.59 | 2026-10-28T06:13:50 | 2026-10-28T06:24:37 | 3 | |
| account_created | svc_backup57 | 2026-10-28T06:19:01 | 2026-10-28T06:19:01 | 1 | Created and deleted during this incident — the only record is this log. |

A red banner appears if any indicator was seen **after** the incident ended
("This is not over"); otherwise a green note says nothing suggests it
continued. A copyable list of indicators is provided for blocking or
searching.

**What preceded the first detection** — activity by the same indicators in the
six hours before. Example: *No activity was recorded in the 6 hours before
2026-10-28 06:13:50. That is a finding, not a blank: there is no
password-guessing burst to explain the access, so the credential was most
likely already known.*

**Recommended actions** — rule-based, not written by AI, and **never carried
out automatically**:

| Priority | Because | Steps |
|---|---|---|
| IMMEDIATE | Admin login succeeded from an external address for chirag._Team, svc_backup57 | Reset their credentials and end active sessions; restrict the admin interface to the management network |
| HIGH | Indicator removal was observed | Preserve current logs and configuration now; treat missing later evidence as unresolved |
| STANDARD | External address 7.39.133.59 involved | Block it at the perimeter after confirming it is not a shared VPN/NAT address; add it to a watchlist |

---

## 12. What's next

**Question it answers:** *What could the attacker reach from here?*

Systems one step away from what was touched, most critical first, from the
asset and privilege inventory:

| Column | Meaning |
|---|---|
| Target | The reachable system |
| Role | What it is (domain controller, file server, ...) |
| Criticality | 1–10 importance from the inventory |
| Basis | `privilege` = standing admin rights; `observed` = a path already seen in the logs |
| Why | The reason it is reachable |

A red banner lists critical systems (criticality 9–10) within reach. On the
sample data set, for example: *Critical systems within reach: DC-01, DC-02,
FS-03.* These are **possibilities**, not observed activity.

---

## 13. Threat hunting

**Question it answers:** *What looks odd, even if no rule flagged it?*

This tab uses **no detection rules**. It ranks every account, address, machine
and process by how anomalous it is: rare things that are severe and span
several attack stages score highest. Attackers touch few things; routine noise
touches many.

**Detections over time** — a bar chart per hour; attacks usually arrive in
bursts. On `firex-30G.log` the chart shows one enormous bar: *Busiest hour:
2026-10-30T08 with 1,073,914 detections.* That is a property of the file, not
of the analysis: from about 30% of the way in, every line carries the same
timestamp (`2026-10-30 08:48:36`).

**Anomaly tables** (top entries, `firex30.db`):

| Kind | Value | Anomaly | Events | Worst severity |
|---|---|---|---|---|
| Users | Ravi.Thomas | 85.0 | 1 | 10 |
| Users | svc_backup57 | 85.0 | 1 | 10 |
| Source IPs | 7.39.133.59 | 87.3 | 3 | 10 |

The attacker's address `7.39.133.59` comes out top among about 1,500 source
addresses on statistics alone, and both top users belong to incidents.

---

## 14. Sources

**Question it answers:** *Can I trust the data underneath all of this?*

For each input file:

| Item | `firex-30G.log` |
|---|---|
| Format | fortigate |
| Events | 37,183,090 |
| Streams | 12 |
| Size | 18.27 GB |
| Time range | 2026-10-23 08:48:37 → 2026-10-30 08:48:36 |
| Timestamp field used | date + time (FortiGate wall clock) |
| SHA-256 | `eb3cc08e…193a207a` |

* **SHA-256** pins the exact bytes the findings came from: a file name can be
  reused, a hash cannot.
* **Rejected / unparseable rows** are counted and shown, never silently
  dropped. Here: every row was read and carried a parseable timestamp.
* **Clock check** compares the two clocks in each FortiGate line, which is what
  prevents a silent five-and-a-half-hour time-zone error.
* **Telemetry streams** — the log mixes independent subsystems, each with its
  own coverage. Largest here: `traffic/forward` 23.8 M events,
  `event/system` 5.9 M, `utm/webfilter` 1.7 M, `utm/dns` 1.1 M.
* **Event volume over the whole file** — a steady line means steady
  collection; a cliff means something stopped sending.

---

## 15. Live mode

**Question it answers:** *What is happening right now?*

Choose **Live** under **Mode** at the top of the sidebar. Instead of a finished
analysis, this page follows a log file that is still being written, through
`src/live_detector.py`, and refreshes itself every 3 seconds.

**Starting it** (three terminals, from the `chronopath` folder):

```powershell
python src/live_detector.py --input data/live.ndjson
python scripts/replay.py --source data/sample.ndjson --target data/live.ndjson --start 2026-10-20T12:50:00 --speed 10
streamlit run src/app.py
```

The second command plays the recorded sample attack into the file at ten times
real speed, so the attack unfolds in about three minutes.

**What the page shows**

| Part | Meaning | Example (mid-replay) |
|---|---|---|
| Lines / s | How fast new log lines are arriving | 134 |
| Alerts | Detections so far | 8 |
| Incidents | Reported incidents so far | 1 |
| Latency p50 | Typical delay from a line being written to its alert appearing | 1.85 s |
| Last tick | When the detector last processed new lines | 1 s ago |
| Incidents table | Live incidents, highest risk first. **Version** goes up each time an incident gains a step | `L00001`, risk 86, 8 steps, version 9 |
| Graph and steps | The selected incident, drawn exactly as in Investigate mode | the vendor account → HR-07 → FS-02 → external IP |
| Write narrative | The AI summary, written **only when clicked** and remembered for that version | built-in summary until clicked |
| Newest alerts | The last 25 detections, each with its own latency | *Large Outbound Data Transfer — 0.10 s* |

**Good to know**

* It is **micro-batch**: new lines are processed every 2 seconds, so results
  appear about 1–2 seconds after a line is written, not instantly.
* It uses the same rules and the same scoring as Investigate mode; on the same
  data both produce the same incidents.
* Live incidents are named `L00001`, `L00002`, ... rather than `INC-01`, because
  their ranking changes while the attack is still happening.
* If the detector stops, the page says so and keeps showing the final state.

---

## 16. The same features without the website

| Want | Command |
|---|---|
| Analyse a log | `python src/parser.py --input <log> --db <name>.db` |
| Investigator brief | `python src/investigate.py --db firex30.db` |
| Ask one question | `python src/investigate.py --db firex30.db --ask "What am I missing?"` |
| Interactive investigator | `python src/investigate.py --db firex30.db --chat` |
| REST API | `python src/api.py`, then e.g. `GET /incidents`, `/incidents/INC-01/path`, `/incidents/INC-01/elliot`, `/incidents/INC-01/elliot/ask?q=...` |
| Live detection | `python src/live_detector.py --input data/live.ndjson` |
| Replay a log into it | `python scripts/replay.py --source data/sample.ndjson --target data/live.ndjson --speed 10` |
| Check the whole project | `python verify.py` |

---

## Glossary

| Term | Meaning |
|---|---|
| **Detection** | One suspicious event (or summary of many) found by a rule. |
| **Incident** | Detections grouped together as one probable attack. |
| **Correlation** | Grouping detections that share an account, address or machine within a time window. |
| **Kill chain** | The usual stages of an attack, from reconnaissance to impact. |
| **MITRE ATT&CK** | The standard catalogue of attacker techniques; codes like T1078. |
| **Anchor** | A rare detection that can single out a victim; it starts an incident. |
| **Estate-wide / ambient** | A technique seen on most machines; context, not a lead. |
| **Identity pivot** | A record naming two accounts — e.g. one account creating another. |
| **Indicator (IOC)** | A concrete value to block or search for: an IP, an account. |
| **Blind window** | A period when someone tried to stop logging. |
| **Telemetry** | The logs and signals a system produces. |
| **Prediction** | Something that *could* happen next. Never observed activity. |
| **Micro-batch** | Processing new data in small groups every few seconds, instead of one line at a time. |
| **Latency** | The delay between a log line being written and its alert appearing. |
