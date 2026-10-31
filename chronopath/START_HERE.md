# START HERE — ChronoPath explained from zero

You don't need any security background to read this. By the end you'll know
what problem we're solving, what we built, and how to run and explain it.

**Read this first, then [READTHIS.md](READTHIS.md) if you want more depth.**

---

## Part 1 — The problem, in plain English

### A story

A company has a few hundred laptops, servers and staff. Every machine writes a
log — a diary of everything that happens. Millions of lines a day.

An attacker breaks in. Here's what they do over several days:

1. Guesses passwords until one works
2. Gets onto a laptop
3. Creates themselves a new admin account so they can come back
4. Moves across to a file server
5. Copies the company's data out to the internet

Each step leaves **one line** in a log. Nine million other lines sit around
them.

### Why this is hard

Security tools *do* notice individual things. They raise alerts:

```
09:14   "Lots of failed logins"      ← looks like someone forgot their password
09:22   "New admin account created"  ← looks like IT onboarding a new hire
09:31   "Large upload to internet"   ← looks like a backup job
```

Each alert, on its own, looks boring. **Together they're a break-in.**

The problem is nothing connects them. A human analyst *can* work it out — by
reading logs for hours, while the attacker keeps going. And in the famous 2013
retail breach (110 million customers' data stolen), **the alerts did fire.
Nobody joined them up.**

### So what are we building?

A tool that does the joining-up automatically:

> Read a huge pile of logs → find the suspicious bits → work out which ones
> belong to the same attack → show it as one story → say where the attacker
> could go next.

That's it. That's the whole project.

### The extra difficulty: size

The log file is **6.5 GB**. Your laptop has 16 GB of memory.

The obvious approach — load the file, then search it — doesn't work. The
moment you load a file that big (plus Windows, plus Chrome, plus Python), you
run out of memory and the program dies.

**Most of our engineering effort went into this one constraint.** More below.

---

## Part 2 — The five words that explain everything

Every security tool talks in this jargon. Learn these five and the rest follows.

| Word | What it means | Everyday analogy |
|---|---|---|
| **Log** | A line recording one thing that happened | A CCTV frame |
| **Detection** | A log line we think is suspicious | A frame where someone's climbing a fence |
| **Incident** | Several detections that are the same attack | All the frames of one burglary, in order |
| **MITRE ATT&CK** | A worldwide catalogue of attacker tricks, each with a code | A crime classification: "T1110 = password guessing" |
| **Kill chain** | The stages of a break-in, in order | Case the place → get in → grab stuff → leave |

**The one sentence that captures the project:**

> We turn millions of **logs** into a few **detections**, group those into
> **incidents**, label each step with **MITRE ATT&CK**, and lay them out along
> the **kill chain** so it reads as a story.

### The kill chain stages you'll see in our output

Roughly in the order an attacker moves through them:

```
Initial Access      → got in
Execution           → ran something
Persistence         → made sure they can come back
Privilege Escalation→ became an admin
Credential Access   → stole passwords
Defense Evasion     → covered their tracks
Lateral Movement    → spread to other machines
Collection          → gathered the data
Exfiltration        → sent it out
Impact              → caused damage (e.g. ransomware)
```

---

## Part 3 — How ChronoPath works

### The big idea (this is what to tell judges)

```
    6.5 GB of logs on disk
             │
             │  ❶ READ IT WITHOUT LOADING IT
             │     Read a chunk, check it, throw it away, repeat.
             │     Memory stays flat no matter how big the file is.
             ▼
    ~400,000 suspicious events   (a tiny fraction)
             │
             │  ❷ JOIN THE DOTS
             │     Which of these share a user, a machine, a time?
             ▼
    14 incidents, worst first
             │
             │  ❸ EXPLAIN IT
             ▼
    Timeline + graph + plain-English report
```

**Why it works:** the expensive job (reading 6.5 GB) is given to a tool built
for exactly that — a streaming database. The clever job (working out what
connects to what) only happens *after* the data has shrunk to something small
enough to hold in memory.

Neither tool is asked to do the other's job. **That's the whole trick.**

### Step 1 in more detail — reading without loading

Imagine finding every mention of one name in a 10,000-page book.

- **The bad way:** photocopy all 10,000 pages, spread them on the floor, then
  look. You run out of floor. *(= loading the file into memory → crash)*
- **Our way:** read one page, note anything relevant, turn the page. You only
  ever hold one page. *(= streaming)*

We use **DuckDB**, a database that does this natively. We proved it: scanning
a 602 MB file used only about **300 MB of memory** — *less than the file
itself*, which is only possible if it was never fully loaded.

### Step 2 in more detail — joining the dots

Two detections belong to the same attack if they share something and happen
near each other in time:

```
Event A: user "Rakes" creates account "svc_backup30"
Event B: user "svc_backup30" logs in            ← 6 minutes later
Event C: user "Rakes" deletes "svc_backup30"    ← 5 minutes after that
```

A and C share the user `Rakes`. B shares the account name with A. So all three
are **one incident** — and that incident reads:

> *Someone created an admin account, used it, and deleted it within twelve
> minutes.*

That's not administration. That's covering tracks. **And that is the real
attack we found in the organisers' actual data file.**

### Step 3 — showing it

Three ways to look at the same result:

1. **A web dashboard** — timeline, a picture of the attack, plain-English summary
2. **A REST API** — `GET /incidents/1/path` for programmatic access
3. **The terminal** — for a quick look

---

## Part 4 — What's actually in the folder

### The files you'd actually open

| File | What it is |
|---|---|
| **START_HERE.md** | This file |
| [README.md](README.md) | The main summary with all results |
| [SETUP.md](SETUP.md) | Install steps and troubleshooting |
| [READTHIS.md](READTHIS.md) | Deeper explanations + judge Q&A |
| [FIREX_RESULTS.md](FIREX_RESULTS.md) | What we found in the real 6.5 GB file |

### The code — six files, each with one job

| File | Job | Analogy |
|---|---|---|
| [src/parser.py](src/parser.py) | Reads huge logs, finds suspicious lines | The reader with a highlighter |
| [src/graph_engine.py](src/graph_engine.py) | Joins detections into incidents | The detective with the pin-board |
| [src/app.py](src/app.py) | Web dashboard | The presentation |
| [src/api.py](src/api.py) | REST API | The machine-readable version |
| [src/fortigate_adapter.py](src/fortigate_adapter.py) | Understands the real file's format | A translator |
| [src/ecs_adapter.py](src/ecs_adapter.py) | Understands a different log format | Another translator |

> **Why two translators?** Different security products write logs differently —
> like different countries writing dates differently. Rather than rewrite the
> whole tool for each, we translate each format into one common shape. The rest
> of the code never knows the difference.

### The rules — where the detection knowledge lives

| File | For which format |
|---|---|
| [rules_fortigate.yaml](rules_fortigate.yaml) | **The real 6.5 GB file** |
| [rules_ecs.yaml](rules_ecs.yaml) | The EDR sample generator |
| [rules.yaml](rules.yaml) | Our own test data |

A rule is just a description of something suspicious. Here's a real one,
readable even if you've never coded:

```yaml
- name: "Firewall Admin Account Created"
  mitre_technique: "T1136"          # the worldwide code for "created an account"
  kill_chain_stage: "Persistence"   # which stage of the break-in
  severity: 10                      # out of 10 — as bad as it gets
  sql_condition: "fg_msg LIKE 'Add system.admin%'"   # what to look for
```

**This matters for marking:** one of the bonus points is "add a new detection
rule by editing a config file, not code". That's this. You add a rule by typing
six lines of text — no programming.

---

## Part 5 — What we actually found

The organisers gave us `firex-10G.log` — **6.5 GB, 9,125,382 events** from a
firewall, covering 23–29 October.

### The key insight: rarity, not volume

Our instinct was to look for the *most common* suspicious thing. That turned
out to be exactly backwards:

```
Failed admin logins ....... 1,272,524    ← this is just the internet,
                                            constantly guessing passwords.
                                            Background noise.
Successful admin logins ........... 5    ← THIS is the break-in.
```

A million failures is what happens to every firewall on the internet, all day.
**Five successes is the attack.** The signal is 250,000× rarer than the noise.

### The attack, as ChronoPath reconstructs it

| When | Who | What |
|---|---|---|
| 23 Oct 16:31 | Tejas.Roy | **Turned the logging off** |
| 23 Oct 18:28 | Tejas.Roy | **Deleted the firewall rules** (while blind) |
| 24 Oct 19:59 | parul.sinha | Admin login succeeded |
| 28 Oct 02:15 | keerat.ghughal | VPN login — *from two countries, 7 min apart* |
| 28 Oct 03:17 | Deepika.Khan | Admin login succeeded (×3) |
| **29 Oct 03:55** | **Rakes** | **Created admin account `svc_backup30`** |
| **29 Oct 04:02** | **svc_backup30** | **Logged in with it** |
| **29 Oct 04:07** | **Rakes** | **Deleted it** |

The last three lines are the clearest evidence in nine million records.

### The numbers

| | Result |
|---|---|
| Whole 6.5 GB file processed | **66.8 seconds** |
| Peak memory used | **422 MB** (we were allowed 8 GB) |
| Attack steps found | **100%** |
| Correctly labelled | **87.5%** |
| Time to open an incident | **4 milliseconds** (allowed 500) |

---

## Part 6 — Running it yourself

```bash
# one-time install
pip install -r requirements.txt

# the quick demo: makes fake logs with a known attack, finds it, scores itself
python run_demo.py

# see the dashboard
streamlit run src/app.py

# or the API
python src/api.py
# then open http://localhost:8000/incidents/1/path
```

### On the real 6.5 GB file

```bash
python src/parser.py --input D:/mitigata/firex-10G.log --memory-limit 6GB
python src/graph_engine.py
```

Takes about a minute. The format is detected automatically.

### Prove the memory claim live

```bash
python scripts/benchmark.py
```

Shows memory used coming in *below* the file size — the strongest thing you
can show a judge, because it proves streaming rather than asserting it.

---

## Part 7 — Videos to watch

Links are **YouTube searches**, not fixed video IDs — deliberately, so none of
them can be dead on the day. Click and take the top result from the named
channel.

### If you watch nothing else (30 minutes)

| # | Topic | Why |
|---|---|---|
| 1 | [What is a SIEM?](https://www.youtube.com/results?search_query=what+is+a+SIEM+IBM+Technology) — *IBM Technology* | Explains the exact problem we're solving |
| 2 | [Cyber Kill Chain explained](https://www.youtube.com/results?search_query=cyber+kill+chain+explained+7+stages) | The attack stages we label |
| 3 | [MITRE ATT&CK in 10 minutes](https://www.youtube.com/results?search_query=MITRE+ATT%26CK+framework+explained+beginners) | Where the T-codes come from |
| 4 | [DuckDB in 100 Seconds](https://www.youtube.com/results?search_query=DuckDB+in+100+Seconds+Fireship) — *Fireship* | The tool that handles 6.5 GB |

### The story behind our demo

| Topic | Why it matters |
|---|---|
| [Target 2013 data breach explained](https://www.youtube.com/results?search_query=Target+2013+data+breach+explained) | The hackathon brief references this breach. Alerts fired; nobody connected them. That gap is the entire reason this project exists. |

### If you want to understand the code

| Topic | For which file |
|---|---|
| [NetworkX Python tutorial](https://www.youtube.com/results?search_query=NetworkX+python+tutorial+graph+theory) | `graph_engine.py` |
| [Streamlit crash course](https://www.youtube.com/results?search_query=streamlit+python+crash+course) | `app.py` |
| [DuckDB Python tutorial](https://www.youtube.com/results?search_query=DuckDB+python+tutorial) | `parser.py` |
| [Union-find explained](https://www.youtube.com/results?search_query=union+find+disjoint+set+explained) | The grouping algorithm |
| [What is a REST API?](https://www.youtube.com/results?search_query=what+is+a+REST+API+explained) | `api.py` |
| [YAML in 5 minutes](https://www.youtube.com/results?search_query=YAML+tutorial+explained+5+minutes) | The rule files |

### Reference (better than videos for exact detail)

- **[attack.mitre.org](https://attack.mitre.org)** — look up any T-code we output
- **[duckdb.org/docs](https://duckdb.org/docs)** — the database docs

---

## Part 8 — Questions you might be asked

**"What does your tool do?"**
> It reads millions of security logs, picks out the suspicious ones, works out
> which belong to the same attack, and shows it as one story with a timeline
> and a graph — plus what the attacker could reach next.

**"How do you handle 6.5 GB on a 16 GB laptop?"**
> We never load the file. We stream it — read a chunk, filter it, discard it.
> We measured 602 MB scanned using ~300 MB of memory, less than the file size,
> which is only possible with streaming. `scripts/benchmark.py` shows it live.

**"What did you find in the real data?"**
> An admin account created, used, and deleted within twelve minutes, preceded
> by someone turning off the firewall's logging and wiping its rules. We found
> it by looking for rare events rather than common ones — 1.27 million failed
> logins are noise, but there were only five successes.

**"How do you know your results are right?"**
> We score ourselves against a known answer. `python scripts/evaluate.py`
> prints detection rate, label accuracy and false alarms every run.

**"Is the AI making up the attack?"**
> No. Detection and grouping are deterministic — same input, same output, no AI
> involved. The AI only rewrites the finished result as a readable paragraph.
> Unplug the internet and the tool still finds the attack.

**"What doesn't work?"**
> On the real file the attack comes back as five incidents instead of one,
> because the attackers used different accounts and IPs with nothing linking
> them. And our thresholds were tuned on the same data we score on, so a
> held-out data set is the honest next test. Accuracy is now 100% detection,
> 100% labels and 0% false alarms under a stricter scorer; the earlier 78%
> false-alarm figure and how we fixed it are in [FIREX_RESULTS.md](FIREX_RESULTS.md).

---

## Part 9 — Glossary

| Term | Plain English |
|---|---|
| **Log / event** | One line recording one thing that happened |
| **Detection** | A log line we flagged as suspicious |
| **Incident** | A group of detections that are one attack |
| **MITRE ATT&CK** | Catalogue of attacker techniques, each with a T-code |
| **Kill chain** | The ordered stages of a break-in |
| **SIEM** | The security tool that collects logs and alerts |
| **EDR** | Security software on laptops/servers |
| **FortiGate** | The firewall brand that wrote our real log file |
| **Brute force** | Guessing passwords over and over |
| **Lateral movement** | Spreading from one machine to another |
| **Exfiltration** | Stealing data out of the company |
| **Persistence** | Making sure you can get back in later |
| **Anti-forensics** | Destroying evidence |
| **Streaming** | Processing a file in pieces instead of loading it |
| **DuckDB** | The database that does the streaming |
| **NetworkX** | The Python library that builds the attack graph |
| **Streamlit** | The library that makes the web dashboard |
| **Graph** | Dots (users, machines) joined by lines (actions) |
| **YAML** | A simple text format for config files |
| **False positive** | Flagging something that wasn't actually an attack |
| **Ground truth** | The known correct answer, used for scoring |

---

**Next step:** run `python run_demo.py`, then open
[FIREX_RESULTS.md](FIREX_RESULTS.md) to see what we found in the real file.
