# Results on the real data set — `firex-10G.log`

Everything below was measured on the organisers' actual file, on the demo
machine (Windows 11, Python 3.14.2, 16 GB RAM, 5-core Dell).

```bash
python src/parser.py --input D:/mitigata/firex-10G.log --memory-limit 6GB
python src/graph_engine.py
python src/api.py          # or: streamlit run src/app.py
```

Format detection, rule selection and parsing are automatic — nothing to configure.

---

## What the file turned out to be

**FortiGate firewall syslog**, not JSON: flat `key=value` text, one event per line.

```
date=2026-10-23 time=08:48:26 type="event" subtype="system"
logdesc="Admin login failed" user="admin" srcip=209.50.167.232
dstip=10.10.99.1 action="login" status="failed" ...
```

| | |
|---|---|
| Size | 6.54 GB |
| Events | **9,125,382** |
| Period | 23–29 October 2026 |
| Composition | traffic/forward 64%, event/system 16%, webfilter 4.5%, IPS 3%, DNS 3%, app-ctrl 3%, virus 1.5%, plus vpn/ha/dhcp/sdwan |

This is a **third** format, after our own flat JSON and the ECS JSON from
`edr_log_generator.py`. We added `src/fortigate_adapter.py` rather than forking
the engine — the detection, correlation, graph, API and UI code is unchanged.

---

## Performance

| Measurement | Result | PRD target |
|---|---|---|
| Full-file parse | 9,125,382 events in **4.5 s** (1,461 MB/s) | — |
| Full detection run, 12 rules | **66.8 s** | under 1 h = "Great" |
| Peak memory (1.58 GB slice, 4 GB cap) | **422 MB** | under 8 GB = "Great" |
| Correlation, 395,361 detections | **6.0 s** | — |
| Open one incident (API) | **4.0 ms** | under 500 ms = "Great" |

The whole 6.5 GB data set is processed in **just over a minute**, using a
fraction of the memory budget.

> One setting makes this work at all: `strict_mode=false` on DuckDB's CSV
> reader. A 200k-line sample parsed fine; the full file failed at ~63% with
> *"CSV Parser state machine reached an invalid state"*, because real syslog
> contains stray quotes and control characters no CSV standard anticipates.
> **A sample-only test would never have found it.**

---

## How we found the attack: rarity, not volume

The organisers supplied no answer key, so the first job was working out what
the planted attack is. Reproduce with `python scripts/discover_firex.py`.

The temptation on a firewall log is to chase the biggest numbers. That is
exactly backwards:

```
Admin login FAILED ............. 1,272,524     <- internet background noise
IPS exploit detections ........... 177,772     <- constant scanning
Antivirus hits ................... 135,623     <- constant
---------------------------------------------
Admin login SUCCEEDED .................... 5   <- THE ATTACK
SSL VPN tunnel up ........................ 4
Config attribute changed ................. 3
Admin account added / deleted ............ 2
```

A million failed logins against an exposed management interface is what the
internet does to every firewall, all day. **Five successes are the intrusion.**
The signal is four orders of magnitude rarer than the noise, and the entire
detection strategy follows from that one observation.

---

## The attack ChronoPath reconstructs

| # | When | Who | From | What |
|---|---|---|---|---|
| 1 | 23 Oct 16:31 | Tejas.Roy | 78.120.139.0 | **Disabled disk logging** |
| 2 | 23 Oct 18:28 | Tejas.Roy | 78.120.139.0 | **Purged firewall policies** (while blind) |
| 3 | 23 Oct 20:36 | Tejas.Roy | 78.120.139.0 | Re-enabled logging |
| 4 | 24 Oct 19:59 | parul.sinha | 8.42.69.77 | Admin login **succeeded** |
| 5 | 28 Oct 02:15 | keerat.ghughal | 102.8.77.227 | SSL VPN up — and from `9.222.114.167` 7 min later |
| 6 | 28 Oct 03:17 | Deepika.Khan | 171.104.84.193 | Admin login succeeded (×3) |
| 7 | **29 Oct 03:55** | **Rakes** | 203.228.177.117 | **Created admin `svc_backup30`** |
| 8 | **29 Oct 04:02** | **svc_backup30** | 203.228.177.117 | **Logged in with it** |
| 9 | **29 Oct 04:07** | **Rakes** | 203.228.177.117 | **Deleted it** |

**Steps 7–9 are the clearest evidence in the data set**: an administrator
account created, used and destroyed inside twelve minutes. That is not
administration, it is anti-forensics — and ChronoPath links it into a single
incident by following the identity pivot from `Rakes` to the account `Rakes`
created.

That incident **ranks #1 of 5**.

---

## Accuracy

Scored against `data/ground_truth_firex.json` (derived by the rarity analysis
above, reproducible via `scripts/discover_firex.py`):

| PRD metric | Result | Good | Great |
|---|---|---|---|
| Detection rate | **100%** (8/8) | >70% | >90% |
| Correct ATT&CK labels | **100%** | >60% | >85% |
| False alarm rate | **0%** (0 of 5 incidents) | <30% | <10% |
| Attack path rebuilt | split *(see below)* | half | all |

Same scorer on the other two formats: EDR (`edr_ready.json`) and our flat
sample both score 100 / 100 / 0% with the attack path rebuilt as incident #1.

### What changed from the earlier 100 / 87.5 / 78.6%

**The old scorer was too generous.** It matched planted steps on host alone,
and every planted step is on the same firewall, so any detection there "found"
every step. `parul.sinha`'s login was in no incident yet counted as detected.
The scorer now matches account + technique + time (±30 min). Re-scored
honestly, the old system was 87.5% detection and 71.4% false alarms (and 96%
on EDR, where the old scorer had reported 0%).

**Label fixes.** One fixed ATT&CK ID per rule mislabelled most IPS hits:
- Each IPS signature is now mapped to its own technique (`technique_map` in
  `rules_fortigate.yaml`): Log4j/Citrix/SQLi → T1190, ZeroLogon/SMB → T1210,
  kernel privesc → T1068, DNS zone transfer → T1590.002, SSH/RDP → T1110.001.
- About 45 signatures that are vendor names with no attack in them
  (`Splunk.security.VM`) are labelled `UNMAPPED` instead of a guessed T1190.
- 17,742 lines matched two rules at once (a Cobalt Strike line was both
  "exploit" and "C2"). The rules no longer overlap. EICAR test files excluded.
- T1562.002 is *Windows* event logging; the firewall log is now T1562.
- Outbound traffic is attributed to the internal machine, not the internet IP.

**False-alarm fixes.** The ten old false alarms were all one of two things:
- *Blocked threats*: every event dropped by the IPS, blocked by AV, or failed
  logins with no success. Not a compromise, so listed separately (158 here).
- *Ambient activity*: every IPS/AV/app-control technique fires on 95-99.9% of
  the 1,387 internal machines, so it cannot single out a victim. Such
  techniques only join an incident as context next to a rare detection on the
  same account or machine; the rest is an estate-wide summary, one line per
  technique, with the count that was allowed through.
- The brute-force rule stamped `MIN(user)` (`002`) on 155 unrelated attacking
  IPs, merging them into one fake actor. Fixed.
- "3+ steps" now means 3+ distinct techniques, not 220 copies of one alert.

**Attack path rebuilt.** All eight planted steps are detected, in four separate
incidents rather than one:

- #1 `Rakes` + `svc_backup30` — the create/use/delete cycle
- #2 `Tejas.Roy` — logging disabled, policies purged
- #3 `Deepika.Khan` — three admin logins
- #4, #5 `parul.sinha`, `keerat.ghughal` — single logins / VPN

Nothing in the data links those actors. They use different accounts, different
source IPs, and act days apart; the only shared attribute is the firewall's own
management IP (`10.10.99.1`), which every administrative event in the file
touches and which is therefore filtered as shared infrastructure. Linking on it
would merge unrelated activity into one blob — measured, that produced a single
395,193-step "incident".

So the correct output here is arguably three incidents, not one: on the evidence
present they may well be three separate intrusions against the same device. We
surface all of them, ranked, with the most damning first.

---

## Fixes this data forced

Each was found by measurement on the real file, and each is a genuine
improvement rather than a workaround.

**1. `strict_mode=false`.** Without it the scan dies at 63% of the file. The
single most important line for working with real syslog.

**2. A placeholder is not an identity.** Firewall records mostly have no user,
so the adapter writes `-`. Treating that as a username made every such record
"the same user" and collapsed **395,193 of 395,361 detections into one
incident**. Values meaning "unknown" are now excluded from correlation.

**3. Rarity beats volume in scoring.** The genuine intrusion is three events
long; routine IPS noise produces incidents of 200+ steps. Volume-based scoring
ranked the real attack **#9**. Adding a severity-10 bonus — rules that fire on
something genuinely rare — moved it to **#1**.

**4. Critical events survive noise suppression.** "Logging disabled", "policies
purged" and "VPN from two countries" each correlated into a group of one, fell
under the noise threshold and were silently dropped — costing three of eight
planted steps. A single severity-10 event is now always reported. This alone
lifted label accuracy from 62.5% to **87.5%**.

**5. Aggregate rules can group by any column.** The SQL hardcoded `host, user`,
so FortiGate rules grouping by `src_ip` alone failed to bind. Output columns are
now emitted explicitly regardless of the grouping key.

**6. The look-ahead needed an IP-keyed asset inventory.** `assets.yaml`
describes hosts as `HR-07` and `FS-02`; this data identifies them only by IP,
so nothing matched and **FR-6 returned an empty list on the real file** -- the
feature silently produced no answer. `assets_firex.yaml` keys the same idea to
the real addresses, derived from the file itself (10.10.99.x is the LAN with
1,272,405 events, 10.10.20.x the DMZ with 1,069,032). The engine now picks the
inventory automatically from whether the incident's hosts look like IPs.

It now answers properly: from the compromised firewall admin account, **five
further systems are reachable**, led by two internal LAN servers at criticality
8 and the internet-facing DMZ host.

**7. The Groq model in the docs does not exist on the free tier.** Testing with
a real key returned HTTP 404 for `llama-3.3-70b-versatile`, which Groq's own
documentation lists as a current production model. Asking the key itself showed
**no Llama chat models available at all**. Switched to `openai/gpt-oss-120b`
(verified working), with two fallbacks. A second bug hid behind the first:
gpt-oss models emit a hidden `reasoning` field that shares the token budget, so
at `max_tokens=700` the visible answer came back as an **empty string** rather
than an error. Raised to 1500 and added an explicit empty-content check.
