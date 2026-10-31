"""
Competing theories about an incident, weighed against the evidence pack.

Every incident gets the same small set of candidate explanations, including
the benign one, so the analyst always sees the alternative to the obvious
story. Each theory carries:

  suspects        what it claims
  supports        evidence for it        (each cited, marked strong or normal)
  challenges      evidence against it    (each cited, marked strong or normal)
  missing         what would be needed and was not supplied
  alternative     the theory that best competes with it
  discriminator   the investigation that would tell them apart
  disproof        what observation would rule it out

STATUS IS COMPUTED, NOT ASSERTED. Two strong challenges, or a decisive
contradiction, abandon a theory -- and the reason is stated, so the analyst can
disagree. A theory with nothing supporting it is shown as "unsupported" rather
than left out, because "we have no evidence of X" is itself worth knowing.
"""

from dataclasses import dataclass, field

from .analysts import is_successful_login
from .evidence import is_external, is_identity

STRONG, NORMAL = 3, 1


@dataclass
class Hypothesis:
    id: str
    title: str
    suspects: str
    supports: list = field(default_factory=list)     # {"text", "cites", "strength"}
    challenges: list = field(default_factory=list)
    missing: list = field(default_factory=list)      # {"text", "cites"}
    alternative: str = ""
    discriminator: str = ""
    disproof: str = ""
    decisive: str = ""          # a contradiction that abandons it on its own
    status: str = ""
    status_reason: str = ""
    score: int = 0

    def weigh(self):
        s = sum(STRONG if x["strength"] == "strong" else NORMAL for x in self.supports)
        c = sum(STRONG if x["strength"] == "strong" else NORMAL for x in self.challenges)
        strong_c = [x for x in self.challenges if x["strength"] == "strong"]
        self.score = s - c
        if self.decisive:
            self.status, self.status_reason = "abandoned", self.decisive
        elif len(strong_c) >= 2:
            self.status = "abandoned"
            self.status_reason = ("Two strong contradictions: "
                                  + "; ".join(x["text"] for x in strong_c[:2]))
        elif not self.supports:
            self.status, self.status_reason = "unsupported", "Nothing in the data supports it yet."
        elif self.score <= 0:
            self.status = "weakened"
            self.status_reason = "The evidence against it outweighs the evidence for it."
        else:
            self.status, self.status_reason = "plausible", "More evidence for it than against it."
        return self

    def as_dict(self):
        return {k: getattr(self, k) for k in (
            "id", "title", "suspects", "supports", "challenges", "missing",
            "alternative", "discriminator", "disproof", "status",
            "status_reason", "score")}


def _p(text, cites, strength=NORMAL):
    return {"text": text, "cites": [c for c in cites if c],
            "strength": "strong" if strength == STRONG else "normal"}


def _signals(pack, findings):
    """Facts the theories are weighed on, each with the IDs that show it."""
    s = {}
    ev = pack.events
    logins = [it for it, e in ev if is_successful_login(e)]
    s["external_login"] = [it.id for it in logins if is_external(it.data["src_ip"])]
    s["external_any"] = [it.id for it, e in ev
                         if is_external(e.get("src_ip")) or is_external(e.get("dest_ip"))]
    s["evasion"] = [it.id for it, e in ev
                    if str(e["mitre_technique"]).startswith(("T1562", "T1070"))]
    s["severity10"] = [it.id for it, e in ev if (e.get("severity") or 0) >= 10]
    s["aggregate"] = [it.id for it, e in ev if (e.get("event_count") or 1) > 20]
    by_key = {f.key.split(":")[0]: f for f in findings}
    keys = {f.key.split(":")[0] for f in findings}
    s["guessed"] = [c for f in findings if f.key.startswith("guessed:") for c in f.cites[:1]]
    s["clean_login"] = [c for f in findings if f.key.startswith("known-credential:")
                        for c in f.cites[:1]]
    s["lifecycle_removed"] = [f for f in findings if f.key.startswith("lifecycle:")
                              and "removed" in f.observation]
    s["stage_order"] = by_key.get("stage-order")
    s["timing"] = by_key.get("timing")
    s["weak"] = by_key.get("weak-links")
    hard = [l for l in pack.of("L") if l.data.get("grade") == "HARD"]
    s["hard_links"] = [l.id for l in hard]
    s["soft_links"] = [l.id for l in pack.of("L") if l.data.get("grade") != "HARD"]
    s["earlier"] = [x for x in pack.of("X")
                    if x.data["column"] in ("user", "src_ip") and x.data["before"] > 0]
    s["gaps"] = [g.id for g in pack.of("G") if "NOT_COLLECTED" in g.data["classification"]]
    s["idp_gaps"] = [g.id for g in pack.of("G")
                     if "identity" in g.data["telemetry"] or "auth" in g.data["telemetry"]]
    s["admin_actions"] = [it.id for it, e in ev
                          if any(w in e["rule_name"].lower()
                                 for w in ("admin", "account", "policy", "config"))]
    s["named_actor"] = [it.id for it, e in ev if is_identity(e["user"])]
    s["keys"] = keys
    return s


def generate(pack, findings):
    s = _signals(pack, findings)
    n_events = len(pack.events)
    hyps = []

    # --- An outsider with a stolen or guessed credential -------------------
    h = Hypothesis(
        "H1", "Outside attacker with a stolen or guessed credential",
        "Someone outside the organisation obtained a valid credential and used it.",
        alternative="H2",
        discriminator=("Whether the account's owner was signed in somewhere else at the "
                       "same time, and what the MFA records show for each login."),
        disproof="The account owner confirms the logins were theirs, from that address.")
    if s["external_login"]:
        h.supports.append(_p("A successful login came from an external address",
                             s["external_login"], STRONG))
    if s["guessed"]:
        h.supports.append(_p("Blocked or failed attempts precede the successful login",
                             s["guessed"], STRONG))
    if s["evasion"]:
        h.supports.append(_p("Evidence was disabled or deleted, which an intruder needs "
                             "and a legitimate user rarely does", s["evasion"]))
    if s["lifecycle_removed"]:
        f = s["lifecycle_removed"][0]
        h.supports.append(_p("A privileged account was created and removed within the "
                             "incident", f.cites[:3]))
    if not s["external_any"]:
        h.challenges.append(_p("No external address appears in any detection of this "
                               "incident", [i.id for i, _ in pack.events], STRONG))
    if s["clean_login"] and not s["guessed"]:
        h.challenges.append(_p("No guessing was detected before the login, so the "
                               "credential was already known", s["clean_login"]))
    h.missing.append({"text": "Identity-provider and MFA records for the logins",
                      "cites": s["idp_gaps"]})
    hyps.append(h)

    # --- A legitimate account holder misusing access ----------------------
    h = Hypothesis(
        "H2", "Insider misusing legitimate access",
        "The named account holder did this themselves, with access they were given.",
        alternative="H1",
        discriminator=("Whether the account holder was working at those times and had a "
                       "business reason (rota, change tickets, their own statement)."),
        disproof="The account holder was demonstrably elsewhere, or their credential was reset.")
    users_before = [x for x in s["earlier"] if x.data["column"] == "user"]
    if users_before:
        h.supports.append(_p("The acting account was active well before the incident, so "
                             "it is an established identity", [x.id for x in users_before]))
    if s["clean_login"]:
        h.supports.append(_p("The login needed no guessing: the credential was known",
                             s["clean_login"]))
    if s["evasion"]:
        h.supports.append(_p("Covering tracks fits someone who expects to be checked",
                             s["evasion"]))
    if s["guessed"]:
        h.challenges.append(_p("Failed attempts before the success suggest someone who did "
                               "not know the password", s["guessed"], STRONG))
    if s["external_login"]:
        h.challenges.append(_p("The login came from outside, which an insider can do but "
                               "usually does not need to", s["external_login"]))
    if not s["named_actor"]:
        h.decisive = "No detection in this incident names an account, so there is no insider to suspect."
    h.missing.append({"text": "HR/rota and change-management records for the account",
                      "cites": []})
    hyps.append(h)

    # --- Routine administration ------------------------------------------
    h = Hypothesis(
        "H3", "Routine administrative work, not an attack",
        "An administrator did planned work that happens to look like an attack.",
        alternative="H2",
        discriminator="A change ticket or maintenance window that covers these exact times.",
        disproof=("No change ticket exists, or the actions include ones no maintenance "
                  "plan needs (disabling logging, deleting the account used)."))
    if s["admin_actions"]:
        h.supports.append(_p("The actions are administrative changes by a named account",
                             s["admin_actions"]))
    if s["clean_login"]:
        h.supports.append(_p("The login needed no guessing", s["clean_login"]))
    if s["evasion"]:
        h.challenges.append(_p("Logging was disabled or evidence deleted; planned work "
                               "has no reason to hide itself", s["evasion"], STRONG))
    if s["external_login"]:
        h.challenges.append(_p("Administration was done from an external address",
                               s["external_login"], STRONG))
    if s["lifecycle_removed"]:
        f = s["lifecycle_removed"][0]
        h.challenges.append(_p("An account was created and deleted within minutes",
                               f.cites[:3]))
    if s["guessed"]:
        h.challenges.append(_p("Failed attempts preceded the login", s["guessed"], STRONG))
    if s["timing"] and "outside 07:00-20:00" in s["timing"].observation:
        h.challenges.append(_p("Steps happened out of hours", s["timing"].cites))
    h.missing.append({"text": "Change tickets / maintenance calendar", "cites": []})
    hyps.append(h)

    # --- Automation -------------------------------------------------------
    h = Hypothesis(
        "H4", "Automated tool or scheduled job",
        "A script, scanner or scheduled task produced this, not a person at a keyboard.",
        alternative="H1",
        discriminator="Exact repetition intervals, user-agent or process name of the actor.",
        disproof="Irregular timing and interactive steps (creating and naming an account).")
    if s["aggregate"]:
        h.supports.append(_p("Some detections summarise many identical raw events",
                             s["aggregate"]))
    if s["timing"] and "after" in s["timing"].observation and " s with a different" in s["timing"].observation:
        h.supports.append(_p("Different techniques follow each other within seconds",
                             s["timing"].cites))
    if s["lifecycle_removed"]:
        f = s["lifecycle_removed"][0]
        h.challenges.append(_p("Creating, using and deleting a named account is "
                               "deliberate, interactive work", f.cites[:3], STRONG))
    if s["timing"] and " h pass between" in s["timing"].observation:
        h.challenges.append(_p("Long pauses between steps look like a person, not a loop",
                               s["timing"].cites))
    hyps.append(h)

    # --- Correlation merged unrelated activity ----------------------------
    if n_events >= 2:
        h = Hypothesis(
            "H5", "Two unrelated activities merged into one incident",
            "The detections do not belong together; correlation joined them.",
            alternative="H1",
            discriminator="A session or process identifier shared by all the steps.",
            disproof="A HARD link chain covering every detection.")
        if s["weak"]:
            h.supports.append(_p("Some detections have no HARD link to the rest",
                                 s["weak"].cites[:6], STRONG if "no recorded link" in s["weak"].observation else NORMAL))
        if s["soft_links"]:
            h.supports.append(_p("Some links are SOFT or INFERRED only", s["soft_links"]))
        if s["hard_links"]:
            h.challenges.append(_p("HARD links connect detections in this incident",
                                   s["hard_links"]))
        if not s["weak"] and s["hard_links"]:
            h.decisive = "Every detection is joined to the rest by a HARD link."
        hyps.append(h)

    # --- The attack began earlier ----------------------------------------
    h = Hypothesis(
        "H6", "The attack began before the first detection",
        "What was detected is the middle of a longer intrusion.",
        alternative="H3",
        discriminator="Logs for the actor's accounts and addresses before the first event.",
        disproof="Complete logs for the period before show no activity by the actor.")
    if s["stage_order"]:
        h.supports.append(_p("A later kill-chain stage appears before an earlier one",
                             s["stage_order"].cites[:2], STRONG))
    if s["earlier"]:
        h.supports.append(_p("The same account or address has detections before the "
                             "incident started", [x.id for x in s["earlier"]], STRONG))
    if s["gaps"]:
        h.supports.append(_p("Sources that would show the earlier phase were not supplied",
                             s["gaps"]))
    first = pack.events[0][1] if pack.events else None
    if first and first["kill_chain_stage"] in ("Reconnaissance", "Initial Access") \
            and not s["earlier"]:
        h.challenges.append(_p("The first detection is itself an access or "
                               "reconnaissance step, and nothing earlier involves the actor",
                               [pack.events[0][0].id]))
    hyps.append(h)

    for h in hyps:
        h.weigh()
    live = [h for h in hyps if h.status == "plausible"]
    if live:
        lead = max(live, key=lambda h: h.score)
        lead.status = "leading"
        lead.status_reason = "Best supported of the plausible explanations."
    order = {"leading": 0, "plausible": 1, "weakened": 2, "unsupported": 3, "abandoned": 4}
    hyps.sort(key=lambda h: (order[h.status], -h.score))
    return hyps
