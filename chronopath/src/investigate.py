"""
investigate.py -- talk to the Elliot investigator from the command line.

  python src/investigate.py --db firex30.db                  brief for INC-01
  python src/investigate.py --db firex30.db --incident INC-02
  python src/investigate.py --db firex30.db --ask "What am I missing?"
  python src/investigate.py --db firex30.db --chat           interactive

In --chat mode, besides questions:
  done <key> [note]       mark a recommended move as done
  dismiss <key> [note]    dismiss a recommended move
  reject H2 <reason>      reject a theory      accept H1    accept a theory
  examined E1 E2          mark evidence as examined
  decide <text>           record an analyst decision
  brief                   show the brief again       quit
"""

import argparse
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import graph_engine  # noqa: E402
from elliot import QUESTIONS, Investigator  # noqa: E402
from elliot.analysts import SECTION_TITLES, SECTIONS  # noqa: E402

WIDTH = 100


def _wrap(text, indent="    "):
    return textwrap.fill(str(text), WIDTH, initial_indent=indent,
                         subsequent_indent=indent)


def print_section(s):
    print(f"\n  == {s.get('title', '')}")
    for k in SECTIONS:
        if s.get(k):
            label = s.get("labels", {}).get(k, "")
            print(f"  {SECTION_TITLES[k]} [{label}]")
            print(_wrap(s[k]))


def print_brief(inv):
    b = inv.brief()
    i = b["incident"]
    print(f"\n{'=' * WIDTH}\n  {i['id']}  risk {i['risk_score']}  "
          f"{i['window'][0]} -> {i['window'][1]}  ({i['detections']} detections)\n{'=' * WIDTH}")
    print("\n  WHAT CAUGHT MY ATTENTION")
    for f in b["findings"]:
        if f["priority"] > 0:
            mark = " (examined)" if f["examined"] else ""
            print_section({**f, "title": f"[{f['priority']}] {f['title']}{mark}"})
    if b["abandoned_since_last_review"]:
        print("\n  THEORIES ABANDONED SINCE LAST REVIEW")
        for a in b["abandoned_since_last_review"]:
            print(_wrap(f"{a['id']} {a['title']}: {a['reason']}"))
    print("\n  THEORIES")
    for h in b["hypotheses"]:
        print(f"\n  {h['id']} {h['title']}  -- {h['status']}, confidence {h['confidence']}")
        print(_wrap(h["status_reason"]))
        for s in h["supports"]:
            print(_wrap(f"+ {s['text']} {s['cites']}"))
        for c in h["challenges"]:
            print(_wrap(f"- {c['text']} {c['cites']}"))
    print("\n  NEXT MOVES (recommended, not performed)")
    for m in b["next_moves"]:
        print(_wrap(f"[{m['priority']}] {m['action']}   ({m['state']}; key={m['key']})"))
    print(f"\n  memory: {b['memory']}")


def print_answer(a):
    print(f"\n  >> {a['headline']}")
    if a["narrative"]:
        print("\n" + textwrap.indent(a["narrative"], "  "))
    else:
        if a.get("validation") and not a["validation"]["passed"]:
            print("  (AI answer discarded: " + "; ".join(a["validation"]["problems"]) + ")")
        for s in a["sections"]:
            print_section(s)
    for x in a["extra"]:
        kind = x.get("kind")
        if kind == "move":
            print(_wrap(f"- [{x['priority']}] {x['action']}  (key={x['key']})"))
        elif kind == "question":
            print(_wrap(f"? {x['question']} -- {x['where']}"))
        elif kind == "self_review":
            for r in x["answers"]:
                print(_wrap(f"{r['verdict'].upper():8} {r['question']} {r['answer']}"))
        elif "text" in x:
            print(_wrap(f"- {x.get('id', '')} {x['text']}"))
        elif "reason" in x:
            print(_wrap(f"- {x['id']} {x['title']}: {x['reason']}"))


def chat(inv):
    print("\nAsk a question, or: done/dismiss <key>, accept/reject H#, examined E1 E2, "
          "decide <text>, brief, quit.\nSuggested questions:")
    for q in QUESTIONS:
        print(f"  - {q}")
    while True:
        try:
            line = input("\nanalyst> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        word, _, rest = line.partition(" ")
        cmd = word.lower()
        if cmd in ("quit", "exit"):
            break
        if cmd == "brief":
            print_brief(inv)
        elif cmd in ("done", "dismiss"):
            key, _, note = rest.partition(" ")
            ok = inv.resolve(key, "done" if cmd == "done" else "dismissed", note)
            print("  recorded." if ok else "  no such recommendation key.")
        elif cmd in ("accept", "reject"):
            hid, _, reason = rest.partition(" ")
            inv.set_verdict(hid.upper(), "accepted" if cmd == "accept" else "rejected", reason)
            print("  recorded; theories re-weighed.")
            inv = Investigator(inv.db_path, inv.incident, use_llm=inv.use_llm)
        elif cmd == "examined":
            inv.mark_examined(rest.split())
            print("  recorded.")
        elif cmd == "decide":
            inv.decide(rest)
            print("  recorded.")
        else:
            print_answer(inv.ask(line))


def main():
    ap = argparse.ArgumentParser(description="The Elliot investigator.")
    ap.add_argument("--db", default="chronopath.db")
    ap.add_argument("--incident", default=None, help="Incident ID (default: top-ranked)")
    ap.add_argument("--ask", default=None, help="Ask one question and exit")
    ap.add_argument("--chat", action="store_true", help="Interactive session")
    ap.add_argument("--no-llm", action="store_true", help="Deterministic answers only")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    incidents = graph_engine.analyse(args.db)
    if not incidents:
        raise SystemExit(f"No incidents in {args.db}.")
    inc = incidents[0]
    if args.incident:
        inc = next((i for i in incidents if i["id"].lower() == args.incident.lower()), None)
        if inc is None:
            raise SystemExit(f"No incident {args.incident}; have "
                             f"{', '.join(i['id'] for i in incidents)}")
    inv = Investigator(args.db, inc, use_llm=False if args.no_llm else None)
    if args.ask:
        print_answer(inv.ask(args.ask))
    elif args.chat:
        print_brief(inv)
        chat(inv)
    else:
        print_brief(inv)


if __name__ == "__main__":
    main()
