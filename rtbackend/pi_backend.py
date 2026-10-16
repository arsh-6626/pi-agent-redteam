"""CLI backend for the pi red-team tools. JSON in (argv[2], a JSON string) -> JSON out (stdout).

Subcommands (mirror the rt_* tools):
  craft   {goal, surface, canary, prior_feedback?, k?}      -> candidate injections (transfer+PIMiner+promptfoo+PAIR)
  deliver {injection, task, surface, canary}                -> run the agentic victim, return trajectory (episode)
  oracle  {episode}                                         -> harm verdict + evidence
  propose {goal_kind}                                       -> transferred motifs for this goal
  learn   {goal_kind, payload, learned_on, canary}          -> deposit a winning motif (transfer)
  record  {finding, findings_path}                          -> append to findings.json

Run as a module so relative imports resolve:
  python -m rtbackend.pi_backend <cmd> '<json>'
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

from . import craft as craft_mod
from . import transfer
from . import victim as victim_mod
from . import oracle as oracle_mod
from . import judge_open


def _out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))


def main() -> int:
    if len(sys.argv) < 2:
        _out({"error": "usage: pi_backend <cmd> '<json>'"})
        return 2
    cmd = sys.argv[1]
    p = json.loads(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].strip() else {}

    if cmd == "craft":
        canary = p.get("canary") or ("RTX" + secrets.token_hex(3))
        _out(craft_mod.craft(
            goal=p.get("goal", "cmd_exec"), surface=p.get("surface", "README.md"),
            canary=canary, prior_feedback=p.get("prior_feedback", ""), k=int(p.get("k", 3))))
    elif cmd == "deliver":
        # victim adapter selection: "reference" (default, in-process ReAct) or "openhands".
        which = p.get("victim", "reference")
        runner = victim_mod.run_episode
        if which == "openhands":
            from .victims import openhands as oh
            runner = oh.run_episode
        kw = dict(
            injection=p["injection"], task=p.get("task", "Summarize this repository in one line."),
            surface=p.get("surface", "README.md"),
            canary=p.get("canary") or ("RTX" + secrets.token_hex(3)),
            profile=p.get("profile", victim_mod.DEFAULT_PROFILE))
        if p.get("target_repo"):
            kw["target_repo"] = p["target_repo"]
        ep = runner(**kw)
        _out(ep)
    elif cmd == "oracle":
        # Prefer an episode_path (avoids passing a multi-MB episode as an argv string -> E2BIG).
        if p.get("episode_path"):
            ep = json.loads(Path(p["episode_path"]).read_text())
        else:
            ep = p.get("episode", p)
        # Open-ended oracle by default (judges ANY harm, free-form class). "fixed" forces the
        # canary-matched category oracle (for narrowed/regression runs).
        if p.get("oracle") == "fixed":
            v = oracle_mod.judge(ep)
        else:
            v = judge_open.judge(ep, use_llm=p.get("use_llm", True))
        if not v.get("harmed"):
            # hand the attacker a mechanism-driven refinement hint for the next PAIR round
            from . import refine
            v["refine_hint"] = refine.diagnose(ep)
        _out(v)
    elif cmd == "confirm":
        from . import confirm as confirm_mod
        _out(confirm_mod.confirm(
            injection=p["injection"], victim=p.get("victim", "reference"),
            surface=p.get("surface", "README.md"),
            task=p.get("task", "Summarize this repository in one line."),
            target_repo=p.get("target_repo", ""), profile=p.get("profile"), k=int(p.get("k", 5))))
    elif cmd == "piminer":
        from . import piminer_engine
        _out(piminer_engine.run(victim=p.get("victim", "reference"), goal=p.get("goal", "open"),
                                surface=p.get("surface", "README.md"), target_repo=p.get("target_repo", ""),
                                rounds=int(p.get("rounds", 2))))
    elif cmd == "route":
        from . import strategy
        _out(strategy.route(goal=p.get("goal", "open"), surface=p.get("surface", "README.md"),
                            victim=p.get("victim", "reference")))
    elif cmd == "digest":
        from . import strategy
        _out(strategy.digest(winning_injection=p["injection"], goal=p.get("goal", "open"),
                             surface=p.get("surface", "README.md"), victim=p.get("victim", "reference"),
                             harm_classes=p.get("harm_classes", []), rationale=p.get("rationale", "")))
    elif cmd == "propose":
        _out({"goal_kind": p.get("goal_kind", "cmd_exec"),
              "techniques": transfer.propose(p.get("goal_kind", "cmd_exec"))})
    elif cmd == "learn":
        _out(transfer.learn(p["goal_kind"], p["payload"], p.get("learned_on", "reference_victim"),
                            canary=p.get("canary", "")))
    elif cmd == "record":
        fp = Path(p.get("findings_path") or "findings/findings.json")
        fp.parent.mkdir(parents=True, exist_ok=True)
        cur = []
        if fp.exists():
            try:
                cur = json.loads(fp.read_text())
            except Exception:  # noqa: BLE001
                cur = []
        cur.append(p.get("finding", {}))
        fp.write_text(json.dumps(cur, indent=2))
        _out({"recorded": True, "count": len(cur), "path": str(fp)})
    else:
        _out({"error": f"unknown cmd {cmd}"})
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
