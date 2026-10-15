"""Transfer layer — the differentiator promptfoo does NOT have.

A win on one victim is distilled into a reusable motif keyed by GOAL KIND (not by
target), and replayed FIRST on the next victim. A harm produced by a motif whose
`learned_on` != the current victim is TRANSFER.

Two stores are read:
  - agenthunt.library.Library  : our own payload-template store (repo-local JSON),
    where rt_learn deposits wins and rt_propose retrieves them.
  - exploit-agent strategy_kg.json : 10 PRE-MINED capability-graph motifs (ipi-toolcall,
    ipi-saystring) with concrete "moves" — seed crafting hints. NOTE: these were mined
    on AgentDojo and are `oracle_confirmed:false`; a confirmed re-grounding here is the
    first oracle-grounded transfer, which is the milestone.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Reuse agenthunt (don't rebuild). HANDOFF: "REUSE, don't rebuild".
_AGENTHUNT_REPO = Path.home() / "agent-cve-hunt"
if str(_AGENTHUNT_REPO) not in sys.path:
    sys.path.insert(0, str(_AGENTHUNT_REPO))

from agenthunt.library import Library, Technique  # noqa: E402

_KG_PATH = Path.home() / "exploit-agent" / "results" / "strategy_kg.json"
_LIB_PATH = Path(__file__).resolve().parent.parent / "findings" / "transfer_library.json"


def library() -> Library:
    return Library(_LIB_PATH)


def propose(goal_kind: str) -> list[dict]:
    """Transferred payload templates for this goal kind (replayed first)."""
    return [
        {"name": t.name, "template": t.template, "learned_on": t.learned_on,
         "goal_kind": t.boundary_kind}
        for t in library().propose(goal_kind)
    ]


def learn(goal_kind: str, payload: str, learned_on: str, *, canary: str) -> dict:
    """Deposit a winning payload as a transferable template (canary -> {canary} slot)."""
    tech = library().learn_from_payload(
        goal_kind, payload, learned_on, tail="", canary=canary)
    return {"name": tech.name, "template": tech.template,
            "learned_on": tech.learned_on, "goal_kind": tech.boundary_kind}


def kg_moves(goal_kind: str, limit: int = 4) -> list[dict]:
    """Pre-mined motif 'moves' as crafting hints. Goal kinds map onto motif_ids:
    cmd_exec/write_out/exfil -> ipi-toolcall (tool-call hijack); say_string -> ipi-saystring."""
    if not _KG_PATH.exists():
        return []
    want = "ipi-saystring" if goal_kind == "say_string" else "ipi-toolcall"
    out: list[dict] = []
    for node in json.loads(_KG_PATH.read_text()).get("nodes", []):
        if node.get("motif", {}).get("motif_id") != want:
            continue
        out.append({
            "short_name": node.get("short_name", ""),
            "mechanism": (node.get("mechanism_intro", "") or "")[:400],
            "moves": [m.get("desc", "") for m in node.get("moves", [])][:3],
        })
        if len(out) >= limit:
            break
    return out
