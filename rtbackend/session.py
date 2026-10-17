"""Attack-session memory — the state that makes the attacker ADAPTIVE across craft calls.

Without this, every rt_craft was a cold one-shot: no memory of what was already tried, so the
attacker re-rolled cosmetic variants. This records, per hunt: the payloads already sent (for the
mutation gate), the attack CLASSES already tried (so the attacker must pick an untried one), the
best susceptibility reached so far (the hill-climb target), and the defenses observed (so feedback
accumulates). Shared file so the pi-agent loop and the scripts both benefit.
"""
from __future__ import annotations

import json
from pathlib import Path

_SESS = Path(__file__).resolve().parent.parent / "findings" / "attack_session.json"


def load() -> dict:
    try:
        return json.loads(_SESS.read_text())
    except Exception:  # noqa: BLE001
        return {"payloads": [], "classes": [], "best_susc": 0.0, "defenses": []}


def save(s: dict) -> None:
    _SESS.parent.mkdir(parents=True, exist_ok=True)
    _SESS.write_text(json.dumps(s, indent=2))


def reset() -> None:
    save({"payloads": [], "classes": [], "best_susc": 0.0, "defenses": []})


def record_attempt(injection: str, cls: str) -> None:
    s = load()
    s.setdefault("payloads", []).append((injection or "")[:4000])
    if cls and cls not in s.setdefault("classes", []):
        s["classes"].append(cls)
    save(s)


def record_result(susc: float, defense: str = "") -> None:
    s = load()
    s["best_susc"] = max(float(s.get("best_susc", 0.0)), float(susc))
    if defense:
        d = defense[:200]
        if d not in s.setdefault("defenses", []):
            s["defenses"].append(d)
    save(s)
