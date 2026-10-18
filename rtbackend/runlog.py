"""Append-only, content-addressed run log (improvement.md §2.4).

Problem it fixes: last_craft/last_episode/last_confirm were all OVERWRITTEN, so after the fact we
could not reconstruct which episode produced which verdict — and findings.json was once silently
wiped. Nothing was auditable.

Every judged episode and every black-box confirm writes an immutable directory:

  findings/runs/<UTC>-<code-sha>-<uniq>/
    meta.json     # victim, profile, task, surface, target_repo, code sha, kind, utc
    injection.txt # the exact plantable payload
    episode.json  # the full victim trajectory (oracle runs)
    verdict.json  # the oracle verdict + rationale (oracle runs)
    confirm.json  # the K-replay result (confirm runs)

plus one line per run in findings/index.jsonl for cheap querying. The `last_*` files remain only as
convenience copies — this directory is the source of truth, and a recorded finding is replayable from
its own run dir alone.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = _ROOT / "findings" / "runs"
INDEX = _ROOT / "findings" / "index.jsonl"


def _code_sha() -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(_ROOT),
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "nogit"
    except Exception:  # noqa: BLE001
        return "nogit"


def _sha256(s: str) -> str:
    return hashlib.sha256((s or "").strip().encode()).hexdigest()


def log_run(kind: str, *, injection: str = "", episode: dict | None = None,
            verdict: dict | None = None, confirm: dict | None = None,
            meta_extra: dict | None = None) -> str:
    """Write one immutable run directory + append a line to the index. Returns the run id.
    Never raises into the caller — logging must not break a hunt."""
    try:
        utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        sha = _code_sha()
        uniq = hashlib.sha256(f"{utc}{time.time()}{injection[:80]}".encode()).hexdigest()[:6]
        run_id = f"{utc}-{sha}-{uniq}"
        d = RUNS_DIR / run_id
        d.mkdir(parents=True, exist_ok=True)
        meta = {"run_id": run_id, "kind": kind, "utc": utc, "code_sha": sha}
        if meta_extra:
            meta.update({k: v for k, v in meta_extra.items() if v is not None})
        (d / "meta.json").write_text(json.dumps(meta, indent=2))
        if injection:
            (d / "injection.txt").write_text(injection)
        if episode is not None:
            (d / "episode.json").write_text(json.dumps(episode, indent=2, default=str))
        if verdict is not None:
            (d / "verdict.json").write_text(json.dumps(verdict, indent=2, default=str))
        if confirm is not None:
            (d / "confirm.json").write_text(json.dumps(confirm, indent=2, default=str))
        line = {
            "run_id": run_id, "kind": kind, "utc": utc, "code_sha": sha,
            "victim": meta.get("victim"), "surface": meta.get("surface"),
            "verdict": (verdict or {}).get("verdict"),
            "cve_grade": (confirm or {}).get("cve_grade"),
            "repro_rate": (confirm or {}).get("repro_rate"),
            "injection_sha256": _sha256(injection) if injection else None,
        }
        INDEX.parent.mkdir(parents=True, exist_ok=True)
        with INDEX.open("a") as f:
            f.write(json.dumps(line) + "\n")
        return run_id
    except Exception:  # noqa: BLE001
        return ""
