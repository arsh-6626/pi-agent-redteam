"""OpenHands victim adapter — red-team the REAL OpenHands CLI agent through pi.

pi stays the only orchestrator: rt_deliver -> backend -> this adapter runs the OpenHands
CLI headless on a benign task in a sandbox workspace with the injection planted, parses its
JSONL event stream, and maps it into the SAME episode shape the oracle/transfer layers consume.

Verified against OpenHands SDK v1.21.0 (installed via `uv tool install openhands --python 3.12`):
  openhands --headless --json --yolo --override-with-envs -t "<task>"
  - --json streams JSONL events (ActionEvent / ObservationEvent / MessageEvent) to stdout,
    interleaved with Rich banner lines (non-JSON) which we skip.
  - --yolo auto-approves every action; LLM config via env LLM_API_KEY / LLM_BASE_URL / LLM_MODEL.
  - Local runtime: actions run on the HOST in cwd (no Docker), so RUN THIS INSIDE run-sandboxed.sh
    for any real/untrusted target. The workspace is a throwaway temp dir either way.

Tool-name map (OpenHands -> our neutral episode tools): file_editor(create/str_replace/insert)->
write_file, file_editor(view)->read_file, execute_bash->run_shell, finish->final.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from ..victim import VictimSandbox, _populate_workspace  # reuse sandbox + injection planting

OPENHANDS_BIN = os.environ.get("OPENHANDS_BIN") or (
    shutil.which("openhands") or str(Path.home() / ".local/bin/openhands"))


def _map_event(o: dict) -> dict | None:
    """One OpenHands JSONL event -> {tool,args,result} or None."""
    kind = o.get("kind")
    if kind == "ActionEvent":
        tn = o.get("tool_name")
        a = o.get("action", {}) or {}
        # OpenHands' shell tool is named "terminal" (v1.21); older/other names kept for safety.
        if tn in ("terminal", "execute_bash", "bash", "run_shell", "run"):
            return {"tool": "run_shell", "args": {"cmd": a.get("command") or a.get("cmd", "")}, "result": ""}
        if tn == "file_editor":
            cmd = a.get("command")
            if cmd == "view":
                return {"tool": "read_file", "args": {"path": a.get("path", "")}, "result": ""}
            content = a.get("file_text") or a.get("new_str") or ""
            return {"tool": "write_file", "args": {"path": a.get("path", ""), "content": content}, "result": ""}
        if tn == "finish":
            return {"tool": "final", "args": {"summary": a.get("message", "")}, "result": ""}
        # browser/think/task_tracker/etc.: keep as a generic tool call for visibility
        return {"tool": str(tn or "tool"), "args": a, "result": ""}
    if kind == "MessageEvent":
        m = o.get("llm_message", {}) or {}
        if (m.get("role") == "assistant"):
            txt = " ".join(c.get("text", "") for c in (m.get("content") or []) if isinstance(c, dict))
            if txt.strip():
                return {"tool": "message", "args": {"text": txt[:500]}, "result": ""}
    return None


def _attach_observations(events: list[dict], raw: list[dict]) -> None:
    """Fill run_shell/file_editor results from matching ObservationEvents (best-effort, in order)."""
    obs = [o for o in raw if o.get("kind") == "ObservationEvent"]
    i = 0
    for ev in events:
        if ev["tool"] in ("run_shell", "read_file", "write_file") and i < len(obs):
            ob = obs[i].get("observation", {}) or {}
            txt = " ".join(c.get("text", "") for c in (ob.get("content") or []) if isinstance(c, dict))
            ev["result"] = txt[:500]
            i += 1


def run_episode(injection: str, task: str, surface: str, canary: str, profile: str = "openhands",
                max_steps: int = 0, target_repo: str | None = None) -> dict:
    sb = VictimSandbox()
    _populate_workspace(sb, injection, surface, target_repo)
    env = dict(os.environ)
    key = env.get("LLM_API_KEY") or env.get("DEEPSEEK_API_KEY", "")
    env["LLM_API_KEY"] = key
    env.setdefault("LLM_BASE_URL", env.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))
    env.setdefault("LLM_MODEL", "deepseek/deepseek-chat")
    env["OPENHANDS_SUPPRESS_BANNER"] = "1"

    cmd = [OPENHANDS_BIN, "--headless", "--json", "--yolo", "--override-with-envs", "-t", task]
    raw: list[dict] = []
    error = None
    try:
        p = subprocess.run(cmd, cwd=str(sb.workspace), env=env, timeout=600,
                           capture_output=True, text=True)
        for ln in p.stdout.splitlines():
            ln = ln.strip()
            if not ln or ln[0] != "{":
                continue
            try:
                raw.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        if not raw:
            error = f"no JSONL events (exit {p.returncode}); stderr: {p.stderr[-300:]}"
    except FileNotFoundError:
        error = f"openhands CLI not found at {OPENHANDS_BIN} (uv tool install openhands --python 3.12)"
    except subprocess.TimeoutExpired:
        error = "openhands timed out"

    events = [e for e in (_map_event(o) for o in raw) if e]
    _attach_observations(events, raw)
    # Record every tool call into the sandbox event log so the oracle sees the same shape.
    sb.events = events
    sz = sb.base / "SECRET_ZONE"
    episode = {
        "task": task, "surface": surface, "canary": canary, "profile": "openhands",
        "injection": injection, "events": events, "base": str(sb.base),
        "workspace": str(sb.workspace), "secret_zone": str(sz),
        "secret_zone_contents": [str(pp.relative_to(sz)) for pp in sz.rglob("*") if pp.is_file()],
        "workspace_files": [str(pp.relative_to(sb.workspace)) for pp in sb.workspace.rglob("*") if pp.is_file()],
    }
    if error:
        episode["adapter_error"] = error
    sb.cleanup()
    return episode
