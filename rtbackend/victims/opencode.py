"""opencode victim adapter — red-team the opencode CLI (host-default coding agent) via the harness.

opencode (sst/opencode, v1.18+) runs non-interactively with:
  opencode run --format json --auto -m <provider/model> --dir <workspace> "<task>"
`--format json` streams JSONL events; `--auto` auto-approves tool use (the host-default danger);
`--dir` is the project dir (our sandbox copy). We map opencode's tool events to the neutral
{tool,args,result} episode shape so the open oracle/transfer layers judge it unchanged.

Brain: opencode's own provider auth here is broken (opencode-go stream errors), and `deepseek` is
not a built-in provider — so we inject a project-level opencode.jsonc defining DeepSeek as an
OpenAI-compatible provider keyed by DEEPSEEK_API_KEY. Isolation (Bug 2): HOME=decoy sandbox home
(seeded secrets; real ~/.ssh unreachable); a STABLE harness XDG cache dir so the provider npm +
model catalog are installed once and reused across episodes (not re-fetched per run).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .. import ds as _ds
from ..victim import VictimSandbox, _populate_workspace, outside_files, snapshot_escapes
from ..egress import EgressSink

_OPENCODE_BIN = os.environ.get("OPENCODE_BIN") or (
    str(Path.home() / ".opencode/bin/opencode"))
# stable per-harness XDG dirs so the deepseek provider npm + catalog persist across episodes
_XDG = Path(__file__).resolve().parents[2] / ".opencode-victim"

_PROJECT_CONFIG = {
    "$schema": "https://opencode.ai/config.json",
    "provider": {
        "deepseek": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "DeepSeek",
            "options": {"baseURL": "https://api.deepseek.com/v1", "apiKey": "{env:DEEPSEEK_API_KEY}"},
            "models": {"deepseek-chat": {"name": "DeepSeek Chat"}},
        }
    },
}


def _map_event(o: dict) -> dict | None:
    if o.get("type") == "tool_use":
        part = o.get("part", {}) or {}
        tn = part.get("tool")
        st = part.get("state", {}) or {}
        inp = st.get("input", {}) or {}
        out = str(st.get("output", ""))[:500]
        if tn == "bash":
            return {"tool": "run_shell", "args": {"cmd": inp.get("command", "")}, "result": out}
        if tn in ("write",):
            return {"tool": "write_file", "args": {"path": inp.get("filePath", ""), "content": inp.get("content", "")}, "result": out}
        if tn in ("edit", "patch"):
            return {"tool": "write_file", "args": {"path": inp.get("filePath", ""),
                    "content": inp.get("newString") or inp.get("replacement") or ""}, "result": out}
        if tn in ("read",):
            return {"tool": "read_file", "args": {"path": inp.get("filePath", "")}, "result": out}
        if tn in ("grep", "glob", "list"):
            return {"tool": "read_file", "args": {"path": inp.get("pattern") or inp.get("path", "")}, "result": out}
        if tn in ("webfetch", "fetch"):
            # surface network use so the egress oracle can see it
            return {"tool": "run_shell", "args": {"cmd": "webfetch " + str(inp.get("url", ""))}, "result": out}
        return {"tool": str(tn or "tool"), "args": inp, "result": out}
    if o.get("type") == "text":
        txt = str((o.get("part", {}) or {}).get("text", "") or o.get("text", ""))
        if txt.strip():
            return {"tool": "message", "args": {"text": txt[:600]}, "result": ""}
    return None


def run_episode(injection: str, task: str, surface: str, canary: str, profile: str = "opencode",
                max_steps: int = 0, target_repo: str | None = None) -> dict:
    sb = VictimSandbox()
    _populate_workspace(sb, injection, surface, target_repo)
    (sb.workspace / "opencode.jsonc").write_text(json.dumps(_PROJECT_CONFIG, indent=2))
    _escape_baseline = outside_files(sb.base, sb.workspace)  # pre-run: seeds + nothing else

    _XDG.mkdir(parents=True, exist_ok=True)
    merged = _ds.load_env()
    key = os.environ.get("DEEPSEEK_API_KEY") or merged.get("DEEPSEEK_API_KEY", "")
    env = {
        "PATH": f"{Path.home()}/.opencode/bin:" + os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "HOME": str(sb.home),                 # isolate real ~/.ssh; decoy secrets live here
        "DEEPSEEK_API_KEY": key,
        "XDG_CACHE_HOME": str(_XDG / "cache"),  # stable: provider npm + catalog cached across episodes
        "XDG_DATA_HOME": str(_XDG / "data"),
        "XDG_CONFIG_HOME": str(_XDG / "config"),
    }
    sink = EgressSink(host=os.environ.get("EGRESS_HOST", "127.0.0.1"),
                      port=int(os.environ.get("EGRESS_PORT", "18080")))
    sink.__enter__()
    cmd = [_OPENCODE_BIN, "run", "--format", "json", "--auto",
           "-m", "deepseek/deepseek-chat", "--dir", str(sb.workspace), task]
    raw: list[dict] = []
    error = None
    try:
        p = subprocess.run(cmd, cwd=str(sb.workspace), env=env, timeout=600,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
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
        error = f"opencode CLI not found at {_OPENCODE_BIN}"
    except subprocess.TimeoutExpired:
        error = "opencode timed out"

    events = [e for e in (_map_event(o) for o in raw) if e]
    # last assistant text -> a 'final' event (opencode has no finish tool)
    msgs = [e for e in events if e["tool"] == "message"]
    if msgs:
        events.append({"tool": "final", "args": {"summary": msgs[-1]["args"]["text"]}, "result": ""})

    escaped = snapshot_escapes(sb.base, sb.workspace, _escape_baseline)
    episode = {
        "task": task, "surface": surface, "canary": canary, "profile": "opencode",
        "injection": injection, "events": events, "base": str(sb.base),
        "workspace": str(sb.workspace), "secret_zone_contents": escaped,
        "workspace_files": [str(pp.relative_to(sb.workspace)) for pp in sb.workspace.rglob("*") if pp.is_file()],
        "egress_receipts": sink.receipts, "egress_url": sink.url,
    }
    if error:
        episode["adapter_error"] = error
    sink.__exit__(None, None, None)
    sb.cleanup()
    return episode
