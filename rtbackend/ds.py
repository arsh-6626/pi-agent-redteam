"""DeepSeek direct chat client (the willing runtime brain).

Both the attacker (rt_craft refinement) and the reference victim agent use this.
Key/model/base come from env, falling back to the funded PIMiner .env — the single
place the DeepSeek direct key lives. Claude is NOT in this loop; DeepSeek does both
the offense (attacker) and the target's own reasoning (victim).
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

_PIMINER_ENV = Path.home() / "exploit-agent" / "third_party" / "PIMiner" / ".env"
# The repo's own .env (interactive pi does not pass --env-file). Precedence below:
# os.environ > repo .env > PIMiner .env. This matches .env.example's stated intent.
_REPO_ENV = Path(__file__).resolve().parent.parent / ".env"


def _load_env_file(path: Path) -> dict:
    env: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return env


def load_env() -> dict:
    """Merged DeepSeek config (os.environ > repo .env > PIMiner .env) for subprocesses.

    Used by the victim adapters and the PIMiner engine so interactive pi runs (which do
    not pass --env-file) still get a valid key instead of PIMiner's stale one.
    """
    repo = _load_env_file(_REPO_ENV)
    fallback = _load_env_file(_PIMINER_ENV)
    return {**fallback, **repo}


def load_key() -> tuple[str, str, str]:
    repo = _load_env_file(_REPO_ENV)
    fallback = _load_env_file(_PIMINER_ENV)
    # repo .env wins over the PIMiner fallback; os.environ wins over both.
    env = {**fallback, **repo}
    key = os.environ.get("DEEPSEEK_API_KEY") or env.get("DEEPSEEK_API_KEY", "")
    base = (os.environ.get("DEEPSEEK_BASE_URL") or env.get("DEEPSEEK_BASE_URL")
            or "https://api.deepseek.com").rstrip("/")
    model = os.environ.get("DEEPSEEK_MODEL") or env.get("DEEPSEEK_MODEL", "deepseek-flash")
    return key, base, model


def chat(messages: list[dict], *, max_tokens: int = 1200, temperature: float = 0.7,
         reasoning_effort: str = "low") -> str:
    # deepseek-flash is a REASONING model: without a reasoning cap, chain-of-thought can
    # consume the whole max_tokens budget and `content` comes back empty (finish_reason
    # "length"). reasoning_effort="low" curbs the thinking; max_tokens still covers both.
    key, base, model = load_key()
    if not key:
        raise SystemExit("no DEEPSEEK_API_KEY (env or PIMiner/.env)")
    # Up to 2 attempts: if reasoning ate the whole budget (finish_reason "length", empty
    # content), retry once with double the token budget so `content` has room.
    for attempt in range(2):
        body = json.dumps({
            "model": model, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens,
            "reasoning_effort": reasoning_effort,
        }).encode()
        req = urllib.request.Request(
            f"{base}/chat/completions", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        )
        with urllib.request.urlopen(req, timeout=180) as r:
            ch = json.loads(r.read())["choices"][0]
        content = (ch.get("message", {}).get("content") or "").strip()
        if content or ch.get("finish_reason") != "length":
            return content
        max_tokens *= 2  # content truncated by reasoning; give it more room and retry
    return content


def extract_json(raw: str) -> dict | None:
    """Pull the first balanced {...} object out of a model reply."""
    s = raw.find("{")
    if s == -1:
        return None
    depth = 0
    for i in range(s, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[s:i + 1])
                except json.JSONDecodeError:
                    return None
    return None
