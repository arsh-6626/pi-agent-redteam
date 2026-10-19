"""DeepSeek direct chat client (the willing runtime brain).

Both the attacker (rt_craft refinement) and the reference victim agent use this.
Key/model/base come from env, falling back to the funded PIMiner .env — the single
place the DeepSeek direct key lives. Claude is NOT in this loop; DeepSeek does both
the offense (attacker) and the target's own reasoning (victim).
"""
from __future__ import annotations

import json
import os
import urllib.error
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


# Model-name fragments that indicate a REASONING model (needs reasoning_effort + a bigger
# token budget). Non-reasoning models (e.g. Groq's llama-3.3) REJECT reasoning_effort with a 400.
_REASONING_HINTS = ("reason", "-r1", "r1-", "flash", "gpt-oss", "qwen3", "o1", "o3", "thinking", "deepthink")


def load_key() -> tuple[str, str, str]:
    repo = _load_env_file(_REPO_ENV)
    fallback = _load_env_file(_PIMINER_ENV)
    # repo .env wins over the PIMiner fallback; os.environ wins over both.
    env = {**fallback, **repo}

    def g(k: str) -> str:
        return os.environ.get(k) or env.get(k, "")

    # Provider switch: a Groq free key (or any RT_LLM_* override) takes precedence over DeepSeek,
    # so the brain keeps working when the DeepSeek balance is exhausted. All are OpenAI-compatible.
    if g("RT_LLM_KEY"):
        return g("RT_LLM_KEY"), (g("RT_LLM_BASE_URL") or "https://api.groq.com/openai/v1").rstrip("/"), \
            (g("RT_LLM_MODEL") or "llama-3.3-70b-versatile")
    if g("GROQ_API_KEY"):
        return g("GROQ_API_KEY"), (g("GROQ_BASE_URL") or "https://api.groq.com/openai/v1").rstrip("/"), \
            (g("GROQ_MODEL") or "llama-3.3-70b-versatile")
    key = g("DEEPSEEK_API_KEY")
    base = (g("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/")
    model = g("DEEPSEEK_MODEL") or "deepseek-flash"
    return key, base, model


def chat(messages: list[dict], *, max_tokens: int = 1200, temperature: float = 0.7,
         reasoning_effort: str = "low") -> str:
    # deepseek-flash is a REASONING model: without a reasoning cap, chain-of-thought can
    # consume the whole max_tokens budget and `content` comes back empty (finish_reason
    # "length"). reasoning_effort="low" curbs the thinking; max_tokens still covers both.
    key, base, model = load_key()
    if not key:
        raise SystemExit("no LLM key — set GROQ_API_KEY (or DEEPSEEK_API_KEY) in env or .env")
    is_reasoning = any(h in model.lower() for h in _REASONING_HINTS)
    # Up to 2 attempts: if reasoning ate the whole budget (finish_reason "length", empty
    # content), retry once with double the token budget so `content` has room.
    for attempt in range(2):
        payload = {"model": model, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens}
        # reasoning_effort is only valid for reasoning models; non-reasoning (Groq llama) 400 on it.
        if is_reasoning:
            payload["reasoning_effort"] = reasoning_effort
        req = urllib.request.Request(
            f"{base}/chat/completions", data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                ch = json.loads(r.read())["choices"][0]
        except urllib.error.HTTPError as e:  # surface the provider's error body (bad model, 402, etc.)
            detail = e.read().decode("utf-8", "replace")[:300]
            raise SystemExit(f"LLM {e.code} from {base} (model={model}): {detail}") from e
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
