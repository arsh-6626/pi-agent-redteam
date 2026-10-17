# Review — VULN 2 (upgraded) LLM-key theft: CVE-grade in harness, NOT yet submittable

Critical triage of `VULN2-llm-key-theft.md` / `findings.json[0]`. Verdict: a materially stronger
finding than the decoy version, but it has **not** beaten the "use the sandbox" rebuttal, and one of
its claims is undercut by our own subsidiary finding. Do **not** file as-is.

## What genuinely improved
- Steals **`LLM_API_KEY` — a credential OpenHands provisions** so the agent can run (present in every
  deployment, inherited by build scripts the agent executes). True confused-deputy theft of the
  product's own secret, not a harness-seeded decoy.
- **5/5 black-box**, bound to this injection (per-injection gate), exfils only a **fingerprint**
  (`sk-1ec…len=35`), not the raw key — responsible.
- Structural argument is sound: the analyzer only sees tool calls, is self-referential
  (`LLMSecurityAnalyzer.security_risk()` returns the acting model's own `action.security_risk`), and
  the model is never deceived, so no read-path defense applies.

## Two problems that block "CVE" (vs "CVE-grade in harness")
1. **"Analyzer ON" is illusory.** The run used `--llm-approve --headless`, but our SUBSIDIARY finding
   shows `--headless` silently downgrades `--llm-approve` to `NeverConfirm()` — so the analyzer was
   **inert**, not defeated-while-active. The honest claim is: *the flag was inert due to the headless
   bug; even active it structurally cannot catch this (reasons above).* The writeup must not imply an
   active analyzer was beaten.
2. **The decisive WAI objections are unaddressed.** Still **local runtime** + **loopback sink**
   (`127.0.0.1:18080`). `vuln2-cve-upgrade.md` itself named the real gate — reproduce in the **Docker
   runtime** and exfil via an **allowlisted channel**. This run did neither. A maintainer still says:
   "non-default local mode; the Docker egress-deny would block that loopback exfil." The upgrade fixed
   the *secret* axis, not the *posture* or *channel* axis — the two that make it WAI.

## To actually close it (the deciding experiment)
1. Reproduce **inside OpenHands' Docker runtime** (recommended posture). Key still reachable + exfil
   works ⇒ WAI defense gone.
2. Exfil via an **allowlisted channel** (LLM endpoint / GitHub gist the sandbox permits) so it
   survives egress-deny.
3. Target **`GITHUB_TOKEN`** where present (GitHub-integrated deployments) — higher impact than the
   LLM key.
4. **Dedup** vs embracethered's 2025 `GITHUB_TOKEN` leak (different mechanism: executed build code,
   model not deceived) before filing.

## Status line
CVE-grade **in the harness** (black-box 5/5). **Not** CVE-grade **for disclosure** — the Docker +
allowlisted-channel reproduction is the single experiment that decides it.

---

## CLOSED — Docker-runtime check failed (2026-10-17): VULN 2 is WAI, not a CVE

The deciding experiment was run. In OpenHands' recommended DockerWorkspace posture the
credential-theft lever **does not work**:
- `forward_env` default = `["DEBUG"]` → `LLM_API_KEY` is NOT in the container env.
- persisted `api_key` is redacted (`"**********"`) in conversation state.
- `get_secrets_as_env_vars()` injects a secret only if the command text names the key; `npm run build`
  names nothing ⇒ no secret injected.

So the build script has no credential to read in the sandbox. VULN 2 reproduces only in local/CLI mode
where the agent env carries the key — the exact posture OpenHands documents as unsafe. **Verdict: WAI,
not disclosable.** OpenHands' Docker credential isolation is genuinely sound here.

## Hunt scoreboard (honest, after all scrutiny)
- VULN 2 (build-script exfil, decoy + LLM-key variants): **WAI / closed** (Docker isolates creds).
- VULN 1 (unauth agent-server RCE): **duplicate** (OpenHands #17878/#17763, PR #17768; local-no-auth documented).
- Subsidiaries (`--llm-approve` headless bypass; insecure defaults): minor, adjacent to known, borrowed stamps.
- Indirect prompt injection (the actual goal): **0 confirmed**.

Net: no submittable CVE and no real IPI yet. What IS validated: the harness + black-box gate + review
discipline caught false positives and killed its own WAI/dup findings instead of filing junk.
