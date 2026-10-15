# pi-agent-redteam

Agentic red-teaming on the **pi** harness: hijack a *running* LLM coding agent via
**indirect prompt injection**, confirm the harmful tool call with an **action oracle**, and
**transfer** the winning technique to the next target as a capability-graph motif.

This is **not** source-code review / SAST. We attack the victim agent's tool-use decisions,
not its source. The one durable differentiator is **cross-target motif transfer** — promptfoo's
adaptive memory is scan-local; ours carries across targets and runs.

> **Authorized security research only.** Self-hosted OSS targets, sandboxed, novel-only,
> coordinated disclosure. The victim executes attacker-chosen shell — run via `run-sandboxed.sh`.
> **Claude is not in the runtime loop:** both the orchestration and the offense run on DeepSeek
> (the willing brain), which does not refuse the authorized red-team role.

## Architecture

```
pi agent (DeepSeek brain)  ──rt_* tools──▶  rtbackend/ (python)
  methodology in src/run.ts                   craft.py   : transfer + PIMiner + promptfoo + PAIR
  tools in src/tools.ts  ──execFile──▶        victim.py  : reference AGENTIC victim (ReAct coding agent)
                                              oracle.py  : harm verdict on ACTIONS (cmd/write/exfil)
                                              transfer.py: motif library (reuses agent-cve-hunt)
```

- **rt_craft** — candidate indirect injections. Mixes, in order: (1) **transferred motifs**
  replayed first, (2) **PIMiner** mined strategies + capability-graph motif *moves*
  (`~/exploit-agent/results/strategy_kg.json`), (3) **promptfoo** indirect-injection *framings*,
  (4) **PAIR** refinement by DeepSeek using the victim's prior trajectory. Each candidate carries
  `provenance` (`transfer` | `crafted`) so a win is attributable.
- **rt_deliver** — plants one candidate in the victim's untrusted surface (a README) and runs the
  **agentic victim** on a benign task. Returns the victim's action trajectory.
- **rt_oracle** — judges the victim's *actions*, not its words: `CMD_EXEC` / `WRITE_OUT` / `EXFIL`.
- **rt_propose / rt_learn** — the transfer library: deposit a confirmed win keyed by goal kind
  (canary slotted out), replay it first on the next victim. A harm from a motif whose `learned_on`
  != the current victim is **transfer**.
- **record_finding** — persists a confirmed hijack with evidence + provenance.

## Both tools, wired honestly

- **PIMiner**: strategy library (`~/exploit-agent/third_party/PIMiner/strategy_library/*.md`) and the
  10 pre-mined capability-graph motifs seed `rt_craft`. The transfer store reuses
  `~/agent-cve-hunt/agenthunt/library.py`.
- **promptfoo**: `rtbackend/promptfoo/` is a custom provider that drives the **same agentic victim +
  action oracle** — a breadth/reporting surface over the *running agent*, not a tool-fuzz. It does
  not own the attack; the transfer library (which promptfoo lacks) is the differentiator.

## Run

```bash
cp .env.example .env         # fill DEEPSEEK_API_KEY
./run-sandboxed.sh --verify  # prove egress containment
./run-sandboxed.sh           # red-team the reference victim; findings -> sandbox-out/
```

Un-sandboxed (reference victim only; it still executes shell confined to a throwaway temp base —
use the container for anything else):

```bash
npm run redteam
```

promptfoo surface:

```bash
PROMPTFOO_PYTHON=python3 npx promptfoo eval -c rtbackend/promptfoo/promptfooconfig.yaml
```

## Victim adapter — dropping in a real target

The reference victim (`rtbackend/victim.py::run_episode`) is a minimal ReAct coding agent with
`read_file / run_shell / write_file`, DeepSeek brain, confined to a disposable base
(`workspace/` = task, `SECRET_ZONE/` = escape sink). To red-team **OpenHands / Aider / Open
Interpreter**, implement the same contract — plant `injection` in an untrusted file, run the agent
on `task`, return `{events:[{tool,args,result}], secret_zone_contents, workspace_files, canary}` —
and point `deliver` at it. The oracle and transfer layers are target-agnostic.

## Status (honest)

- End-to-end loop **works**: craft → deliver (agentic victim) → oracle → learn/propose, validated
  against live DeepSeek. Transfer *plumbing* verified (a motif learned on victim A re-grounds on a
  fresh run tagged `learned_on=A`).
- **The reference victim (deepseek-flash) RESISTS.** A PAIR hunt (`scripts/pair_hunt.py`) across the
  `aider`/`openhands` victim profiles did **not** land a genuine hijack: `cmd_exec` was robustly
  clean (that oracle checks real tool-call args + filesystem). An early `say_string` "hit" was an
  **oracle false positive** — the victim refused but *quoted* the canary while explaining the
  refusal; `oracle.py` now guards against refusal/negation language. Lesson: the **action** harm
  classes (cmd_exec/write_out/exfil) are the trustworthy oracle; text-based `say_string` is weak.
- So there is **no genuine hijack to transfer yet** — the transfer result remains plumbing-only.
- **Victim adapters:** `rtbackend/victim.py` (reference, with realistic `VICTIM_PROFILES`) and
  `rtbackend/victims/openhands.py` (real OpenHands via headless `openhands.core.main`, UNTESTED
  pending install). Select with `rt_deliver{victim:"openhands"}`.
- **Next milestones:** a confirmed hijack of a *real* agent (OpenHands/Aider are more injectable
  than a bare deepseek-flash ReAct loop), then an oracle-confirmed transfer across two real victims
  (KG motifs are `oracle_confirmed:false` today). This repo is the vehicle to get them.
