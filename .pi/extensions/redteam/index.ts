/**
 * Project extension: expose the agentic red-team tools inside the interactive `pi` interface.
 *
 * Run `pi` from the repo root (grant project trust) and the rt_* tools + the red-team methodology
 * (.pi/APPEND_SYSTEM.md) are live in the pi harness — no headless `src/run.ts` needed. The pi agent
 * itself is the orchestrator; point its model at DeepSeek (PROVIDER=deepseek) so Claude stays out of
 * the loop, same as the tools' own DeepSeek-backed victim/attacker.
 *
 * Reuses the exact tool definitions from src/tools.ts (one source of truth for headless + interactive).
 */
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { buildTools } from "../../../src/tools.ts";

export default function redteamExtension(pi: ExtensionAPI) {
  pi.on("session_start", (_event, ctx) => {
    const repoRoot = process.cwd();
    const findingsPath = join(repoRoot, "findings", "findings.json");
    const tools = buildTools(repoRoot, findingsPath);
    for (const t of tools) pi.registerTool(t as any);
    ctx.ui.notify(
      `red-team tools live: ${tools.map((t) => t.name).join(", ")}  (brain should be PROVIDER=deepseek)`,
      "info",
    );
  });
}
