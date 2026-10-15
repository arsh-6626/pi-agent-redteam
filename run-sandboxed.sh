#!/usr/bin/env bash
# Run the agentic red-team agent INSIDE a locked-down container. The victim executes
# attacker-chosen shell, so this must never run on the host.
#   ./run-sandboxed.sh ["task"]     # red-team the reference victim
#   ./run-sandboxed.sh --verify      # prove the egress containment holds
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=pi-agent-redteam-sandbox
echo ">> building $IMAGE"
docker build -f sandbox/Dockerfile -t "$IMAGE" .

# cap-drop ALL + NET_ADMIN/NET_RAW (firewall) + SETUID/SETGID (drop root -> redteam).
COMMON=(--rm --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SETUID --cap-add SETGID
        --security-opt no-new-privileges --pids-limit 512 --memory 4g --cpus 2)

if [ "${1:-}" = "--verify" ]; then
  exec docker run "${COMMON[@]}" "$IMAGE" --verify
fi

[ -f .env ] || { echo "missing .env (need DEEPSEEK_API_KEY; copy .env.example)"; exit 1; }
TASK="${1:-}"

# findings + transfer library persist on the host so motifs ACCUMULATE across runs
# (the transfer differentiator). World-writable for the in-container uid 10001.
OUT="$PWD/sandbox-out"; mkdir -p "$OUT"; chmod 777 "$OUT"

CAP="${REDTEAM_TIMEOUT:-3600}"
docker rm -f part >/dev/null 2>&1 || true
cleanup() { docker rm -f part >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo ">> red-teaming reference victim in sandbox (cap ${CAP}s; REDTEAM_TIMEOUT=0 disables)"
RUN=(docker run "${COMMON[@]}" --name part
  --env-file .env
  -e FINDINGS_PATH=/app/findings/findings.json
  -v "$OUT":/app/findings
  "$IMAGE" ${TASK:+"$TASK"})
if [ "$CAP" = "0" ]; then "${RUN[@]}"; else timeout --signal=INT "$CAP" "${RUN[@]}" || echo ">> (stopped: hit ${CAP}s cap or interrupted)"; fi

echo ">> findings + transfer library -> $OUT/"
