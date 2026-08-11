#!/usr/bin/env python3
"""Register Doxa's externally supervised MCP service with managed-dev."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

SERVICE = "doxa-managed"
HOSTNAME = os.environ.get("DOXA_HOSTNAME", "doxa-managed.motiavated.com")
CONTAINER = "doxa-managed-mcp"
TARGET_URL = f"http://{CONTAINER}:3000"
PORT = int(os.environ.get("MCP_PORT", "3010"))
HOME = Path.home()
REGISTRY = HOME / ".local/share/managed-dev/registry.json"
MANAGED_DEV = HOME / ".local/bin/managed-dev"

if not 1 <= PORT <= 65535:
    raise SystemExit("MCP_PORT must be in 1-65535")

inspection = json.loads(
    subprocess.run(
        ["docker", "inspect", CONTAINER],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
)[0]
if not inspection["State"]["Running"]:
    raise SystemExit(f"{CONTAINER} is not running")
if "web" not in inspection["NetworkSettings"]["Networks"]:
    raise SystemExit(f"{CONTAINER} is not attached to the web network")
pid = int(inspection["State"]["Pid"])
if pid <= 0:
    raise SystemExit(f"{CONTAINER} has no live host PID")

registry = json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}
if not isinstance(registry, dict):
    raise SystemExit("managed-dev registry is not an object")
registry[SERVICE] = {
    "project": "doxa",
    "cwd": "/app",
    "command": "node dist/index.js",
    "port": PORT,
    "hostname": HOSTNAME,
    "type": "misc",
    "pid": pid,
    "log": f"docker logs {CONTAINER}",
    "node_version": "24",
    "started_at": int(time.time()),
    "supervisor": "docker-compose",
    "target_url": TARGET_URL,
}
REGISTRY.parent.mkdir(parents=True, exist_ok=True)
tmp = REGISTRY.with_suffix(".tmp")
tmp.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
os.chmod(tmp, 0o600)
tmp.replace(REGISTRY)
subprocess.run([str(MANAGED_DEV), "expose", SERVICE], check=True)
print(json.dumps({"service": SERVICE, "hostname": HOSTNAME, "target": TARGET_URL}, indent=2))
