# fabricator-agent

Minimal remote agent used by Fabricator core.

## Install (Debian/Ubuntu)

### Install from GitHub repository

```bash
sudo apt update
sudo apt install -y git build-essential debhelper dh-python python3 python3-venv
git clone https://github.com/ren0san/fabricator-agent.git
cd fabricator-agent
dpkg-buildpackage -us -uc -b
cd ..
sudo apt install -y ./fabricator-agent_0.1.0-1_all.deb
```

After install:

```bash
systemctl status fabricator-agent --no-pager
journalctl -u fabricator-agent -n 50 --no-pager
```

Package installs and enables `fabricator-agent.service` automatically.

## Complete Install (Ubuntu)

```bash
# 1) build package
sudo apt update
sudo apt install -y git build-essential debhelper dh-python python3 python3-venv
git clone https://github.com/ren0san/fabricator-agent.git
cd fabricator-agent
dpkg-buildpackage -us -uc -b

# 2) install package
cd ..
sudo apt install -y ./fabricator-agent_0.1.0-1_all.deb

# 3) configure runtime env
sudo tee /etc/default/fabricator-agent >/dev/null <<'EOF'
AGENT_BACKEND_URL=https://api.thun-der.ru
AGENT_HTTP_PORT=8010
AGENT_LOCAL_API_URL=http://127.0.0.1:8000
EOF

# 4) restart and verify
sudo systemctl daemon-reload
sudo systemctl enable --now fabricator-agent
sudo systemctl restart fabricator-agent
systemctl status fabricator-agent --no-pager
curl -s http://127.0.0.1:8010/health
curl -s http://127.0.0.1:8010/status
```

## Complete Uninstall (Ubuntu)

```bash
# 1) stop and disable service
sudo systemctl stop fabricator-agent || true
sudo systemctl disable fabricator-agent || true

# 2) remove package and orphaned deps
sudo apt purge -y fabricator-agent
sudo apt autoremove -y

# 3) remove state/config leftovers
sudo rm -rf /opt/fabricator-agent
sudo rm -f /etc/default/fabricator-agent
sudo rm -f /etc/fabricator-agent/config.toml
sudo rm -f /lib/systemd/system/fabricator-agent.service

# 4) reload systemd and verify service is gone
sudo systemctl daemon-reload
sudo systemctl reset-failed
systemctl status fabricator-agent --no-pager || true
```

## Quick Start (Ubuntu, 5-10 min)

1. Install package:

```bash
sudo apt update
sudo apt install -y git build-essential debhelper dh-python python3 python3-venv
git clone https://github.com/ren0san/fabricator-agent.git
cd fabricator-agent
dpkg-buildpackage -us -uc -b
cd ..
sudo apt install -y ./fabricator-agent_0.1.0-1_all.deb
```

2. Set minimum required env:

```bash
sudo tee /etc/default/fabricator-agent >/dev/null <<'EOF'
AGENT_BACKEND_URL=https://api.thun-der.ru
AGENT_HTTP_PORT=8010
AGENT_LOCAL_API_URL=http://127.0.0.1:8000
EOF
```

3. Restart and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl restart fabricator-agent
systemctl status fabricator-agent --no-pager
curl -s http://127.0.0.1:8010/health
curl -s http://127.0.0.1:8010/status
```

4. On backend side complete bind for `agent_id` from `/status`, then wait until `status.paired=true`.

Optional hardening (recommended for production):

```bash
LOCAL_TOKEN="$(openssl rand -hex 32)"
ADMIN_TOKEN="$(openssl rand -hex 32)"
echo "AGENT_LOCAL_API_TOKEN=${LOCAL_TOKEN}" | sudo tee -a /etc/default/fabricator-agent >/dev/null
echo "AGENT_ADMIN_TOKEN=${ADMIN_TOKEN}" | sudo tee -a /etc/default/fabricator-agent >/dev/null
sudo systemctl restart fabricator-agent
```

## Quick Ops

Check supported runtime instructions:

```bash
curl -s http://127.0.0.1:8010/instructions
```

Check available diagnostics:

```bash
curl -s http://127.0.0.1:8010/diagnostics
```

Run emergency diagnostic (manual local call):

```bash
curl -s -X POST http://127.0.0.1:8010/diagnostics/run \
  -H "Content-Type: application/json" \
  -H "X-Agent-Admin-Token: CHANGE_ME_STRONG_RANDOM_TOKEN" \
  -d '{"name":"fabricator-agent-service-status","timeout_seconds":30}'
```

## Defaults (no manual config required)

- `AGENT_BACKEND_URL=https://api.thun-der.ru`
- `AGENT_CONFIG_PATH=/etc/fabricator-agent/config.toml`
- `AGENT_TOKEN_FILE=/opt/fabricator-agent/agent.token`
- `AGENT_ID` is auto-generated and persisted in `/opt/fabricator-agent/agent.id` if not provided

## Optional env

- `AGENT_ID`
- `AGENT_PUBLIC_KEY`
- `AGENT_POLL_SECONDS`
- `AGENT_HTTP_TIMEOUT_SECONDS`
- `AGENT_HTTP_PORT`
- `AGENT_API_TOKEN` (optional legacy mode; not required for runtime pairing flow)
- `AGENT_LOCAL_API_URL` (default `http://127.0.0.1:8000`)
- `AGENT_LOCAL_API_TOKEN` (optional; token for local Fabricator API calls)
- `AGENT_ADMIN_TOKEN` (optional; required only for local emergency diagnostic endpoint `/diagnostics/run`)
- `AGENT_DIAG_TIMEOUT_SECONDS` (default `45`)
- `AGENT_OUTPUT_TAIL_CHARS` (default `4000`)
- `AGENT_FABRICATOR_SERVICE` (default `ss14-provisioner`)

## Pairing flow

1. Agent calls `/api/agent/enroll/request` and receives `claim_code`.
2. Admin binds this `agent_id` to a `slug` via `/api/agent/admin/pending/{agent_id}/bind`.
3. Agent calls `/api/agent/enroll/complete` and receives `agent_token`.
4. Runtime traffic uses `/api/agent/runtime/*` with `X-Agent-Token`.

If runtime token becomes invalid (for example after rebind/reissue), agent clears local token and re-enrolls automatically.

## Runtime instruction kinds (fixed set)

- `create-instance`
- `delete-instance`
- `restart-instance`
- `stop-instance`
- `update-instance`
- `run-diagnostic`
- `ping`
- `set-poll-seconds`
- `refresh-config`

`install-watchdog` is disabled in favor of fixed instruction kinds only.

Instruction payload examples (from backend):
(`repo` below is instance source repo for `create-instance`, not this agent install URL)

- `create-instance`: `{"kind":"create-instance","payload":{"body":{"slug":"alpha","repo":"https://github.com/org/repo","branch":"master"}}}`
- `restart-instance`: `{"kind":"restart-instance","payload":{"slug":"alpha"}}`
- `stop-instance`: `{"kind":"stop-instance","payload":{"slug":"alpha","reason":"maintenance"}}`
- `run-diagnostic`: `{"kind":"run-diagnostic","payload":{"name":"fabricator-service-journal-tail","timeout_seconds":30}}`

## Emergency diagnostics

For force-majeure troubleshooting, agent exposes a local endpoint:

`POST /diagnostics/run`

Headers:

- `X-Agent-Admin-Token: <AGENT_ADMIN_TOKEN>`

Body:

```json
{
  "name": "fabricator-service-status",
  "timeout_seconds": 30
}
```

Response contains `ok`, `error`, and `result` with `returncode`, `stdout_tail`, `stderr_tail`.

Allowed diagnostic names:

- `uname`
- `os-release`
- `disk-free`
- `memory`
- `fabricator-service-status`
- `fabricator-agent-service-status`
- `fabricator-service-journal-tail`
- `fabricator-agent-journal-tail`

## Troubleshooting

If you see:

```bash
E: Unable to locate package fabricator-agent
```

this is expected on a clean server without Fabricator APT repo.
Use the GitHub install flow from this README (`git clone` + `dpkg-buildpackage` + local `.deb` install).

If you see:

```bash
sudo: unable to resolve host <hostname>: Name or service not known
```

fix host mapping (replace `tunnel-DE` with your hostname):

```bash
hostnamectl --static
echo "127.0.1.1 tunnel-DE" | sudo tee -a /etc/hosts >/dev/null
```

If service fails with:

```bash
Error: Invalid value for '--port': '' is not a valid integer.
```

set port explicitly and restart:

```bash
echo 'AGENT_HTTP_PORT=8010' | sudo tee /etc/default/fabricator-agent >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart fabricator-agent
systemctl status fabricator-agent --no-pager
```
