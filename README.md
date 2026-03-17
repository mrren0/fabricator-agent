# fabricator-agent

Minimal remote agent used by Fabricator core.

## Install (Ubuntu)

```bash
sudo apt update
sudo apt install -y git build-essential debhelper dh-python python3 python3-venv
cd ~
if [ ! -d ~/fabricator-agent/.git ]; then
  git clone https://github.com/ren0san/fabricator-agent.git ~/fabricator-agent
fi
cd ~/fabricator-agent
dpkg-buildpackage -us -uc -b
sudo apt-get install -y --reinstall ../fabricator-agent_*_all.deb
sudo systemctl daemon-reload
sudo systemctl enable --now fabricator-agent.service
sudo systemctl restart fabricator-agent.service
systemctl status fabricator-agent --no-pager || true
curl -sS http://127.0.0.1:8010/health
curl -sS http://127.0.0.1:8010/status
```

## Update (Ubuntu)

```bash
sudo apt update
sudo apt install -y git
cd ~
if [ ! -d ~/fabricator-agent/.git ]; then
  git clone https://github.com/ren0san/fabricator-agent.git ~/fabricator-agent
fi
cd ~/fabricator-agent
git remote set-url origin https://github.com/ren0san/fabricator-agent.git
git remote -v
git fetch --all --prune
git checkout main
git reset --hard origin/main
git log -1 --oneline
grep -n "FABRICATOR_AGENT_SOURCE_REPO" agent_main.py
grep -n "last_instruction_id" agent_main.py
dpkg-buildpackage -us -uc -b
sudo apt-get install -y --reinstall ../fabricator-agent_*_all.deb
sudo systemctl daemon-reload
sudo systemctl enable --now fabricator-agent.service
sudo systemctl restart fabricator-agent.service
sleep 5
systemctl status fabricator-agent --no-pager || true
curl -sS http://127.0.0.1:8010/status | jq
grep -n "FABRICATOR_AGENT_SOURCE_REPO" /opt/fabricator-agent/agent_main.py
grep -n "last_instruction_id" /opt/fabricator-agent/agent_main.py
journalctl -u fabricator-agent -n 50 --no-pager
```

## Complete Uninstall (Ubuntu)

```bash
# 1) Stop and disable service
sudo systemctl stop fabricator-agent || true
sudo systemctl disable fabricator-agent || true

# 2) Remove package
sudo apt purge -y fabricator-agent
sudo apt autoremove -y

# 3) Remove leftover files
sudo rm -rf /opt/fabricator-agent
sudo rm -f /etc/default/fabricator-agent
sudo rm -f /etc/fabricator-agent/config.toml
sudo rm -f /lib/systemd/system/fabricator-agent.service

# 4) Reload systemd
sudo systemctl daemon-reload
sudo systemctl reset-failed
systemctl status fabricator-agent --no-pager || true
```

## Optional Runtime Config

By default installation works without manual env setup. If needed, override defaults:

```bash
sudo tee /etc/default/fabricator-agent >/dev/null <<'EOF'
AGENT_BACKEND_URL=https://api.thun-der.ru
AGENT_HTTP_PORT=8010
AGENT_INSTRUCTION_WAIT_SECONDS=25
AGENT_HEARTBEAT_SECONDS=30
AGENT_CONFIG_SYNC_SECONDS=30
AGENT_LOG_LEVEL=INFO
AGENT_LOCAL_API_URL=
AGENT_TEST_MODE=0
AGENT_PUBLIC_IP=
AGENT_SELF_UPDATE_SERVICE=fabricator-agent

# Optional secure auto-bind flow
AGENT_BOOTSTRAP_TOKEN=
AGENT_SLUG=

# Optional local diagnostic endpoint protection
AGENT_ADMIN_TOKEN=
EOF

sudo systemctl daemon-reload
sudo systemctl restart fabricator-agent
```

Remote-only default behavior:

- if `AGENT_LOCAL_API_URL` is empty, the agent tries `http://127.0.0.1:8000`
- `AGENT_LOG_LEVEL` controls instruction execution logs in `journalctl -u fabricator-agent` (`INFO` by default)
- if `AGENT_LOCAL_API_URL` points to control-plane instead of local edge API, restart/update/stop instructions are rejected with explicit log error to prevent false `ok` acks
- `AGENT_SELF_UPDATE_SERVICE` controls which systemd unit is restarted after self-update command (default: `fabricator-agent`)
- the core control plane talks to the agent via outbound long-poll + ack; no public inbound agent port is required
- `AGENT_INSTRUCTION_WAIT_SECONDS` controls long-poll hold time on master instruction queue
- `AGENT_HEARTBEAT_SECONDS` controls how often the agent sends heartbeat while pull runs continuously
- `AGENT_CONFIG_SYNC_SECONDS` controls how often the agent scans and uploads changed remote `config.toml` snapshots to the master cache
- local edge token fallback order:
  - `AGENT_LOCAL_API_TOKEN`
  - `SS14_EDGE_API_TOKEN`
  - `AGENT_API_TOKEN` / `SS14_API_TOKEN`
- for `create-slug`, the agent now first tries built-in local Watchdog provisioning
- set `AGENT_EMBEDDED_CREATE_SLUG=0` only if you explicitly want to force the old local HTTP API path
- built-in provisioning auto-detects common systemd unit names for Watchdog if `SS14_WD_SYSTEMD_SERVICE` is not set
- built-in provisioning follows the same model as master backend: one shared Watchdog installation manages many slugs

## Version check (terminal)

```bash
# Direct endpoint
curl -sS http://127.0.0.1:8010/version | jq

# Helper script
python3 scripts/show_version.py --url http://127.0.0.1:8010
```
