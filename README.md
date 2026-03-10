# fabricator-agent

Minimal remote agent used by Fabricator core.

## Complete Install (Ubuntu)

```bash
# 1) Fetch repository
sudo apt update
sudo apt install -y git build-essential debhelper dh-python python3 python3-venv
cd /root
if [ ! -d fabricator-agent/.git ]; then
  git clone https://github.com/ren0san/fabricator-agent.git
fi
cd fabricator-agent

# 2) Build, install/reinstall, restart service
sudo bash scripts/remote_deploy.sh /root/fabricator-agent

# 3) Verify
systemctl status fabricator-agent --no-pager || true
curl -sS http://127.0.0.1:8010/health
curl -sS http://127.0.0.1:8010/status
```

## Complete Update (Ubuntu)

```bash
# Option A (recommended): trigger instruction from Fabricator core
# kind = self-update-agent

# Option B: update manually from GitHub
sudo apt update
sudo apt install -y git
cd /root
if [ ! -d /root/fabricator-agent/.git ]; then
  git clone https://github.com/ren0san/fabricator-agent.git /root/fabricator-agent
fi
cd /root/fabricator-agent
git remote set-url origin https://github.com/ren0san/fabricator-agent.git
git remote -v
git fetch --all --prune
git checkout main
git reset --hard origin/main
git log -1 --oneline
grep -n "FABRICATOR_AGENT_SOURCE_REPO" agent_main.py
grep -n "last_instruction_id" agent_main.py
sudo bash scripts/remote_deploy.sh /root/fabricator-agent
sudo systemctl restart fabricator-agent
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
AGENT_LOCAL_API_URL=
AGENT_TEST_MODE=0
AGENT_PUBLIC_IP=

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
- local edge token fallback order:
  - `AGENT_LOCAL_API_TOKEN`
  - `SS14_EDGE_API_TOKEN`
  - `AGENT_API_TOKEN` / `SS14_API_TOKEN`
- for `create-slug`, the agent now first tries built-in local Watchdog provisioning
- set `AGENT_EMBEDDED_CREATE_SLUG=0` only if you explicitly want to force the old local HTTP API path

## Version check (terminal)

```bash
# Direct endpoint
curl -sS http://127.0.0.1:8010/version | jq

# Helper script
python3 scripts/show_version.py --url http://127.0.0.1:8010
```
