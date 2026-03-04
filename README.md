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
if [ ! -d fabricator-agent/.git ]; then
  git clone https://github.com/ren0san/fabricator-agent.git
fi
cd fabricator-agent
git fetch --all --prune
git checkout main
git pull --ff-only origin main
sudo bash scripts/remote_deploy.sh /root/fabricator-agent
systemctl status fabricator-agent --no-pager || true
curl -sS http://127.0.0.1:8010/status
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
AGENT_LOCAL_API_URL=http://127.0.0.1:8000
AGENT_TEST_MODE=0

# Optional secure auto-bind flow
AGENT_BOOTSTRAP_TOKEN=
AGENT_SLUG=

# Optional local diagnostic endpoint protection
AGENT_ADMIN_TOKEN=
EOF

sudo systemctl daemon-reload
sudo systemctl restart fabricator-agent
```
