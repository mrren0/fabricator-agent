# fabricator-agent

Minimal remote agent used by Fabricator core.

## Install (Debian/Ubuntu)

### Option A: Install from APT repository (recommended)

`fabricator-agent` is not in the default Ubuntu/Debian repositories.
`apt install fabricator-agent` works only after adding the Fabricator APT repo.

```bash
# add Fabricator APT repo first (URL/key are provided by Fabricator ops)
sudo apt update
sudo apt install -y fabricator-agent
```

### Option B: Build and install .deb locally

```bash
sudo apt update
sudo apt install -y build-essential debhelper dh-python python3 python3-venv
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

## Pairing flow

1. Agent calls `/api/agent/enroll/request` and receives `claim_code`.
2. Admin binds this `agent_id` to a `slug` via `/api/agent/admin/pending/{agent_id}/bind`.
3. Agent calls `/api/agent/enroll/complete` and receives `agent_token`.
4. Runtime traffic uses `/api/agent/runtime/*` with `X-Agent-Token`.

## Troubleshooting

If you see:

```bash
E: Unable to locate package fabricator-agent
```

it means the Fabricator APT repository is not configured on this machine (or package publication is not set up yet).

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
