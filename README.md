# fabricator-agent

Minimal remote agent used by Fabricator core.

## Install (Debian/Ubuntu)

```bash
apt install fabricator-agent
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
