# fabricator-agent

Minimal remote agent used by Fabricator core.

## Run locally

```bash
pip install -r fabricator-agent/requirements.txt
cd fabricator-agent
uvicorn agent_main:app --host 0.0.0.0 --port 8010
```

## Required env

- `AGENT_BACKEND_URL`
- `AGENT_ID`
- `AGENT_CONFIG_PATH`

## Pairing flow

1. Agent calls `/api/agent/enroll/request` and receives `claim_code`.
2. Admin binds this `agent_id` to a `slug` via `/api/agent/admin/pending/{agent_id}/bind`.
3. Agent calls `/api/agent/enroll/complete` and receives `agent_token`.
4. Runtime traffic uses `/api/agent/runtime/*` with `X-Agent-Token`.
