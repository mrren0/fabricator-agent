import sys
import types
from unittest.mock import patch

if "pwd" not in sys.modules:
    pwd_stub = types.ModuleType("pwd")
    pwd_stub.getpwnam = lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("pwd unavailable"))
    sys.modules["pwd"] = pwd_stub
if "grp" not in sys.modules:
    grp_stub = types.ModuleType("grp")
    grp_stub.getgrnam = lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("grp unavailable"))
    sys.modules["grp"] = grp_stub

import agent_main


def _runtime() -> agent_main.AgentRuntime:
    runtime = agent_main.AgentRuntime.__new__(agent_main.AgentRuntime)
    runtime.local_api_url = "http://127.0.0.1:8000"
    runtime.timeout = 5
    runtime.status = {}
    return runtime


def test_supported_instruction_kinds_include_update_policy():
    kinds = agent_main.AgentRuntime.supported_instruction_kinds()
    assert "get-instance-update-policy" in kinds
    assert "set-instance-update-policy" in kinds


def test_execute_instruction_get_instance_update_policy_uses_local_api():
    runtime = _runtime()
    item = {"id": "inst-1", "kind": "get-instance-update-policy", "payload": {"slug": "srv-1"}}

    response = types.SimpleNamespace(status_code=200, json=lambda: {"update_mode": "git"}, text='{"update_mode":"git"}')
    with patch.object(agent_main, "_local_api_token", return_value="token"), \
         patch.object(agent_main.requests, "request", return_value=response) as request_mock:
        ok, result, error = runtime._execute_instruction(item)

    assert ok is True
    assert error is None
    assert (result.get("response") or {}).get("update_mode") == "git"
    request_mock.assert_called_once_with(
        "GET",
        "http://127.0.0.1:8000/api/ss14/admin/instances/srv-1/update-policy",
        headers={"X-API-Token": "token", "Content-Type": "application/json"},
        timeout=5,
    )


def test_execute_instruction_set_instance_update_policy_uses_local_api():
    runtime = _runtime()
    item = {
        "id": "inst-2",
        "kind": "set-instance-update-policy",
        "payload": {
            "slug": "srv-1",
            "update_mode": "cdn",
            "manifest_url": "https://cdn.example/manifest.json",
            "repo": "https://github.com/org/repo",
            "branch": "master",
        },
    }

    response = types.SimpleNamespace(
        status_code=200,
        json=lambda: {"update_mode": "cdn", "manifest_url": "https://cdn.example/manifest.json"},
        text='{"update_mode":"cdn"}',
    )
    with patch.object(agent_main, "_local_api_token", return_value="token"), \
         patch.object(agent_main.requests, "request", return_value=response) as request_mock:
        ok, result, error = runtime._execute_instruction(item)

    assert ok is True
    assert error is None
    assert (result.get("response") or {}).get("update_mode") == "cdn"
    request_mock.assert_called_once_with(
        "POST",
        "http://127.0.0.1:8000/api/ss14/admin/instances/srv-1/update-policy",
        headers={"X-API-Token": "token", "Content-Type": "application/json"},
        timeout=5,
        json={
            "update_mode": "cdn",
            "manifest_url": "https://cdn.example/manifest.json",
            "repo": "https://github.com/org/repo",
            "branch": "master",
        },
    )
