import sys
import tempfile
import types
from pathlib import Path

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


def test_execute_instruction_get_instance_update_policy_uses_embedded_fragment():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        wd_root = root / "watchdog-srv-1"
        fragments = wd_root / "instances.d"
        fragments.mkdir(parents=True, exist_ok=True)
        (fragments / "srv-1.yml").write_text(
            "    srv-1:\n"
            "      Name: \"srv-1\"\n"
            "      ApiToken: \"token-1\"\n"
            "      ApiPort: 1212\n"
            "      ConfigFileName: \"config.toml\"\n"
            "      UpdateType: \"Manifest\"\n"
            "      Updates:\n"
            "        ManifestUrl: \"https://cdn.example/srv-1/manifest\"\n"
            "      TimeoutSeconds: 120\n",
            encoding="utf-8",
        )
        item = {"id": "inst-1", "kind": "get-instance-update-policy", "payload": {"slug": "srv-1"}}
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            ok, result, error = runtime._execute_instruction(item)
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok is True
    assert error is None
    assert result["update_mode"] == "cdn"
    assert result["manifest_url"] == "https://cdn.example/srv-1/manifest"


def test_execute_instruction_set_instance_update_policy_updates_embedded_fragment():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        wd_root = root / "watchdog-srv-1"
        fragments = wd_root / "instances.d"
        fragments.mkdir(parents=True, exist_ok=True)
        appsettings_base = wd_root / "appsettings.base.yml"
        appsettings_base.write_text(
            "Serilog:\n"
            "  MinimumLevel:\n"
            "    Default: Information\n\n"
            "Servers:\n"
            "  Instances:\n",
            encoding="utf-8",
        )
        (fragments / "srv-1.yml").write_text(
            "    srv-1:\n"
            "      Name: \"srv-1\"\n"
            "      ApiToken: \"token-1\"\n"
            "      ApiPort: 1212\n"
            "      ConfigFileName: \"config.toml\"\n"
            "      UpdateType: \"Git\"\n"
            "      Updates:\n"
            "        BaseUrl: \"https://github.com/org/repo\"\n"
            "        Branch: \"master\"\n"
            "      TimeoutSeconds: 120\n",
            encoding="utf-8",
        )
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
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            ok, result, error = runtime._execute_instruction(item)
            fragment_text = (fragments / "srv-1.yml").read_text(encoding="utf-8")
            appsettings_text = (wd_root / "appsettings.yml").read_text(encoding="utf-8")
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok is True
    assert error is None
    assert result["update_mode"] == "cdn"
    assert result["manifest_url"] == "https://cdn.example/manifest.json"
    assert 'UpdateType: "Manifest"' in fragment_text
    assert 'ManifestUrl: "https://cdn.example/manifest.json"' in fragment_text
    assert 'UpdateType: "Manifest"' in appsettings_text
