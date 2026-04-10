import sys
import tempfile
import types
from pathlib import Path
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
    assert "reset-instance-sqlite" in kinds
    assert "list-instance-data" in kinds
    assert "download-instance-data-file" in kinds
    assert "upload-instance-data-file" in kinds


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
            with patch.object(runtime, "_embedded_ensure_runtime_for_manifest_url", return_value=None):
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


def test_set_instance_update_policy_installs_runtime_from_manifest_metadata():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        wd_root = root / "watchdog-srv-1"
        fragments = wd_root / "instances.d"
        fragments.mkdir(parents=True, exist_ok=True)
        appsettings_base = wd_root / "appsettings.base.yml"
        appsettings_base.write_text(
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
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            with patch.object(
                runtime,
                "_embedded_ensure_runtime_for_manifest_url",
                return_value={
                    "framework": "Microsoft.NETCore.App",
                    "version": "9.0.0",
                    "installed": True,
                    "already_present": False,
                    "source": "manifest:https://cdn.example/manifest.json",
                },
            ) as runtime_mock:
                ok, result, error = runtime._embedded_set_instance_update_policy(
                    "srv-1",
                    "cdn",
                    "https://cdn.example/manifest.json",
                    "https://github.com/org/repo",
                    "master",
                )
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok is True
    assert error is None
    assert result["runtime"]["framework"] == "Microsoft.NETCore.App"
    assert result["runtime"]["version"] == "9.0.0"
    runtime_mock.assert_called_once_with("https://cdn.example/manifest.json")


def test_restart_instance_prepares_runtime_from_extracted_runtimeconfig():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        slug = "srv-1"
        wd_root = root / "watchdog-srv-1"
        bin_dir = wd_root / "instances" / slug / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "Robust.Server.runtimeconfig.json").write_text(
            '{"runtimeOptions":{"framework":{"name":"Microsoft.NETCore.App","version":"9.0.0"}}}',
            encoding="utf-8",
        )
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            with patch.object(runtime, "_embedded_dotnet_command", return_value=["/opt/dotnet/dotnet"]):
                with patch.object(runtime, "_embedded_list_installed_runtimes", return_value={}):
                    with patch.object(
                        runtime,
                        "_embedded_ensure_dotnet_runtime",
                        return_value=["/opt/dotnet/dotnet"],
                    ) as install_mock:
                        with patch.object(runtime, "_embedded_guess_watchdog_services", return_value=[]):
                            with patch.object(agent_main.subprocess, "run") as run_mock:
                                run_mock.side_effect = [
                                    types.SimpleNamespace(stdout="", stderr="", returncode=0),
                                    types.SimpleNamespace(stdout="active\n", stderr="", returncode=0),
                                ]
                                ok, result, error = runtime._execute_watchdog_service_restart(
                                    instruction_id="inst-r1",
                                    kind="restart-instance",
                                    slug=slug,
                                )
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok is True
    assert error is None
    assert result["runtime"]["framework"] == "Microsoft.NETCore.App"
    assert result["runtime"]["version"] == "9.0.0"
    install_mock.assert_called_once_with("Microsoft.NETCore.App", "9.0.0")


def test_reset_instance_sqlite_removes_data_directory():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        slug = "srv-1"
        wd_root = root / "watchdog-srv-1"
        inst_dir = wd_root / "instances" / slug
        (inst_dir / "data").mkdir(parents=True, exist_ok=True)
        (inst_dir / "data" / "server.db").write_text("sqlite", encoding="utf-8")
        (inst_dir / "config.toml").write_text('[database]\nengine = "sqlite"\n', encoding="utf-8")
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            ok, result, error = runtime._embedded_reset_instance_sqlite(
                slug,
                delete_database=False,
                delete_data=True,
            )
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok is True
    assert error is None
    assert result["updated"] is True
    assert any(path.endswith("data") for path in result["deleted_paths"])


def test_database_values_ignore_commented_postgres_lines():
    runtime = _runtime()

    values = runtime._database_values_from_config(
        '[database]\n# engine = "postgres"\n# pg_host = "127.0.0.1"\n'
    )

    assert values["engine"] == ""


def test_instance_data_instructions_roundtrip_inside_data_only():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        slug = "srv-1"
        wd_root = root / "watchdog-srv-1"
        inst_dir = wd_root / "instances" / slug
        (inst_dir / "data" / "maps").mkdir(parents=True, exist_ok=True)
        (inst_dir / "data" / "maps" / "map.yml").write_text("abc", encoding="utf-8")
        (inst_dir / "config.toml").write_text('[game]\nhostname = "srv-1"\n', encoding="utf-8")
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            with patch.object(runtime, "_upload_download_transfer_chunks", return_value=(True, {"transfer_id": "tr-1", "size": 3}, None)):
                ok_list, list_result, list_error = runtime._execute_instruction({
                    "id": "inst-list",
                    "kind": "list-instance-data",
                    "payload": {"slug": slug, "path": "maps"},
                })
                ok_download, download_result, download_error = runtime._execute_instruction({
                    "id": "inst-download",
                    "kind": "download-instance-data-file",
                    "payload": {"slug": slug, "path": "maps/map.yml"},
                })
                ok_upload, upload_result, upload_error = runtime._execute_instruction({
                    "id": "inst-upload",
                    "kind": "upload-instance-data-file",
                    "payload": {"slug": slug, "path": "maps", "filename": "new.yml", "content_base64": "eHl6"},
                })
                ok_delete, delete_result, delete_error = runtime._execute_instruction({
                    "id": "inst-delete",
                    "kind": "delete-instance-data-entry",
                    "payload": {"slug": slug, "path": "maps/new.yml"},
                })
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok_list is True
    assert list_error is None
    assert list_result["path"] == "maps"
    assert list_result["items"][0]["name"] == "map.yml"
    assert ok_download is True
    assert download_error is None
    assert download_result["transfer_id"] == "tr-1"
    assert ok_upload is True
    assert upload_error is None
    assert upload_result["path"] == "maps/new.yml"
    assert ok_delete is True
    assert delete_error is None
    assert delete_result["deleted"] is True
