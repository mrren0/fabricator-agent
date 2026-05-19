import sys
import sqlite3
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
    runtime.backend_url = "https://api.example.test"
    runtime.timeout = 5
    runtime.status = {}
    return runtime


def test_supported_instruction_kinds_include_update_policy():
    kinds = agent_main.AgentRuntime.supported_instruction_kinds()
    assert "get-instance-update-policy" in kinds
    assert "set-instance-update-policy" in kinds
    assert "reset-instance-sqlite" in kinds
    assert "download-instance-database-backup" in kinds
    assert "upload-instance-database-backup" in kinds
    assert "reset-instance-postgres" in kinds
    assert "list-instance-data" in kinds
    assert "get-instance-whitelist" in kinds
    assert "set-instance-whitelist-enabled" in kinds
    assert "add-instance-whitelist-player" in kinds
    assert "remove-instance-whitelist-player" in kinds
    assert "download-instance-data-file" in kinds
    assert "upload-instance-data-file" in kinds


def test_rebuild_manifest_sends_build_id_and_patches_captured_log():
    runtime = _runtime()
    posted = {}
    patched = {}

    class LogResponse:
        status_code = 200
        text = "git clone\nResolved commit abc123\n"

    class PatchResponse:
        status_code = 200
        text = '{"ok":true}'

    def fake_post(url, headers=None, json=None, timeout=None):
        posted["url"] = url
        posted["headers"] = headers
        posted["json"] = json
        response = agent_main.requests.Response()
        response.status_code = 200
        response._content = b'{"manifest_url":"https://cdn.example/manifest","status":"ready"}'
        return response

    def fake_get(url, timeout=None):
        posted["log_url"] = url
        return LogResponse()

    def fake_patch(url, headers=None, json=None, timeout=None):
        patched["url"] = url
        patched["headers"] = headers
        patched["json"] = json
        return PatchResponse()

    with patch.object(agent_main.requests, "post", side_effect=fake_post), patch.object(
        agent_main.requests, "get", side_effect=fake_get
    ), patch.object(agent_main.requests, "patch", side_effect=fake_patch):
        ok, result, error = runtime._embedded_rebuild_manifest(
            "moonlight-shard",
            "https://github.com/org/repo",
            "master",
            True,
            "http://127.0.0.1:13001",
            "master-token",
            "build-123",
        )

    assert ok is True
    assert error is None
    assert posted["json"]["build_id"] == "build-123"
    assert result["build_id"] == "build-123"
    assert "/api/internal/manifest/attempts/build-123/log" in patched["url"]
    assert "Resolved commit abc123" in patched["json"]["log_text"]


def test_resolve_watchdog_api_base_url_uses_local_default_for_embedded_instance():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        wd_root = root / "watchdog-fallout"
        cfg = wd_root / "instances" / "fallout" / "config.toml"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text('[watchdog]\ntoken = "token-1"\n', encoding="utf-8")
        old = {
            k: agent_main.os.environ.get(k)
            for k in (
                "SS14_WD_ROOT",
                "SS14_WD_DEDICATED_BASE",
                "AGENT_WATCHDOG_API_URL",
                "AGENT_WATCHDOG_DEFAULT_API_URL",
                "AGENT_WATCHDOG_LOCAL_API_URL",
            )
        }
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        for key in ("AGENT_WATCHDOG_API_URL", "AGENT_WATCHDOG_DEFAULT_API_URL", "AGENT_WATCHDOG_LOCAL_API_URL"):
            agent_main.os.environ.pop(key, None)
        try:
            base_url, source = runtime._resolve_watchdog_api_base_url("fallout")
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert base_url == "http://127.0.0.1:8000"
    assert source.startswith("default-local-watchdog:")
    assert source.endswith("config.toml")


def test_execute_instruction_force_stop_uses_watchdog_http_then_verifies_inactive():
    runtime = _runtime()
    with patch.object(
        runtime,
        "_execute_watchdog_http_action",
        return_value=(True, {"status_code": 200, "url": "http://127.0.0.1:8000/instances/fallout/stop"}, None),
    ) as stop_http_mock, patch.object(
        runtime,
        "_wait_for_instance_inactive",
        return_value=(True, {"active": False, "status": "offline"}),
    ) as inactive_mock:
        ok, result, error = runtime._execute_instruction(
            {
                "id": "inst-force-stop",
                "kind": "stop-instance",
                "payload": {"slug": "fallout", "schedule_mode": "force"},
            }
        )

    assert ok is True
    assert error is None
    assert result["status_code"] == 200
    assert result["mode"] == "force"
    stop_http_mock.assert_called_once()
    inactive_mock.assert_called_once_with(slug="fallout")


def test_execute_instruction_force_stop_falls_back_to_systemctl_when_watchdog_stop_keeps_server_active():
    runtime = _runtime()
    with patch.object(
        runtime,
        "_execute_watchdog_http_action",
        return_value=(True, {"status_code": 200, "url": "http://127.0.0.1:8000/instances/fallout/stop"}, None),
    ) as stop_http_mock, patch.object(
        runtime,
        "_wait_for_instance_inactive",
        return_value=(False, {"active": True, "players": 1}),
    ) as inactive_mock, patch.object(
        runtime,
        "_execute_watchdog_service_stop",
        return_value=(True, {"status_code": 200, "service": "SS14.Watchdog-fallout"}, None),
    ) as stop_mock:
        ok, result, error = runtime._execute_instruction(
            {
                "id": "inst-force-stop-fallback",
                "kind": "stop-instance",
                "payload": {"slug": "fallout", "schedule_mode": "force"},
            }
        )

    assert ok is True
    assert error is None
    assert result["fallback"] == "systemctl-stop"
    assert result["service"] == "SS14.Watchdog-fallout"
    assert result["watchdog_http_error"] == "watchdog stop returned success, but instance is still active"
    stop_http_mock.assert_called_once()
    inactive_mock.assert_called_once_with(slug="fallout")
    stop_mock.assert_called_once()


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


def test_gentle_wait_proceeds_immediately_when_players_are_zero():
    runtime = _runtime()

    with patch.object(
        runtime,
        "_embedded_instance_status_snapshot",
        return_value={
            "active": True,
            "status": "online",
            "players": 0,
            "max_players": 30,
        },
    ) as snapshot_mock:
        ok, result, error = runtime._wait_for_instance_empty_if_needed(
            instruction_id="inst-g1",
            kind="restart-instance",
            slug="srv-1",
            payload={"slug": "srv-1", "schedule_mode": "gentle"},
        )

    assert ok is True
    assert error is None
    assert result["mode"] == "gentle"
    assert result["players"] == 0
    snapshot_mock.assert_called_once_with("srv-1")


def test_execute_instruction_restart_includes_gentle_wait_metadata():
    runtime = _runtime()

    with patch.object(
        runtime,
        "_wait_for_instance_empty_if_needed",
        return_value=(True, {"mode": "gentle", "players": 0, "waited_seconds": 0.0}, None),
    ) as wait_mock:
        with patch.object(
            runtime,
            "_execute_watchdog_http_action",
            return_value=(True, {"status_code": 200, "url": "http://127.0.0.1:8000/instances/srv-1/restart"}, None),
        ) as restart_mock:
            ok, result, error = runtime._execute_instruction(
                {
                    "id": "inst-g2",
                    "kind": "restart-instance",
                    "payload": {"slug": "srv-1", "schedule_mode": "gentle"},
                }
            )

    assert ok is True
    assert error is None
    assert result["schedule_wait"]["mode"] == "gentle"
    wait_mock.assert_called_once()
    restart_mock.assert_called_once()


def test_execute_instruction_update_gentle_waits_for_players_before_watchdog_update():
    runtime = _runtime()

    with patch.object(
        runtime,
        "_wait_for_instance_empty_if_needed",
        return_value=(True, {"mode": "gentle", "players": 0, "waited_seconds": 0.0}, None),
    ) as wait_mock:
        with patch.object(
            runtime,
            "_execute_watchdog_http_action",
            return_value=(True, {"status_code": 200}, None),
        ) as update_mock:
            with patch.object(runtime, "_execute_watchdog_service_restart") as restart_mock:
                ok, result, error = runtime._execute_instruction(
                    {
                        "id": "inst-u1",
                        "kind": "update-instance",
                        "payload": {"slug": "srv-1", "schedule_mode": "gentle"},
                    }
                )

    assert ok is True
    assert error is None
    assert result["status_code"] == 200
    assert result["schedule_wait"]["mode"] == "gentle"
    wait_mock.assert_called_once()
    update_mock.assert_called_once()
    restart_mock.assert_not_called()


def test_execute_instruction_update_force_restarts_after_watchdog_update():
    runtime = _runtime()

    with patch.object(
        runtime,
        "_wait_for_instance_empty_if_needed",
        return_value=(True, None, None),
    ) as wait_mock, patch.object(
        runtime,
        "_execute_watchdog_http_action",
        side_effect=[
            (True, {"status_code": 200, "url": "http://127.0.0.1:8000/instances/srv-1/update"}, None),
            (True, {"status_code": 200, "url": "http://127.0.0.1:8000/instances/srv-1/restart"}, None),
        ],
    ) as update_mock, patch.object(agent_main.time, "sleep", return_value=None) as sleep_mock:
            ok, result, error = runtime._execute_instruction(
                {
                    "id": "inst-u2",
                    "kind": "update-instance",
                    "payload": {"slug": "srv-1", "schedule_mode": "force"},
                }
            )

    assert ok is True
    assert error is None
    assert result["forced_restart"]["status_code"] == 200
    assert result["forced_restart"]["url"].endswith("/instances/srv-1/restart")
    wait_mock.assert_called_once()
    assert update_mock.call_count == 2
    sleep_mock.assert_called_once()


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
                ok_mkdir, mkdir_result, mkdir_error = runtime._execute_instruction({
                    "id": "inst-mkdir",
                    "kind": "create-instance-data-directory",
                    "payload": {"slug": slug, "path": "maps", "name": "subdir"},
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
    assert ok_mkdir is True
    assert mkdir_error is None
    assert mkdir_result["path"] == "maps/subdir"
    assert ok_delete is True
    assert delete_error is None
    assert delete_result["deleted"] is True


def test_instance_database_backup_roundtrip_sqlite():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        slug = "srv-1"
        wd_root = root / "watchdog-srv-1"
        inst_dir = wd_root / "instances" / slug
        (inst_dir / "data").mkdir(parents=True, exist_ok=True)
        (inst_dir / "players.db").write_text("sqlite-one", encoding="utf-8")
        (inst_dir / "data" / "server.db").write_text("sqlite-two", encoding="utf-8")
        (inst_dir / "config.toml").write_text('[database]\nengine = "sqlite"\n', encoding="utf-8")
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            with patch.object(runtime, "_upload_download_transfer_chunks", return_value=(True, {"transfer_id": "db-tr-1", "size": 12}, None)):
                ok_download, download_result, download_error = runtime._execute_instruction({
                    "id": "db-download",
                    "kind": "download-instance-database-backup",
                    "payload": {"slug": slug},
                })
                backup_b64 = runtime._embedded_download_instance_database_backup(slug)[1]["content_base64"]
                (inst_dir / "players.db").unlink()
                (inst_dir / "data" / "server.db").unlink()
                ok_restore, restore_result, restore_error = runtime._execute_instruction({
                    "id": "db-restore",
                    "kind": "upload-instance-database-backup",
                    "payload": {"slug": slug, "filename": "backup.zip", "content_base64": backup_b64},
                })
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value

    assert ok_download is True
    assert download_error is None
    assert download_result["transfer_id"] == "db-tr-1"
    assert ok_restore is True
    assert restore_error is None
    assert restore_result["restored"] is True


def test_embedded_create_slug_renders_cdn_update_policy_from_payload():
    runtime = _runtime()
    fragment = runtime._embedded_render_update_policy_fragment(
        slug="srv-new",
        api_token="token-1",
        api_port=1212,
        repo="https://github.com/org/repo",
        branch="master",
        update_mode="cdn",
        manifest_url="https://cdn.example/srv-new/manifest",
    )

    assert 'UpdateType: "Manifest"' in fragment
    assert 'ManifestUrl: "https://cdn.example/srv-new/manifest"' in fragment
    assert 'BaseUrl: "https://github.com/org/repo"' not in fragment


def test_instance_whitelist_roundtrip_sqlite_and_config_toggle():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        slug = "srv-1"
        wd_root = root / "watchdog-srv-1"
        inst_dir = wd_root / "instances" / slug
        data_dir = inst_dir / "data"
        data_dir.mkdir(parents=True)
        (inst_dir / "config.toml").write_text('[game]\nhostname = "srv-1"\n[whitelist]\nenabled = false\n', encoding="utf-8")
        db_path = data_dir / "server.db"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("CREATE TABLE player (player_id INTEGER PRIMARY KEY, user_id TEXT UNIQUE, last_seen_user_name TEXT, last_seen_time TEXT)")
            conn.execute("CREATE TABLE whitelist (user_id TEXT PRIMARY KEY)")
            conn.execute(
                "INSERT INTO player (user_id, last_seen_user_name, last_seen_time) VALUES (?, ?, ?)",
                ("00000000-0000-0000-0000-000000000001", "Ren0san", "2026-05-14"),
            )
            conn.commit()
        finally:
            conn.close()
        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            ok, result, error = runtime._embedded_get_instance_whitelist(slug)
            assert ok is True, error
            assert result["enabled"] is False
            assert result["players"] == []

            ok, result, error = runtime._embedded_change_instance_whitelist_player(slug, "Ren0san", add=True)
            assert ok is True, error
            assert result["players"][0]["username"] == "Ren0san"

            ok, result, error = runtime._embedded_set_instance_whitelist_enabled(slug, True)
            assert ok is True, error
            assert result["enabled"] is True
            assert result["restart_required"] is True
            assert "enabled = true" in (inst_dir / "config.toml").read_text(encoding="utf-8")

            ok, result, error = runtime._embedded_change_instance_whitelist_player(slug, "ren0SAN", add=False)
            assert ok is True, error
            assert result["players"] == []
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value


def test_instance_whitelist_resolves_auth_user_and_scans_live_layout_alias():
    runtime = _runtime()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        wd_root = root / "watchdog-moonlight-shard"
        inst_dir = wd_root / "instances" / "moonlight-shard"
        data_dir = inst_dir / "data"
        data_dir.mkdir(parents=True)
        (inst_dir / "config.toml").write_text(
            '[game]\nhostname = "moonlight"\n[auth]\nserver = "https://auth.example/"\n[whitelist]\nenabled = true\n',
            encoding="utf-8",
        )
        db_path = data_dir / "preferences.db"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("CREATE TABLE player (player_id INTEGER PRIMARY KEY, user_id TEXT UNIQUE, last_seen_user_name TEXT, last_seen_time TEXT)")
            conn.execute("CREATE TABLE whitelist (user_id TEXT PRIMARY KEY)")
            conn.commit()
        finally:
            conn.close()

        class Response:
            status_code = 200
            ok = True

            @staticmethod
            def json():
                return {"userName": "Ren0san", "userId": "71718f43-ebd4-4460-b7f1-70f40112eaa9"}

        old = {k: agent_main.os.environ.get(k) for k in ("SS14_WD_ROOT", "SS14_WD_DEDICATED_BASE")}
        agent_main.os.environ["SS14_WD_ROOT"] = str(root / "watchdog")
        agent_main.os.environ["SS14_WD_DEDICATED_BASE"] = str(root)
        try:
            with patch("agent_main.requests.get", return_value=Response()) as req:
                ok, result, error = runtime._embedded_change_instance_whitelist_player("moonlight", "Ren0san", add=True)
            assert ok is True, error
            assert req.call_args_list[0].kwargs["params"] == {"name": "Ren0san"}
            assert req.call_args_list[0].kwargs["headers"] == {"User-Agent": "SpaceStation14/1.0"}
            assert req.call_args_list[1].kwargs["params"] == {"userid": "71718f43-ebd4-4460-b7f1-70f40112eaa9"}
            assert result["config_path"].replace("\\", "/").endswith("watchdog-moonlight-shard/instances/moonlight-shard/config.toml")
            assert result["changed_player"] == {
                "username": "Ren0san",
                "user_id": "71718F43-EBD4-4460-B7F1-70F40112EAA9",
                "action": "add",
            }
            assert result["players"] == [
                {
                    "user_id": "71718F43-EBD4-4460-B7F1-70F40112EAA9",
                    "username": "Ren0san",
                    "last_seen_time": "",
                }
            ]
        finally:
            for key, value in old.items():
                if value is None:
                    agent_main.os.environ.pop(key, None)
                else:
                    agent_main.os.environ[key] = value
