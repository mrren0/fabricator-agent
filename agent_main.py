"""Lightweight remote agent for fabricator.

The agent reads local config.toml, registers itself on the core backend and
long-polls for instructions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import base64
import mimetypes
import os
import pwd
import grp
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import threading
import time
import uuid
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
from requests import HTTPError

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - runtime compatibility for Python 3.10
    import tomli as tomllib


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


logger = logging.getLogger("fabricator-agent")


DEFAULT_LOCAL_EDGE_URL = "http://127.0.0.1:8000"


def _configure_agent_logger() -> None:
    level_raw = (_env("AGENT_LOG_LEVEL", "INFO") or "INFO").strip().upper()
    level = getattr(logging, level_raw, logging.INFO)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(handler)
    logger.propagate = False


_configure_agent_logger()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _default_local_api_url() -> str:
    return (_env("AGENT_LOCAL_API_URL", DEFAULT_LOCAL_EDGE_URL) or DEFAULT_LOCAL_EDGE_URL).rstrip("/")


def _local_api_token(runtime: "AgentRuntime") -> str:
    return (
        _env("AGENT_LOCAL_API_TOKEN")
        or _env("SS14_EDGE_API_TOKEN")
        or runtime.api_token
        or ""
    )


def _log_tail(value: Any, *, limit: int = 700) -> str:
    try:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True)
    except Exception:
        text = str(value)
    text = str(text).replace("\n", "\\n").replace("\r", "\\r")
    if len(text) > limit:
        return text[:limit] + "...(truncated)"
    return text


def _watchdog_restart_policy() -> str:
    policy = (_env("SS14_WD_RESTART_POLICY", "always") or "always").strip()
    return policy or "always"


def _watchdog_restart_sec() -> str:
    sec = (_env("SS14_WD_RESTART_SEC", "5") or "5").strip()
    return sec or "5"


def _watchdog_restart_prevent_exit_status() -> str:
    value = (_env("SS14_WD_RESTART_PREVENT_EXIT_STATUS", "SIGKILL") or "SIGKILL").strip()
    return value or "SIGKILL"


def _watchdog_oom_policy() -> str:
    policy = (_env("SS14_WD_OOM_POLICY", "continue") or "continue").strip().lower()
    return policy if policy in {"continue", "stop", "kill"} else "continue"


def _normalize_host(raw: str | None) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        parsed = urlparse(s if "://" in s else f"dummy://{s}")
        host = (parsed.hostname or "").strip()
        if host:
            return host
    except Exception:
        pass
    s = s.split("/")[0]
    s = s.split(":")[0]
    return s.strip()


def _is_ip_literal(value: str | None) -> bool:
    host = _normalize_host(value)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _build_server_url(public_host: str, slug: str, port: int) -> str:
    host = _normalize_host(public_host)
    if host and not _is_ip_literal(host):
        return f"ss14s://{host}/{slug}"
    if host:
        return f"ss14://{host}:{port}"
    return f"ss14://127.0.0.1:{port}"


def _normalize_ip(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return ""


def _is_public_ip(value: str | None) -> bool:
    ip = _normalize_ip(value)
    if not ip:
        return False
    addr = ipaddress.ip_address(ip)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _probe_public_ip_from_web() -> str:
    probe_url = _env("AGENT_PUBLIC_IP_URL", "https://api64.ipify.org")
    if not probe_url:
        return ""
    try:
        res = requests.get(probe_url, timeout=4)
        if res.status_code >= 400:
            return ""
        return _normalize_ip((res.text or "").strip())
    except Exception:
        return ""


def _detect_public_ip() -> str:
    override = _normalize_ip(_env("AGENT_PUBLIC_IP"))
    if override:
        return override

    local_egress = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 80))
            local_egress = _normalize_ip(sock.getsockname()[0])
        finally:
            sock.close()
    except Exception:
        local_egress = ""

    if _is_public_ip(local_egress):
        return local_egress

    external = _probe_public_ip_from_web()
    if _is_public_ip(external):
        return external

    return local_egress or external


def _private_ip_sort_key(ip: str) -> tuple[int, int, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return (9, 9, ip)
    family_rank = 0 if addr.version == 4 else 1
    private_rank = 0 if addr.is_private else 1
    return (private_rank, family_rank, ip)


def _detect_private_ip() -> str:
    override = _env("AGENT_PRIVATE_IP")
    if override:
        values = []
        for token in str(override).replace(",", " ").split():
            ip = _normalize_ip(token)
            if ip:
                values.append(ip)
        if values:
            return sorted(set(values), key=_private_ip_sort_key)[0]

    candidates: list[str] = []
    try:
        proc = subprocess.run(
            ["/bin/sh", "-lc", "hostname -I"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        for token in str(proc.stdout or "").replace(",", " ").split():
            ip = _normalize_ip(token)
            if ip:
                candidates.append(ip)
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 80))
            local_egress = _normalize_ip(sock.getsockname()[0])
        finally:
            sock.close()
        if local_egress:
            candidates.append(local_egress)
    except Exception:
        pass

    filtered: list[str] = []
    for ip in candidates:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            continue
        filtered.append(ip)
    if not filtered:
        return ""
    return sorted(set(filtered), key=_private_ip_sort_key)[0]


APP_VERSION = (_env("FABRICATOR_AGENT_VERSION", "0.1.0") or "0.1.0").strip() or "0.1.0"


def _file_sha12(path: Path) -> str:
    try:
        data = path.read_bytes()
        return hashlib.sha256(data).hexdigest()[:12]
    except Exception:
        return "unknown"


AGENT_BUILD = (_env("FABRICATOR_AGENT_BUILD") or "").strip() or _file_sha12(Path(__file__).resolve())
AGENT_VERSION_DISPLAY = (
    APP_VERSION
    if ("+" in APP_VERSION or APP_VERSION.endswith(AGENT_BUILD))
    else f"{APP_VERSION}+{AGENT_BUILD}"
)
try:
    AGENT_INSTALLED_AT = float(Path(__file__).resolve().stat().st_mtime)
except Exception:
    AGENT_INSTALLED_AT = 0.0


def _default_self_update_command() -> str:
    return "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade fabricator-agent"


def _self_update_service_name() -> str:
    # Safety: self-update must only restart the local fabricator-agent service.
    # Never restart game/watchdog services from this flow.
    return "fabricator-agent"


_ALLOWED_SELF_UPDATE_RESTART_UNITS = {"fabricator-agent", "fabricator-agent.service"}
_SELF_UPDATE_RESTART_PATTERN = re.compile(
    r"\bsystemctl\s+(?:--no-block\s+)?(?:restart|try-restart)\s+([^\n;&|]+)",
    re.IGNORECASE,
)


def _unsafe_self_update_restart_units(command: str) -> list[str]:
    unsafe: list[str] = []
    for match in _SELF_UPDATE_RESTART_PATTERN.finditer(str(command or "")):
        raw_units = str(match.group(1) or "").strip()
        if not raw_units:
            unsafe.append("<empty>")
            continue
        try:
            units = shlex.split(raw_units)
        except Exception:
            unsafe.append(raw_units)
            continue
        for unit in units:
            normalized = str(unit or "").strip().strip("'\"")
            if normalized and normalized not in _ALLOWED_SELF_UPDATE_RESTART_UNITS:
                unsafe.append(normalized)
    return unsafe


def _finalize_self_update_command(cmd: str, *, restart_enabled: bool) -> str:
    base = str(cmd or "").strip()
    if not base:
        return ""
    unsafe_units = _unsafe_self_update_restart_units(base)
    if unsafe_units:
        units = ", ".join(sorted(set(unsafe_units)))
        raise ValueError(f"self-update command contains unsafe restart target(s): {units}")
    if not restart_enabled:
        return base
    if _SELF_UPDATE_RESTART_PATTERN.search(base):
        return base
    service = shlex.quote(_self_update_service_name())
    return f"{base} && systemctl restart {service}"


def _pid_is_running(pid: int | None) -> bool:
    value = int(pid or 0)
    if value <= 0:
        return False
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False
    return True


def _resolve_self_update_paths() -> tuple[Path, Path]:
    base_dir = Path(_env("AGENT_SELF_UPDATE_STATE_DIR", "/var/lib/fabricator-agent") or "/var/lib/fabricator-agent")
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        base_dir = Path("/tmp/fabricator-agent")
        base_dir.mkdir(parents=True, exist_ok=True)
    log_path = Path(_env("AGENT_SELF_UPDATE_LOG_PATH", str(base_dir / "self-update.log")) or (base_dir / "self-update.log"))
    state_path = Path(_env("AGENT_SELF_UPDATE_STATUS_PATH", str(base_dir / "self-update-status.json")) or (base_dir / "self-update-status.json"))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return log_path, state_path


def _detached_popen(cmd: str, *, env: dict[str, str], log_path: Path | None = None) -> subprocess.Popen[Any]:
    stdout_target: Any = subprocess.DEVNULL
    stderr_target: Any = subprocess.DEVNULL
    log_file = None
    if log_path:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_file = open(log_path, "ab")
            header = (
                f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"self-update launch pid=? command={cmd}\n"
            )
            log_file.write(header.encode("utf-8", errors="ignore"))
            log_file.flush()
            stdout_target = log_file
            stderr_target = log_file
        except Exception:
            if log_file:
                try:
                    log_file.close()
                except Exception:
                    pass
            log_file = None
            stdout_target = subprocess.DEVNULL
            stderr_target = subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            ["/bin/sh", "-lc", cmd],
            stdout=stdout_target,
            stderr=stderr_target,
            stdin=subprocess.DEVNULL,
            env=env,
            text=False,
            start_new_session=True,
        )
    finally:
        if log_file:
            try:
                log_file.close()
            except Exception:
                pass
    return proc


def _run_git(*args: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", *args],
            cwd=Path(__file__).resolve().parent,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            text=True,
        )
    except Exception:
        return None
    value = out.strip()
    return value or None


@lru_cache(maxsize=1)
def _build_info() -> dict[str, Any]:
    return {
        "service": "fabricator-agent",
        "version": APP_VERSION,
        "version_base": APP_VERSION,
        "version_full": AGENT_VERSION_DISPLAY,
        "build": AGENT_BUILD,
        "installed_at": AGENT_INSTALLED_AT,
        "tag": _run_git("describe", "--tags", "--abbrev=0"),
        "commit": _run_git("rev-parse", "--short=12", "HEAD"),
        "dirty": bool(_run_git("status", "--porcelain")),
    }


class AgentRuntime:
    def __init__(self) -> None:
        self.test_mode = _env_bool("AGENT_TEST_MODE", False)
        self.backend_url = (_env("AGENT_BACKEND_URL", "https://api.thun-der.ru") or "").rstrip("/")
        self.api_token = _env("AGENT_API_TOKEN") or _env("SS14_API_TOKEN")
        self.agent_token = _env("AGENT_TOKEN")
        self.admin_token = _env("AGENT_ADMIN_TOKEN")
        self.agent_id_file = Path(_env("AGENT_ID_FILE", "/opt/fabricator-agent/agent.id") or "/opt/fabricator-agent/agent.id")
        self.agent_id = self._resolve_agent_id()
        self.hostname = socket.gethostname()
        self.public_ip = _detect_public_ip()
        self.private_ip = _detect_private_ip()
        self.location = _env("AGENT_LOCATION")
        self.config_path = Path(
            _env("AGENT_CONFIG_PATH", "/etc/fabricator-agent/config.toml") or "/etc/fabricator-agent/config.toml"
        )
        self.public_key = _env("AGENT_PUBLIC_KEY")
        self.bootstrap_token = _env("AGENT_BOOTSTRAP_TOKEN")
        self.agent_slug = _env("AGENT_SLUG")
        self.token_file = Path(_env("AGENT_TOKEN_FILE", "/opt/fabricator-agent/agent.token") or "/opt/fabricator-agent/agent.token")
        self.poll_seconds = int(_env("AGENT_POLL_SECONDS", "10") or "10")
        self.timeout = int(_env("AGENT_HTTP_TIMEOUT_SECONDS", "10") or "10")
        self.instruction_wait_seconds = max(0, int(_env("AGENT_INSTRUCTION_WAIT_SECONDS", "25") or "25"))
        self.instruction_limit = max(1, min(25, int(_env("AGENT_INSTRUCTION_LIMIT", "1") or "1")))
        self.heartbeat_seconds = max(5, int(_env("AGENT_HEARTBEAT_SECONDS", "30") or "30"))
        self.config_sync_seconds = max(
            5,
            int(_env("AGENT_CONFIG_SYNC_SECONDS", str(self.heartbeat_seconds)) or str(self.heartbeat_seconds)),
        )
        self.watchdog_log_sync_seconds = max(
            5,
            int(_env("AGENT_WATCHDOG_LOG_SYNC_SECONDS", "15") or "15"),
        )
        self.watchdog_log_lines = max(20, min(400, int(_env("AGENT_WATCHDOG_LOG_SYNC_LINES", "80") or "80")))
        self.watchdog_log_max_slugs = max(1, min(20, int(_env("AGENT_WATCHDOG_LOG_SYNC_MAX_SLUGS", "8") or "8")))
        self.runtime_post_retries = max(1, int(_env("AGENT_RUNTIME_POST_RETRIES", "3") or "3"))
        self.runtime_post_retry_delay = max(
            0.1,
            float(_env("AGENT_RUNTIME_POST_RETRY_DELAY_SECONDS", "0.5") or "0.5"),
        )
        self.diagnostic_timeout = int(_env("AGENT_DIAG_TIMEOUT_SECONDS", "45") or "45")
        self.output_tail_chars = int(_env("AGENT_OUTPUT_TAIL_CHARS", "4000") or "4000")
        self.fabricator_service_name = _env("AGENT_FABRICATOR_SERVICE", "ss14-provisioner") or "ss14-provisioner"
        self.local_api_url = _default_local_api_url()
        self._legacy_auth_disabled = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status: dict[str, Any] = {
            "registered": False,
            "last_error": None,
            "last_register_at": None,
            "last_heartbeat_at": None,
            "last_pull_at": None,
            "last_pull_started_at": None,
            "last_pull_completed_at": None,
            "last_pull_duration_ms": None,
            "last_pull_wait_seconds": float(self.instruction_wait_seconds),
            "last_pull_timeout_seconds": None,
            "last_pull_http_status": None,
            "last_pull_mode": None,
            "last_pull_instruction_ids": [],
            "last_instruction_count": 0,
            "last_instruction_id": None,
            "last_instruction_kind": None,
            "last_instruction_at": None,
            "last_instruction_ok": None,
            "last_instruction_error": None,
            "last_instruction_result": None,
            "last_pull_next_poll_seconds": None,
            "last_ack_at": None,
            "last_ack_instruction_id": None,
            "last_ack_instruction_kind": None,
            "last_ack_ok": None,
            "last_ack_http_status": None,
            "last_ack_duration_ms": None,
            "last_ack_error": None,
            "last_progress_at": None,
            "last_progress_instruction_id": None,
            "last_progress_execution_state": None,
            "last_progress_stage": None,
            "last_progress_http_status": None,
            "last_progress_duration_ms": None,
            "last_progress_error": None,
            "loop_cycle_seq": 0,
            "last_cycle_started_at": None,
            "last_cycle_completed_at": None,
            "last_cycle_duration_ms": None,
            "last_cycle_sleep_seconds": None,
            "instruction_limit": self.instruction_limit,
            "config_sha256": None,
            "last_config_snapshot_sync_at": None,
            "last_config_snapshot_count": 0,
            "last_config_snapshot_error": None,
            "last_watchdog_log_sync_at": None,
            "last_watchdog_log_sync_count": 0,
            "last_watchdog_log_sync_error": None,
            "claim_code": None,
            "paired": False,
            "legacy_auth_disabled": False,
            "last_diagnostic_name": None,
            "last_diagnostic_at": None,
            "last_diagnostic_ok": None,
            "mode": "test-local" if self.test_mode else "runtime",
        }
        self._next_heartbeat_at = 0.0
        self._next_config_sync_at = 0.0
        self._next_watchdog_log_sync_at = 0.0
        self._cycle_seq = 0
        self._config_snapshot_hashes: dict[str, str] = {}
        self._watchdog_log_hashes: dict[str, deque[str]] = {}
        self._load_token_file()
        self._embedded_reconcile_watchdog_services()
        logger.info(
            "Agent runtime initialized agent_id=%s backend_url=%s local_api_url=%s poll=%ss wait=%ss heartbeat=%ss",
            self.agent_id,
            self.backend_url,
            self.local_api_url,
            self.poll_seconds,
            self.instruction_wait_seconds,
            self.heartbeat_seconds,
        )
        local_host = _normalize_host(self.local_api_url)
        backend_host = _normalize_host(self.backend_url)
        if (
            local_host
            and backend_host
            and local_host == backend_host
            and local_host not in {"127.0.0.1", "localhost", "::1"}
        ):
            logger.warning(
                "AGENT_LOCAL_API_URL points to the same host as AGENT_BACKEND_URL (%s). "
                "This can cause remote instruction loops.",
                local_host,
            )

    @staticmethod
    def supported_instruction_kinds() -> list[str]:
        return [
            "ping",
            "set-poll-seconds",
            "refresh-config",
            "run-diagnostic",
            "get-watchdog-logs",
            "self-update-agent",
            "create-slug",
            "create-instance",
            "delete-instance",
            "restart-instance",
            "stop-instance",
            "update-instance",
            "repair-instance",
            "get-instance-update-policy",
            "set-instance-update-policy",
            "get-instance-config",
            "set-instance-config",
            "get-instance-database",
            "set-instance-database",
            "reset-instance-sqlite",
            "list-instance-data",
            "download-instance-data-file",
            "upload-instance-data-file",
        ]

    def _resolve_agent_id(self) -> str:
        env_id = _env("AGENT_ID")
        if env_id:
            return env_id
        try:
            existing = self.agent_id_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except Exception:
            pass
        generated = f"fbr-{uuid.uuid4().hex[:16]}"
        try:
            self.agent_id_file.parent.mkdir(parents=True, exist_ok=True)
            self.agent_id_file.write_text(generated, encoding="utf-8")
        except Exception:
            # Best effort. If file write fails, keep generated value in memory.
            pass
        return generated

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-API-Token": self.api_token or "",
        }

    def _runtime_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Agent-Token": self.agent_token or "",
        }

    def _load_token_file(self) -> None:
        if self.agent_token:
            return
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
            if token:
                self.agent_token = token
        except Exception:
            pass

    def _save_token_file(self) -> None:
        if not self.agent_token:
            return
        try:
            self.token_file.parent.mkdir(parents=True, exist_ok=True)
            self.token_file.write_text(self.agent_token, encoding="utf-8")
        except Exception:
            pass

    def _clear_token_file(self) -> None:
        try:
            if self.token_file.exists():
                self.token_file.unlink()
        except Exception:
            pass

    def _invalidate_runtime_token(self, reason: str) -> None:
        # Token can become stale after a rebind/reissue on the backend.
        self.agent_token = None
        self.status["paired"] = False
        self.status["claim_code"] = None
        self._clear_token_file()
        self.status["last_error"] = reason
        self._next_config_sync_at = 0.0
        self._next_watchdog_log_sync_at = 0.0
        self._config_snapshot_hashes.clear()
        self._watchdog_log_hashes.clear()

    def _read_config(self) -> tuple[dict[str, Any] | None, str | None]:
        if not self.config_path.exists():
            return None, None
        raw = self.config_path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        parsed = tomllib.loads(raw.decode("utf-8", errors="ignore"))
        return parsed, sha

    def _config_sync_due(self) -> bool:
        return time.time() >= float(self._next_config_sync_at or 0.0)

    def _watchdog_log_sync_due(self) -> bool:
        return time.time() >= float(self._next_watchdog_log_sync_at or 0.0)

    def _list_embedded_instance_config_paths(self) -> dict[str, Path]:
        template_root = Path(_env("SS14_WD_ROOT", "/opt/ss14/wds/watchdog") or "/opt/ss14/wds/watchdog")
        dedicated_base = Path(
            _env(
                "SS14_WD_DEDICATED_BASE",
                str(template_root.parent.parent if template_root.parent.name == "wds" else template_root.parent),
            )
            or str(template_root.parent.parent if template_root.parent.name == "wds" else template_root.parent)
        )
        items: dict[str, Path] = {}
        legacy_root = template_root / "instances"
        try:
            for cfg_path in legacy_root.glob("*/config.toml"):
                if not cfg_path.is_file():
                    continue
                slug = str(cfg_path.parent.name or "").strip().lower()
                if slug:
                    items.setdefault(slug, cfg_path)
        except Exception:
            logger.exception("Legacy config snapshot scan failed root=%s", legacy_root)
        dedicated_prefix = f"{template_root.name}-"
        try:
            for wd_root in dedicated_base.glob(f"{dedicated_prefix}*"):
                if not wd_root.is_dir():
                    continue
                slug = str(wd_root.name[len(dedicated_prefix):] or "").strip().lower()
                if not slug:
                    continue
                cfg_path = wd_root / "instances" / slug / "config.toml"
                if cfg_path.is_file():
                    items[slug] = cfg_path
        except Exception:
            logger.exception("Dedicated config snapshot scan failed base=%s", dedicated_base)
        return items

    def _sync_config_snapshots(self, *, force: bool = False) -> None:
        self._next_config_sync_at = time.time() + float(self.config_sync_seconds)
        if not self.agent_token:
            return
        cfg_paths = self._list_embedded_instance_config_paths()
        current_slugs = set(cfg_paths.keys())
        for slug in list(self._config_snapshot_hashes):
            if slug not in current_slugs:
                self._config_snapshot_hashes.pop(slug, None)
        items: list[dict[str, Any]] = []
        next_hashes: dict[str, str] = {}
        for slug, cfg_path in cfg_paths.items():
            try:
                content = cfg_path.read_text(encoding="utf-8", errors="ignore")
                content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
                next_hashes[slug] = content_sha256
                if not force and self._config_snapshot_hashes.get(slug) == content_sha256:
                    continue
                source_updated_at: float | None
                try:
                    source_updated_at = float(cfg_path.stat().st_mtime)
                except Exception:
                    source_updated_at = None
                items.append(
                    {
                        "slug": slug,
                        "config_path": str(cfg_path),
                        "content": content,
                        "content_sha256": content_sha256,
                        "source_updated_at": source_updated_at,
                    }
                )
            except Exception:
                logger.exception("Config snapshot read failed slug=%s path=%s", slug, cfg_path)
        if not items:
            self._config_snapshot_hashes.update(next_hashes)
            self.status["last_config_snapshot_sync_at"] = time.time()
            self.status["last_config_snapshot_count"] = 0
            self.status["last_config_snapshot_error"] = None
            return
        res = self._post_with_retries(
            f"{self.backend_url}/api/agent/runtime/{self.agent_id}/config-snapshots",
            json={"items": items},
            headers=self._runtime_headers(),
        )
        if res.status_code == 401:
            self._invalidate_runtime_token("Runtime token rejected while syncing config snapshots; re-enrolling")
            return
        res.raise_for_status()
        self._config_snapshot_hashes.update(next_hashes)
        self.status["last_config_snapshot_sync_at"] = time.time()
        self.status["last_config_snapshot_count"] = len(items)
        self.status["last_config_snapshot_error"] = None

    def _collect_watchdog_log_batch_for_slug(self, slug: str, cfg_path: Path) -> dict[str, Any] | None:
        meta = self._read_embedded_instance_meta(slug, cfg_path)
        payload_hints: dict[str, Any] = {
            "slug": slug,
            "lines": int(self.watchdog_log_lines),
            "since_seconds": int(max(self.watchdog_log_sync_seconds * 3, 30)),
        }
        port = int(meta.get("port") or 0)
        if port > 0:
            payload_hints["watchdog_service_mode"] = "per-slug"
        ok, result, error = self._get_watchdog_logs(payload_hints)
        if not ok:
            if str(error or "").strip():
                self.status["last_watchdog_log_sync_error"] = str(error)
            return None
        items = result.get("items") if isinstance(result.get("items"), list) else []
        if not items:
            return None
        cache = self._watchdog_log_hashes.setdefault(slug, deque(maxlen=800))
        seen = set(cache)
        fresh: list[dict[str, Any]] = []
        now_ts = time.time()
        for raw_item in items:
            raw_line = str((raw_item or {}).get("raw") or "").rstrip()
            if not raw_line:
                continue
            line_hash = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
            if line_hash in seen:
                continue
            cache.append(line_hash)
            seen.add(line_hash)
            fresh.append(
                {
                    "raw": raw_line,
                    "line_hash": line_hash,
                    "line_ts": None,
                    "collected_at": now_ts,
                }
            )
        if not fresh:
            return None
        return {
            "slug": slug,
            "service_name": str(result.get("service") or "").strip() or None,
            "items": fresh,
        }

    def _sync_watchdog_logs(self) -> None:
        self._next_watchdog_log_sync_at = time.time() + float(self.watchdog_log_sync_seconds)
        if not self.agent_token:
            return
        cfg_paths = self._list_embedded_instance_config_paths()
        current_slugs = set(cfg_paths.keys())
        for slug in list(self._watchdog_log_hashes):
            if slug not in current_slugs:
                self._watchdog_log_hashes.pop(slug, None)
        batches: list[dict[str, Any]] = []
        for slug in sorted(current_slugs)[: int(self.watchdog_log_max_slugs)]:
            try:
                batch = self._collect_watchdog_log_batch_for_slug(slug, cfg_paths[slug])
            except Exception as exc:
                self.status["last_watchdog_log_sync_error"] = str(exc)
                logger.exception("Watchdog log sync collection failed slug=%s", slug)
                continue
            if batch:
                batches.append(batch)
        if not batches:
            self.status["last_watchdog_log_sync_at"] = time.time()
            self.status["last_watchdog_log_sync_count"] = 0
            if self.status.get("last_watchdog_log_sync_error") is None:
                self.status["last_watchdog_log_sync_error"] = None
            return
        res = self._post_with_retries(
            f"{self.backend_url}/api/agent/runtime/{self.agent_id}/watchdog-logs",
            json={"items": batches},
            headers=self._runtime_headers(),
        )
        if res.status_code == 401:
            self._invalidate_runtime_token("Runtime token rejected while syncing watchdog logs; re-enrolling")
            return
        res.raise_for_status()
        self.status["last_watchdog_log_sync_at"] = time.time()
        self.status["last_watchdog_log_sync_count"] = sum(len(item.get("items") or []) for item in batches)
        self.status["last_watchdog_log_sync_error"] = None

    @staticmethod
    def _first_not_none(*values: Any) -> Any:
        for value in values:
            if value is not None:
                return value
        return None

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            parsed = int(value)
        except Exception:
            return None
        return parsed

    @staticmethod
    def _compact_status_body(*, status: str, name: str | None, players: int | None, max_players: int | None) -> str:
        payload: dict[str, Any] = {"status": str(status or "unknown").strip().lower() or "unknown"}
        if name:
            payload["name"] = str(name)
        if players is not None:
            payload["players"] = int(players)
        if max_players is not None:
            payload["max_players"] = int(max_players)
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))

    def _read_embedded_instance_meta(self, slug: str, cfg_path: Path) -> dict[str, Any]:
        meta: dict[str, Any] = {"slug": slug, "port": 0, "name": None, "max_players": None}
        try:
            parsed = tomllib.loads(cfg_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return meta
        if not isinstance(parsed, dict):
            return meta
        status_cfg = parsed.get("status") if isinstance(parsed.get("status"), dict) else {}
        server_cfg = parsed.get("server") if isinstance(parsed.get("server"), dict) else {}
        net_cfg = parsed.get("net") if isinstance(parsed.get("net"), dict) else {}

        name_raw = self._first_not_none(
            server_cfg.get("name"),
            status_cfg.get("name"),
            status_cfg.get("server_name"),
        )
        name = str(name_raw or "").strip() or None
        port = self._safe_int(self._first_not_none(net_cfg.get("port"), status_cfg.get("port"))) or 0
        max_players = self._safe_int(
            self._first_not_none(
                status_cfg.get("max_players"),
                status_cfg.get("maxplayers"),
                server_cfg.get("max_players"),
            )
        )
        meta["port"] = max(0, int(port))
        meta["name"] = name
        meta["max_players"] = max_players if (max_players is None or max_players >= 0) else None
        return meta

    def _probe_embedded_instance_status(
        self,
        *,
        slug: str,
        port: int,
        configured_name: str | None,
        configured_max_players: int | None,
    ) -> dict[str, Any]:
        base_url = f"http://127.0.0.1:{int(port)}"
        if int(port or 0) <= 0:
            compact_body = self._compact_status_body(
                status="offline",
                name=configured_name,
                players=0,
                max_players=configured_max_players,
            )
            return {
                "active": False,
                "status_code": 0,
                "body": compact_body,
                "url": "",
                "error": "invalid instance port",
                "status": "offline",
                "name": configured_name,
                "players": 0,
                "max_players": configured_max_players,
            }

        timeout = max(0.4, min(float(self.timeout or 2.0), 2.0))
        last_error = ""
        for path in ("/status", "/info"):
            url = f"{base_url}{path}"
            try:
                res = requests.get(url, timeout=timeout)
                code = int(res.status_code or 0)
                text = str(res.text or "")
            except Exception as exc:
                last_error = str(exc)
                continue

            payload: dict[str, Any] = {}
            if text.strip():
                try:
                    parsed = res.json() if hasattr(res, "json") else json.loads(text)
                    if isinstance(parsed, dict):
                        payload = parsed
                except Exception:
                    payload = {}
            status_payload = payload.get("status") if isinstance(payload.get("status"), dict) else {}
            game_payload = payload.get("game") if isinstance(payload.get("game"), dict) else {}
            status_game_payload = status_payload.get("game") if isinstance(status_payload.get("game"), dict) else {}
            players = self._safe_int(
                self._first_not_none(
                    payload.get("players"),
                    payload.get("player_count"),
                    payload.get("current_players"),
                    game_payload.get("players"),
                    game_payload.get("player_count"),
                    game_payload.get("current_players"),
                    status_payload.get("players"),
                    status_game_payload.get("players"),
                    status_game_payload.get("player_count"),
                    status_game_payload.get("current_players"),
                )
            )
            max_players = self._safe_int(
                self._first_not_none(
                    payload.get("max_players"),
                    payload.get("maxPlayers"),
                    game_payload.get("max_players"),
                    game_payload.get("maxplayers"),
                    status_payload.get("max_players"),
                    status_game_payload.get("max_players"),
                    status_game_payload.get("maxplayers"),
                    configured_max_players,
                )
            )
            name = str(
                self._first_not_none(
                    payload.get("name"),
                    payload.get("server_name"),
                    payload.get("hostname"),
                    game_payload.get("hostname"),
                    game_payload.get("name"),
                    game_payload.get("server_name"),
                    status_payload.get("name"),
                    status_payload.get("server_name"),
                    status_payload.get("hostname"),
                    status_game_payload.get("hostname"),
                    status_game_payload.get("name"),
                    status_game_payload.get("server_name"),
                    configured_name,
                    slug,
                )
                or ""
            ).strip() or None

            if code == 200:
                compact_body = self._compact_status_body(
                    status="online",
                    name=name,
                    players=(players if players is not None else 0),
                    max_players=max_players,
                )
                return {
                    "active": True,
                    "status_code": 200,
                    "body": compact_body,
                    "url": url,
                    "error": None,
                    "status": "online",
                    "name": name,
                    "players": (players if players is not None else 0),
                    "max_players": max_players,
                }
            if code == 404 and not text.strip():
                continue
            compact_body = self._compact_status_body(
                status="offline",
                name=name,
                players=0,
                max_players=max_players,
            )
            return {
                "active": False,
                "status_code": code,
                "body": compact_body,
                "url": url,
                "error": f"status probe returned {code}",
                "status": "offline",
                "name": name,
                "players": 0,
                "max_players": max_players,
            }

        compact_body = self._compact_status_body(
            status="offline",
            name=(configured_name or slug),
            players=0,
            max_players=configured_max_players,
        )
        return {
            "active": False,
            "status_code": 0,
            "body": compact_body,
            "url": f"{base_url}/status",
            "error": (last_error or "status probe failed"),
            "status": "offline",
            "name": (configured_name or slug),
            "players": 0,
            "max_players": configured_max_players,
        }

    def _heartbeat_remote_instances_payload(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        now_ts = time.time()
        for slug, cfg_path in self._list_embedded_instance_config_paths().items():
            meta = self._read_embedded_instance_meta(slug, cfg_path)
            status_payload = self._probe_embedded_instance_status(
                slug=slug,
                port=int(meta.get("port") or 0),
                configured_name=str(meta.get("name") or "").strip() or None,
                configured_max_players=self._safe_int(meta.get("max_players")),
            )
            items.append(
                {
                    "slug": slug,
                    "active": bool(status_payload.get("active")),
                    "status_code": int(status_payload.get("status_code") or 0),
                    "body": str(status_payload.get("body") or ""),
                    "url": str(status_payload.get("url") or ""),
                    "error": str(status_payload.get("error") or "").strip() or None,
                    "status": str(status_payload.get("status") or "").strip().lower() or "offline",
                    "name": str(status_payload.get("name") or "").strip() or slug,
                    "players": int(status_payload.get("players") or 0),
                    "max_players": self._safe_int(status_payload.get("max_players")),
                    "watchdog": {
                        "config_path": str(cfg_path),
                        "port": int(meta.get("port") or 0),
                    },
                    "observed_at": now_ts,
                }
            )
        return items

    def _register(self, cfg: dict[str, Any] | None, cfg_sha: str | None) -> None:
        if not self.api_token or self._legacy_auth_disabled:
            return
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "public_ip": self.public_ip or None,
            "location": self.location,
            "config_path": str(self.config_path),
            "config_sha256": cfg_sha,
            "config": cfg,
            "capabilities": ["config.toml", "heartbeat", "instruction-pull"],
            "tags": [],
            "details": {
                "public_ip": self.public_ip or None,
                "private_ip": self.private_ip or None,
                "hostname": self.hostname,
            },
        }
        res = requests.post(
            f"{self.backend_url}/api/agent/register",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if res.status_code == 401:
            self._legacy_auth_disabled = True
            self.status["legacy_auth_disabled"] = True
            return
        res.raise_for_status()
        self.status["registered"] = True
        self.status["last_register_at"] = time.time()
        self.status["config_sha256"] = cfg_sha

    def _heartbeat_due(self) -> bool:
        return time.time() >= float(self._next_heartbeat_at or 0.0)

    def _heartbeat(self, cfg_sha: str | None) -> None:
        now = time.time()
        self._next_heartbeat_at = now + float(self.heartbeat_seconds)
        if self.agent_token:
            logger.info(
                "Sending runtime heartbeat agent_id=%s backend_url=%s next_due_in=%ss",
                self.agent_id,
                self.backend_url,
                self.heartbeat_seconds,
            )
            payload = {
                "status": "ok",
                "config_sha256": cfg_sha,
                "metrics": {},
                "details": {
                    "public_ip": self.public_ip or None,
                    "private_ip": self.private_ip or None,
                    "agent_version": APP_VERSION,
                    "agent_version_full": AGENT_VERSION_DISPLAY,
                    "agent_version_base": APP_VERSION,
                    "agent_build": AGENT_BUILD,
                    "agent_installed_at": AGENT_INSTALLED_AT,
                },
                "remote_instances": self._heartbeat_remote_instances_payload(),
            }
            res = requests.post(
                f"{self.backend_url}/api/agent/runtime/{self.agent_id}/heartbeat",
                json=payload,
                headers=self._runtime_headers(),
                timeout=self.timeout,
            )
            if res.status_code == 401:
                self._invalidate_runtime_token("Runtime token rejected by backend; re-enrolling")
                return
            res.raise_for_status()
            self.status["registered"] = True
            self.status["last_heartbeat_at"] = time.time()
            self.status["paired"] = True
            logger.info("Runtime heartbeat accepted agent_id=%s", self.agent_id)
            return

        # Legacy mode: heartbeat is available only with AGENT_API_TOKEN/SS14_API_TOKEN.
        if not self.api_token or self._legacy_auth_disabled:
            return

        logger.info(
            "Sending legacy heartbeat agent_id=%s backend_url=%s next_due_in=%ss",
            self.agent_id,
            self.backend_url,
            self.heartbeat_seconds,
        )
        payload = {
            "agent_id": self.agent_id,
            "status": "ok",
            "config_sha256": cfg_sha,
            "metrics": {},
            "details": {
                "public_ip": self.public_ip or None,
                "private_ip": self.private_ip or None,
                "agent_version": APP_VERSION,
                "agent_version_full": AGENT_VERSION_DISPLAY,
                "agent_version_base": APP_VERSION,
                "agent_build": AGENT_BUILD,
                "agent_installed_at": AGENT_INSTALLED_AT,
            },
        }
        res = requests.post(
            f"{self.backend_url}/api/agent/heartbeat",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if res.status_code == 401:
            # Legacy token is optional. Disable this branch and continue runtime pairing.
            self._legacy_auth_disabled = True
            self.status["legacy_auth_disabled"] = True
            return
        res.raise_for_status()
        self.status["last_heartbeat_at"] = time.time()
        logger.info("Legacy heartbeat accepted agent_id=%s", self.agent_id)

    def _pull(self) -> tuple[list[dict[str, Any]], float]:
        request_timeout = max(self.timeout, self.instruction_wait_seconds + 15)
        wait_seconds = max(0, int(self.instruction_wait_seconds))
        pull_started_at = time.time()
        pull_started_monotonic = time.monotonic()
        pull_mode = "runtime" if self.agent_token else "legacy"
        self.status["last_pull_started_at"] = pull_started_at
        self.status["last_pull_mode"] = pull_mode
        self.status["last_pull_wait_seconds"] = float(wait_seconds)
        self.status["last_pull_timeout_seconds"] = float(request_timeout)
        logger.info(
            "Instruction pull start mode=%s wait_seconds=%s limit=%s timeout_seconds=%s",
            pull_mode,
            wait_seconds,
            int(self.instruction_limit),
            request_timeout,
        )
        if self.agent_token:
            logger.info(
                "Polling master for instructions agent_id=%s limit=%s wait_seconds=%s",
                self.agent_id,
                self.instruction_limit,
                wait_seconds,
            )
            try:
                res = requests.get(
                    f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions",
                    params={"limit": int(self.instruction_limit), "wait_seconds": wait_seconds},
                    headers=self._runtime_headers(),
                    timeout=request_timeout,
                )
            except requests.ReadTimeout:
                elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
                self.status["last_pull_http_status"] = None
                self.status["last_pull_completed_at"] = time.time()
                self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
                self.status["last_pull_instruction_ids"] = []
                logger.warning(
                    "Instruction pull timed out mode=%s wait_seconds=%s timeout_seconds=%s elapsed_ms=%.1f",
                    pull_mode,
                    wait_seconds,
                    request_timeout,
                    elapsed_ms,
                )
                return [], float(self.poll_seconds)
            self.status["last_pull_http_status"] = int(res.status_code)
            if res.status_code == 401:
                self._invalidate_runtime_token("Runtime token rejected while pulling; re-enrolling")
                elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
                self.status["last_pull_completed_at"] = time.time()
                self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
                self.status["last_pull_instruction_ids"] = []
                logger.warning(
                    "Instruction pull unauthorized mode=%s status_code=%s elapsed_ms=%.1f",
                    pull_mode,
                    res.status_code,
                    elapsed_ms,
                )
                return [], float(self.poll_seconds)
            res.raise_for_status()
            data = res.json() if res.content else {}
            self.status["last_pull_at"] = time.time()
            items = data.get("instructions") or []
            instruction_ids = [str((item or {}).get("id") or "").strip() for item in items]
            instruction_ids = [iid for iid in instruction_ids if iid]
            self.status["last_instruction_count"] = len(items)
            next_poll_seconds = float(data.get("next_poll_seconds") or 0)
            self.status["last_pull_next_poll_seconds"] = next_poll_seconds
            elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
            self.status["last_pull_completed_at"] = time.time()
            self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_pull_instruction_ids"] = instruction_ids
            logger.info(
                "Instruction pull done mode=%s status_code=%s elapsed_ms=%.1f instruction_count=%s next_poll_seconds=%s instruction_ids=%s",
                pull_mode,
                res.status_code,
                elapsed_ms,
                len(items),
                next_poll_seconds,
                ",".join(instruction_ids) if instruction_ids else "-",
            )
            return items, next_poll_seconds

        # Legacy mode: pull is available only with AGENT_API_TOKEN/SS14_API_TOKEN.
        if not self.api_token or self._legacy_auth_disabled:
            elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
            self.status["last_pull_completed_at"] = time.time()
            self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_pull_http_status"] = None
            self.status["last_pull_instruction_ids"] = []
            logger.info(
                "Instruction pull skipped mode=legacy reason=%s elapsed_ms=%.1f",
                "legacy_auth_unavailable",
                elapsed_ms,
            )
            return [], float(self.poll_seconds)

        logger.info(
            "Polling master for instructions via legacy auth agent_id=%s limit=%s wait_seconds=%s",
            self.agent_id,
            self.instruction_limit,
            wait_seconds,
        )
        try:
            res = requests.get(
                f"{self.backend_url}/api/agent/instructions/{self.agent_id}",
                params={"limit": int(self.instruction_limit), "wait_seconds": wait_seconds},
                headers=self._headers(),
                timeout=request_timeout,
            )
        except requests.ReadTimeout:
            elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
            self.status["last_pull_http_status"] = None
            self.status["last_pull_completed_at"] = time.time()
            self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_pull_instruction_ids"] = []
            logger.warning(
                "Instruction pull timed out mode=%s wait_seconds=%s timeout_seconds=%s elapsed_ms=%.1f",
                pull_mode,
                wait_seconds,
                request_timeout,
                elapsed_ms,
            )
            return [], float(self.poll_seconds)
        self.status["last_pull_http_status"] = int(res.status_code)
        if res.status_code == 401:
            self._legacy_auth_disabled = True
            self.status["legacy_auth_disabled"] = True
            elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
            self.status["last_pull_completed_at"] = time.time()
            self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_pull_instruction_ids"] = []
            logger.warning(
                "Instruction pull unauthorized mode=%s status_code=%s elapsed_ms=%.1f",
                pull_mode,
                res.status_code,
                elapsed_ms,
            )
            return [], float(self.poll_seconds)
        res.raise_for_status()
        data = res.json() if res.content else {}
        self.status["last_pull_at"] = time.time()
        items = data.get("instructions") or []
        instruction_ids = [str((item or {}).get("id") or "").strip() for item in items]
        instruction_ids = [iid for iid in instruction_ids if iid]
        self.status["last_instruction_count"] = len(items)
        next_poll_seconds = float(data.get("next_poll_seconds") or 0)
        self.status["last_pull_next_poll_seconds"] = next_poll_seconds
        elapsed_ms = (time.monotonic() - pull_started_monotonic) * 1000.0
        self.status["last_pull_completed_at"] = time.time()
        self.status["last_pull_duration_ms"] = round(elapsed_ms, 3)
        self.status["last_pull_instruction_ids"] = instruction_ids
        logger.info(
            "Instruction pull done mode=%s status_code=%s elapsed_ms=%.1f instruction_count=%s next_poll_seconds=%s instruction_ids=%s",
            pull_mode,
            res.status_code,
            elapsed_ms,
            len(items),
            next_poll_seconds,
            ",".join(instruction_ids) if instruction_ids else "-",
        )
        return items, next_poll_seconds

    def _ack(
        self,
        instruction_id: str,
        ok: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        *,
        instruction_kind: str | None = None,
    ) -> None:
        payload = {"ok": bool(ok), "result": result or {}, "error": error}
        mode = "runtime" if self.agent_token else "legacy"
        started_monotonic = time.monotonic()
        self.status["last_ack_instruction_id"] = instruction_id or None
        self.status["last_ack_instruction_kind"] = str(instruction_kind or "").strip().lower() or None
        self.status["last_ack_ok"] = bool(ok)
        self.status["last_ack_error"] = str(error or "").strip() or None
        logger.info(
            "Instruction ack send id=%s kind=%s mode=%s ok=%s",
            instruction_id or "-",
            self.status["last_ack_instruction_kind"] or "-",
            mode,
            bool(ok),
        )
        if self.agent_token:
            try:
                res = self._post_with_retries(
                    f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions/{instruction_id}/ack",
                    json=payload,
                    headers=self._runtime_headers(),
                )
            except Exception as exc:
                elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
                self.status["last_ack_http_status"] = None
                self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
                self.status["last_ack_at"] = time.time()
                self.status["last_ack_error"] = str(exc)
                logger.exception(
                    "Instruction ack transport failed id=%s kind=%s mode=%s elapsed_ms=%.1f",
                    instruction_id or "-",
                    self.status["last_ack_instruction_kind"] or "-",
                    mode,
                    elapsed_ms,
                )
                raise
            self.status["last_ack_http_status"] = int(res.status_code)
            if res.status_code == 401:
                self._invalidate_runtime_token("Runtime token rejected while ack; re-enrolling")
                elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
                self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
                self.status["last_ack_at"] = time.time()
                self.status["last_ack_error"] = "401 unauthorized"
                logger.warning(
                    "Instruction ack unauthorized id=%s kind=%s mode=%s status_code=%s elapsed_ms=%.1f",
                    instruction_id or "-",
                    self.status["last_ack_instruction_kind"] or "-",
                    mode,
                    res.status_code,
                    elapsed_ms,
                )
                return
            try:
                res.raise_for_status()
            except Exception:
                elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
                self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
                self.status["last_ack_at"] = time.time()
                self.status["last_ack_error"] = f"http {res.status_code}"
                logger.exception(
                    "Instruction ack rejected id=%s kind=%s mode=%s status_code=%s elapsed_ms=%.1f",
                    instruction_id or "-",
                    self.status["last_ack_instruction_kind"] or "-",
                    mode,
                    res.status_code,
                    elapsed_ms,
                )
                raise
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_ack_at"] = time.time()
            self.status["last_ack_error"] = None
            logger.info(
                "Instruction ack confirmed id=%s kind=%s mode=%s status_code=%s elapsed_ms=%.1f",
                instruction_id or "-",
                self.status["last_ack_instruction_kind"] or "-",
                mode,
                res.status_code,
                elapsed_ms,
            )
            return
        if self._legacy_auth_disabled:
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_ack_http_status"] = None
            self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_ack_at"] = time.time()
            self.status["last_ack_error"] = "legacy auth disabled"
            logger.warning(
                "Instruction ack skipped id=%s kind=%s mode=%s reason=%s elapsed_ms=%.1f",
                instruction_id or "-",
                self.status["last_ack_instruction_kind"] or "-",
                mode,
                "legacy_auth_disabled",
                elapsed_ms,
            )
            return
        try:
            res = self._post_with_retries(
                f"{self.backend_url}/api/agent/instructions/{self.agent_id}/{instruction_id}/ack",
                json=payload,
                headers=self._headers(),
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_ack_http_status"] = None
            self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_ack_at"] = time.time()
            self.status["last_ack_error"] = str(exc)
            logger.exception(
                "Instruction ack transport failed id=%s kind=%s mode=%s elapsed_ms=%.1f",
                instruction_id or "-",
                self.status["last_ack_instruction_kind"] or "-",
                mode,
                elapsed_ms,
            )
            raise
        self.status["last_ack_http_status"] = int(res.status_code)
        if res.status_code == 401:
            self._legacy_auth_disabled = True
            self.status["legacy_auth_disabled"] = True
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_ack_at"] = time.time()
            self.status["last_ack_error"] = "401 unauthorized"
            logger.warning(
                "Instruction ack unauthorized id=%s kind=%s mode=%s status_code=%s elapsed_ms=%.1f",
                instruction_id or "-",
                self.status["last_ack_instruction_kind"] or "-",
                mode,
                res.status_code,
                elapsed_ms,
            )
            return
        try:
            res.raise_for_status()
        except Exception:
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_ack_at"] = time.time()
            self.status["last_ack_error"] = f"http {res.status_code}"
            logger.exception(
                "Instruction ack rejected id=%s kind=%s mode=%s status_code=%s elapsed_ms=%.1f",
                instruction_id or "-",
                self.status["last_ack_instruction_kind"] or "-",
                mode,
                res.status_code,
                elapsed_ms,
            )
            raise
        elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
        self.status["last_ack_duration_ms"] = round(elapsed_ms, 3)
        self.status["last_ack_at"] = time.time()
        self.status["last_ack_error"] = None
        logger.info(
            "Instruction ack confirmed id=%s kind=%s mode=%s status_code=%s elapsed_ms=%.1f",
            instruction_id or "-",
            self.status["last_ack_instruction_kind"] or "-",
            mode,
            res.status_code,
            elapsed_ms,
        )

    def _post_with_retries(self, url: str, *, json: dict[str, Any], headers: dict[str, str]) -> requests.Response:
        last_exc: requests.RequestException | None = None
        for attempt in range(self.runtime_post_retries):
            try:
                res = requests.post(
                    url,
                    json=json,
                    headers=headers,
                    timeout=self.timeout,
                )
                if attempt > 0:
                    logger.info(
                        "HTTP POST recovered after retry url=%s attempt=%s/%s status_code=%s",
                        url,
                        attempt + 1,
                        self.runtime_post_retries,
                        res.status_code,
                    )
                return res
            except requests.RequestException as exc:
                last_exc = exc
                if attempt + 1 < self.runtime_post_retries:
                    delay = self.runtime_post_retry_delay * float(attempt + 1)
                    logger.warning(
                        "HTTP POST failed url=%s attempt=%s/%s retry_in=%.2fs error=%s",
                        url,
                        attempt + 1,
                        self.runtime_post_retries,
                        delay,
                        str(exc),
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        "HTTP POST failed url=%s attempt=%s/%s giving_up error=%s",
                        url,
                        attempt + 1,
                        self.runtime_post_retries,
                        str(exc),
                    )
        if last_exc:
            raise last_exc
        raise RuntimeError("runtime post failed with unknown error")

    def _progress(
        self,
        instruction_id: str,
        *,
        execution_state: str,
        stage: str | None = None,
        message: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        if not self.agent_token:
            return
        payload = {
            "execution_state": str(execution_state or "").strip().lower(),
            "stage": str(stage or "").strip().lower() or None,
            "message": str(message or "").strip() or None,
            "result": result or None,
        }
        started_monotonic = time.monotonic()
        self.status["last_progress_instruction_id"] = instruction_id or None
        self.status["last_progress_execution_state"] = payload.get("execution_state")
        self.status["last_progress_stage"] = payload.get("stage")
        logger.info(
            "Instruction progress send id=%s state=%s stage=%s",
            instruction_id or "-",
            payload.get("execution_state") or "-",
            payload.get("stage") or "-",
        )
        try:
            res = self._post_with_retries(
                f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions/{instruction_id}/progress",
                json=payload,
                headers=self._runtime_headers(),
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_progress_http_status"] = None
            self.status["last_progress_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_progress_at"] = time.time()
            self.status["last_progress_error"] = str(exc)
            logger.exception(
                "Instruction progress transport failed id=%s state=%s stage=%s elapsed_ms=%.1f",
                instruction_id or "-",
                payload.get("execution_state") or "-",
                payload.get("stage") or "-",
                elapsed_ms,
            )
            raise
        self.status["last_progress_http_status"] = int(res.status_code)
        if res.status_code == 401:
            self._invalidate_runtime_token("Runtime token rejected while sending progress; re-enrolling")
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_progress_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_progress_at"] = time.time()
            self.status["last_progress_error"] = "401 unauthorized"
            logger.warning(
                "Instruction progress unauthorized id=%s state=%s stage=%s status_code=%s elapsed_ms=%.1f",
                instruction_id or "-",
                payload.get("execution_state") or "-",
                payload.get("stage") or "-",
                res.status_code,
                elapsed_ms,
            )
            return
        try:
            res.raise_for_status()
        except Exception:
            elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
            self.status["last_progress_duration_ms"] = round(elapsed_ms, 3)
            self.status["last_progress_at"] = time.time()
            self.status["last_progress_error"] = f"http {res.status_code}"
            logger.exception(
                "Instruction progress rejected id=%s state=%s stage=%s status_code=%s elapsed_ms=%.1f",
                instruction_id or "-",
                payload.get("execution_state") or "-",
                payload.get("stage") or "-",
                res.status_code,
                elapsed_ms,
            )
            raise
        elapsed_ms = (time.monotonic() - started_monotonic) * 1000.0
        self.status["last_progress_duration_ms"] = round(elapsed_ms, 3)
        self.status["last_progress_at"] = time.time()
        self.status["last_progress_error"] = None
        logger.info(
            "Instruction progress confirmed id=%s state=%s stage=%s status_code=%s elapsed_ms=%.1f",
            instruction_id or "-",
            payload.get("execution_state") or "-",
            payload.get("stage") or "-",
            res.status_code,
            elapsed_ms,
        )

    def _enroll_request(self) -> None:
        payload = {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "hostname": self.hostname,
            "public_ip": self.public_ip or None,
            "details": {
                "location": self.location,
                "slug": self.agent_slug,
                "public_ip": self.public_ip or None,
            },
        }
        headers = {"Content-Type": "application/json"}
        if self.bootstrap_token:
            headers["X-Agent-Bootstrap-Token"] = self.bootstrap_token
        res = requests.post(
            f"{self.backend_url}/api/agent/enroll/request",
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        res.raise_for_status()
        data = res.json() if res.content else {}
        self.status["claim_code"] = data.get("claim_code")

    def _enroll_complete(self) -> bool:
        claim_code = str(self.status.get("claim_code") or "").strip()
        if not claim_code:
            return False
        res = requests.post(
            f"{self.backend_url}/api/agent/enroll/complete",
            json={"agent_id": self.agent_id, "claim_code": claim_code},
            timeout=self.timeout,
        )
        if res.status_code == 400:
            # Self-heal stale claim codes when backend no longer has the pending row.
            detail = ""
            try:
                payload = res.json() if res.content else {}
                if isinstance(payload, dict):
                    detail = str(payload.get("detail") or "").strip().lower()
            except Exception:
                detail = ""
            if ("pending enrollment not found" in detail) or ("invalid claim_code" in detail):
                self.status["claim_code"] = None
            return False
        if res.status_code == 409:
            # Not bound yet: keep polling with the same claim code.
            return False
        res.raise_for_status()
        data = res.json() if res.content else {}
        token = str(data.get("agent_token") or "").strip()
        if not token:
            return False
        self.agent_token = token
        self.status["registered"] = True
        self.status["paired"] = True
        self._save_token_file()
        return True

    def _diagnostic_specs(self) -> dict[str, list[str]]:
        service = self.fabricator_service_name
        return {
            "ip-local": ["hostname", "-I"],
            "uname": ["uname", "-a"],
            "os-release": ["cat", "/etc/os-release"],
            "disk-free": ["df", "-h"],
            "memory": ["free", "-m"],
            "fabricator-service-status": ["systemctl", "status", service, "--no-pager", "--full"],
            "fabricator-agent-service-status": ["systemctl", "status", "fabricator-agent", "--no-pager", "--full"],
            "fabricator-service-journal-tail": ["journalctl", "-u", service, "-n", "120", "--no-pager"],
            "fabricator-agent-journal-tail": ["journalctl", "-u", "fabricator-agent", "-n", "120", "--no-pager"],
        }

    def _run_diagnostic(self, name: str, timeout_seconds: int | None = None) -> tuple[bool, dict[str, Any], str | None]:
        requested = (name or "").strip().lower()
        specs = self._diagnostic_specs()
        cmd = specs.get(requested)
        if not cmd:
            return False, {"available": sorted(specs.keys())}, f"unsupported diagnostic name: {requested or '<empty>'}"
        timeout = timeout_seconds if timeout_seconds and timeout_seconds > 0 else self.diagnostic_timeout
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            ok = proc.returncode == 0
            result = {
                "name": requested,
                "command": cmd,
                "returncode": proc.returncode,
                "timeout_seconds": timeout,
                "duration_ms": int((time.time() - started) * 1000),
                "stdout_tail": (proc.stdout or "")[-self.output_tail_chars :],
                "stderr_tail": (proc.stderr or "")[-self.output_tail_chars :],
            }
            self.status["last_diagnostic_name"] = requested
            self.status["last_diagnostic_at"] = time.time()
            self.status["last_diagnostic_ok"] = ok
            if ok:
                return True, result, None
            return False, result, "diagnostic command failed"
        except subprocess.TimeoutExpired as exc:
            result = {
                "name": requested,
                "command": cmd,
                "returncode": None,
                "timeout_seconds": timeout,
                "duration_ms": int((time.time() - started) * 1000),
                "stdout_tail": ((exc.stdout or "") if isinstance(exc.stdout, str) else "")[-self.output_tail_chars :],
                "stderr_tail": ((exc.stderr or "") if isinstance(exc.stderr, str) else "")[-self.output_tail_chars :],
            }
            self.status["last_diagnostic_name"] = requested
            self.status["last_diagnostic_at"] = time.time()
            self.status["last_diagnostic_ok"] = False
            return False, result, "diagnostic command timed out"
        except FileNotFoundError as exc:
            self.status["last_diagnostic_name"] = requested
            self.status["last_diagnostic_at"] = time.time()
            self.status["last_diagnostic_ok"] = False
            return False, {"name": requested, "command": cmd}, f"diagnostic command binary is missing: {exc}"

    @staticmethod
    def _journalctl_binary() -> str | None:
        discovered = shutil.which("journalctl")
        if discovered:
            return discovered
        for candidate in ("/usr/bin/journalctl", "/bin/journalctl", "/usr/sbin/journalctl", "/sbin/journalctl"):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _watchdog_service_candidates(
        self,
        slug: str,
        explicit_service: str | None = None,
        explicit_services: list[str] | None = None,
        watchdog_mode: str | None = None,
    ) -> list[str]:
        slug_norm = str(slug or "").strip().lower()
        candidates: list[str] = []
        if explicit_service:
            candidates.append(str(explicit_service).strip())
        for raw in list(explicit_services or []):
            value = str(raw or "").strip()
            if value:
                candidates.append(value)
        # Always include shared watchdog unit fallbacks. Some nodes run a single
        # SS14.Watchdog service even for multiple slugs.
        candidates.extend(
            [
                "SS14.Watchdog",
                "SS14.Watchdog.service",
                "ss14-watchdog.service",
                "ss14-watchdog",
            ]
        )
        candidates.extend(
            [
                f"SS14.Watchdog-{slug_norm}.service",
                f"SS14.Watchdog-{slug_norm}",
                f"ss14-watchdog-{slug_norm}.service",
                f"ss14-watchdog-{slug_norm}",
            ]
        )
        try:
            proc = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=max(3, min(10, self.diagnostic_timeout)),
            )
            if proc.returncode == 0:
                for raw in (proc.stdout or "").splitlines():
                    text = str(raw or "").strip()
                    if not text:
                        continue
                    unit = text.split(None, 1)[0]
                    low = unit.lower()
                    if "watchdog" not in low:
                        continue
                    candidates.append(unit)
        except Exception:
            pass
        seen: set[str] = set()
        out: list[str] = []
        for value in candidates:
            key = str(value or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    def _get_watchdog_logs(self, payload: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        slug = str((payload or {}).get("slug") or "").strip().lower()
        if not slug:
            return False, {}, "slug is required"
        try:
            lines = int((payload or {}).get("lines") or 120)
        except Exception:
            lines = 120
        try:
            since_seconds = int((payload or {}).get("since_seconds") or 120)
        except Exception:
            since_seconds = 120
        lines = max(20, min(lines, 500))
        since_seconds = max(5, min(since_seconds, 604800))
        explicit_service = str(
            (payload or {}).get("service")
            or (payload or {}).get("watchdog_service_name")
            or (payload or {}).get("watchdog_service")
            or ""
        ).strip()
        explicit_services_raw = (payload or {}).get("watchdog_services")
        explicit_services: list[str] = []
        if isinstance(explicit_services_raw, list):
            explicit_services = [str(value or "").strip() for value in explicit_services_raw if str(value or "").strip()]
        watchdog_mode = str((payload or {}).get("watchdog_service_mode") or "").strip().lower()
        journalctl_bin = self._journalctl_binary()
        if not journalctl_bin:
            return False, {"slug": slug}, "journalctl is not available on this node"
        unique_candidates = self._watchdog_service_candidates(
            slug,
            explicit_service=explicit_service,
            explicit_services=explicit_services,
            watchdog_mode=watchdog_mode,
        )
        errors: list[str] = []
        no_entries_services: list[str] = []
        for service in unique_candidates:
            cmd = [
                journalctl_bin,
                "-u",
                service,
                "-n",
                str(lines),
                "--no-pager",
                "--since",
                f"{since_seconds} seconds ago",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(5, self.diagnostic_timeout))
            except FileNotFoundError as exc:
                return False, {"service": service}, f"journalctl is not available: {exc}"
            except subprocess.TimeoutExpired as exc:
                out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
                err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
                errors.append(f"{service}: timed out; stdout={_log_tail(out)} stderr={_log_tail(err)}")
                continue
            stdout = str(proc.stdout or "")
            stderr = str(proc.stderr or "")
            if proc.returncode != 0:
                errors.append(f"{service}: rc={proc.returncode} stderr={_log_tail(stderr)}")
                continue
            merged_text = (stdout + "\n" + stderr).lower()
            if "-- no entries --" in merged_text:
                no_entries_services.append(service)
                continue
            items = []
            for raw in stdout.splitlines():
                line = str(raw or "").rstrip()
                if line:
                    items.append({"raw": line})
            if not items:
                no_entries_services.append(service)
                continue
            return True, {
                "slug": slug,
                "service": service,
                "lines": lines,
                "since_seconds": since_seconds,
                "items": items,
            }, None
        # Fallback: some hosts use unexpected unit names or journal aliases.
        # Try a global journal tail and filter for watchdog-related lines.
        try:
            fallback_cmd = [
                journalctl_bin,
                "-n",
                str(max(lines, 300)),
                "--no-pager",
                "--since",
                f"{since_seconds} seconds ago",
            ]
            fallback_proc = subprocess.run(
                fallback_cmd,
                capture_output=True,
                text=True,
                timeout=max(5, self.diagnostic_timeout),
            )
            if fallback_proc.returncode == 0:
                filtered: list[dict[str, str]] = []
                slug_low = slug.lower()
                for raw in str(fallback_proc.stdout or "").splitlines():
                    line = str(raw or "").rstrip()
                    if not line:
                        continue
                    low = line.lower()
                    if "watchdog" not in low:
                        continue
                    if ("ss14.watchdog" not in low) and ("ss14-watchdog" not in low):
                        continue
                    # Prefer lines that mention slug, but keep generic watchdog lines too.
                    score = 1
                    if slug_low and slug_low in low:
                        score = 0
                    filtered.append({"raw": line, "_score": str(score)})
                if filtered:
                    filtered.sort(key=lambda row: int(str(row.get("_score") or "1")))
                    items = [{"raw": row.get("raw") or ""} for row in filtered[:lines] if str(row.get("raw") or "").strip()]
                    if items:
                        return True, {
                            "slug": slug,
                            "service": "journalctl-global-watchdog-fallback",
                            "lines": lines,
                            "since_seconds": since_seconds,
                            "items": items,
                            "note": "resolved via global watchdog journal fallback",
                        }, None
        except Exception as exc:
            errors.append(f"global-fallback: {exc}")
        if no_entries_services:
            return True, {
                "slug": slug,
                "service": no_entries_services[0],
                "lines": lines,
                "since_seconds": since_seconds,
                "items": [],
                "note": f"No entries found for services: {', '.join(no_entries_services[:8])}",
            }, None
        return False, {
            "slug": slug,
            "services": unique_candidates,
            "journalctl_bin": journalctl_bin,
        }, "watchdog log tail failed: " + " | ".join(errors[-4:])

    def _run_self_update(self, payload: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        payload_command = str(payload.get("command") or "").strip()
        base_cmd = payload_command or (
            _env(
                "AGENT_SELF_UPDATE_COMMAND",
                _default_self_update_command(),
            )
            or ""
        ).strip()
        if not base_cmd:
            return False, {}, "AGENT_SELF_UPDATE_COMMAND is empty"
        if "restart" in payload:
            restart_enabled = bool(payload.get("restart"))
        else:
            restart_enabled = _env_bool("AGENT_SELF_UPDATE_RESTART", True)
        try:
            cmd = _finalize_self_update_command(base_cmd, restart_enabled=restart_enabled)
        except ValueError as exc:
            return False, {"base_command": base_cmd}, str(exc)
        if not cmd:
            return False, {}, "self-update command is empty after normalization"
        env = os.environ.copy()
        env["FABRICATOR_AGENT_ID"] = self.agent_id
        env["FABRICATOR_AGENT_BACKEND_URL"] = self.backend_url
        env["FABRICATOR_AGENT_SOURCE_REPO"] = str(payload.get("source_repo") or "").strip()
        env["FABRICATOR_AGENT_SOURCE_BRANCH"] = str(payload.get("source_branch") or "").strip()
        env["FABRICATOR_AGENT_TARGET_VERSION"] = str(payload.get("target_version") or "").strip()
        env["FABRICATOR_AGENT_TARGET_BUILD"] = str(payload.get("target_build") or "").strip()
        logger.info(
            "Starting self-update restart=%s source_repo=%s source_branch=%s target_version=%s target_build=%s",
            restart_enabled,
            env["FABRICATOR_AGENT_SOURCE_REPO"] or "-",
            env["FABRICATOR_AGENT_SOURCE_BRANCH"] or "-",
            env["FABRICATOR_AGENT_TARGET_VERSION"] or "-",
            env["FABRICATOR_AGENT_TARGET_BUILD"] or "-",
        )
        if restart_enabled:
            log_path, state_path = _resolve_self_update_paths()
            existing: dict[str, Any] = {}
            try:
                if state_path.is_file():
                    loaded = json.loads(state_path.read_text(encoding="utf-8", errors="ignore"))
                    if isinstance(loaded, dict):
                        existing = loaded
            except Exception:
                existing = {}
            existing_pid = int(existing.get("pid") or 0)
            if _pid_is_running(existing_pid):
                logger.warning(
                    "Self-update already running pid=%s state_path=%s log_path=%s",
                    existing_pid,
                    state_path,
                    log_path,
                )
                return (
                    True,
                    {
                        "mode": "detached-already-running",
                        "pid": existing_pid,
                        "state_path": str(state_path),
                        "log_path": str(log_path),
                        "command": str(existing.get("command") or ""),
                        "restart": True,
                        "restart_service": _self_update_service_name(),
                        "note": "self-update process already running",
                    },
                    None,
                )
            try:
                proc = _detached_popen(cmd, env=env, log_path=log_path)
            except Exception as exc:
                return False, {}, f"failed to start detached self-update: {exc}"
            state_payload = {
                "pid": int(proc.pid),
                "started_at": time.time(),
                "restart": True,
                "command": cmd,
                "base_command": base_cmd,
                "source_repo": env["FABRICATOR_AGENT_SOURCE_REPO"] or None,
                "source_branch": env["FABRICATOR_AGENT_SOURCE_BRANCH"] or None,
                "target_version": env["FABRICATOR_AGENT_TARGET_VERSION"] or None,
                "target_build": env["FABRICATOR_AGENT_TARGET_BUILD"] or None,
                "log_path": str(log_path),
            }
            try:
                state_path.write_text(json.dumps(state_payload, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            except Exception:
                logger.exception("Failed to persist self-update state path=%s", state_path)
            logger.info(
                "Self-update detached process started pid=%s state_path=%s log_path=%s",
                int(proc.pid),
                state_path,
                log_path,
            )
            return (
                True,
                {
                    "mode": "detached",
                    "pid": int(proc.pid),
                    "command": cmd,
                    "base_command": base_cmd,
                    "restart": True,
                    "restart_service": _self_update_service_name(),
                    "source_repo": env["FABRICATOR_AGENT_SOURCE_REPO"] or None,
                    "source_branch": env["FABRICATOR_AGENT_SOURCE_BRANCH"] or None,
                    "target_version": env["FABRICATOR_AGENT_TARGET_VERSION"] or None,
                    "target_build": env["FABRICATOR_AGENT_TARGET_BUILD"] or None,
                    "state_path": str(state_path),
                    "log_path": str(log_path),
                    "note": "self-update scheduled; agent restart may interrupt further logs",
                },
                None,
            )
        timeout_seconds = int(_env("AGENT_SELF_UPDATE_TIMEOUT_SECONDS", "900") or "900")
        proc = subprocess.run(
            ["/bin/sh", "-lc", cmd],
            capture_output=True,
            text=True,
            timeout=max(10, timeout_seconds),
            env=env,
        )
        stdout_tail = (proc.stdout or "")[-self.output_tail_chars :]
        stderr_tail = (proc.stderr or "")[-self.output_tail_chars :]
        if proc.returncode != 0:
            return (
                False,
                {
                    "mode": "inline",
                    "command": cmd,
                    "base_command": base_cmd,
                    "returncode": proc.returncode,
                    "source_repo": env["FABRICATOR_AGENT_SOURCE_REPO"] or None,
                    "source_branch": env["FABRICATOR_AGENT_SOURCE_BRANCH"] or None,
                    "target_version": env["FABRICATOR_AGENT_TARGET_VERSION"] or None,
                    "target_build": env["FABRICATOR_AGENT_TARGET_BUILD"] or None,
                    "stdout_tail": stdout_tail,
                    "stderr_tail": stderr_tail,
                },
                f"self-update failed with code {proc.returncode}",
            )

        return (
            True,
            {
                "mode": "inline",
                "command": cmd,
                "base_command": base_cmd,
                "returncode": 0,
                "source_repo": env["FABRICATOR_AGENT_SOURCE_REPO"] or None,
                "source_branch": env["FABRICATOR_AGENT_SOURCE_BRANCH"] or None,
                "target_version": env["FABRICATOR_AGENT_TARGET_VERSION"] or None,
                "target_build": env["FABRICATOR_AGENT_TARGET_BUILD"] or None,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "restart": False,
            },
            None,
        )

    def _embedded_pick_port(self, *, start: int, stop: int, used_ports: set[int], error_message: str) -> int:
        first = max(1, int(start))
        for port in range(first, int(stop) + 1):
            if port in used_ports:
                continue
            if self._embedded_is_port_free(port):
                return port
        raise RuntimeError(error_message)

    def _embedded_allocate_port(self, requested_port: int, instances_dir: Path, fragments_dir: Path) -> int:
        try:
            port_min = int(_env("SS14_PORT_MIN", "1212") or "1212")
            port_max = int(_env("SS14_PORT_MAX", "2211") or "2211")
        except Exception as exc:
            raise RuntimeError(f"invalid SS14_PORT_MIN/SS14_PORT_MAX: {exc}")
        if port_min <= 0 or port_max <= 0:
            raise RuntimeError("SS14_PORT_MIN/SS14_PORT_MAX must be positive integers")
        if port_min > port_max:
            port_min, port_max = port_max, port_min

        used_ports: set[int] = set()
        for cfg_file in instances_dir.glob("*/config.toml"):
            try:
                for line in cfg_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("port ="):
                        used_ports.add(int(stripped.split("=", 1)[1].strip()))
                        break
            except Exception:
                continue
        for frag_file in fragments_dir.glob("*.yml"):
            try:
                for line in frag_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("ApiPort:"):
                        used_ports.add(int(stripped.split(":", 1)[1].strip()))
                        break
            except Exception:
                continue
        requested = int(requested_port or 0)
        if requested not in (0, 1):
            if requested < 1 or requested > 65535:
                raise RuntimeError(f"requested port {requested} is outside valid range 1..65535")
            if requested in used_ports or not self._embedded_is_port_free(requested):
                raise RuntimeError(f"requested port {requested} is already in use")
            return requested
        return self._embedded_pick_port(
            start=port_min,
            stop=port_max,
            used_ports=used_ports,
            error_message=f"No free ports available in range {port_min}..{port_max}",
        )

    def _embedded_allocate_watchdog_port(
        self,
        requested_port: int,
        dedicated_base: Path,
        template_root: Path,
        forbidden_ports: set[int] | None = None,
    ) -> int:
        try:
            port_min = int(_env("SS14_WD_PORT_MIN", "8000") or "8000")
            port_max = int(_env("SS14_WD_PORT_MAX", "8999") or "8999")
        except Exception as exc:
            raise RuntimeError(f"invalid SS14_WD_PORT_MIN/SS14_WD_PORT_MAX: {exc}")
        if port_min <= 0 or port_max <= 0:
            raise RuntimeError("SS14_WD_PORT_MIN/SS14_WD_PORT_MAX must be positive integers")
        if port_min > port_max:
            port_min, port_max = port_max, port_min

        used_ports: set[int] = set()
        for root in [template_root, *sorted(dedicated_base.glob(f"{template_root.name}-*"))]:
            for cfg_path in (root / "appsettings.base.yml", root / "appsettings.yml"):
                try:
                    text = cfg_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("Urls:"):
                        tail = stripped.split(":", 1)[1]
                        try:
                            parsed = urlparse(tail.strip().strip('"'))
                            if parsed.port:
                                used_ports.add(int(parsed.port))
                        except Exception:
                            continue
        if forbidden_ports:
            used_ports.update(int(port) for port in forbidden_ports if int(port) > 0)

        requested = int(requested_port or 0)
        if requested not in (0, 1):
            if requested < 1 or requested > 65535:
                raise RuntimeError(f"requested watchdog port {requested} is outside valid range 1..65535")
            if requested in used_ports or not self._embedded_is_port_free(requested):
                raise RuntimeError(f"requested watchdog port {requested} is already in use")
            return requested
        return self._embedded_pick_port(
            start=port_min,
            stop=port_max,
            used_ports=used_ports,
            error_message=f"No free watchdog ports available in range {port_min}..{port_max}",
        )

    def _embedded_is_port_free(self, port: int) -> bool:
        def _try_bind(fam: int, typ: int, addr: str) -> bool:
            sock = socket.socket(fam, typ)
            try:
                sock.settimeout(1.0)
                if typ == socket.SOCK_STREAM:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if fam == socket.AF_INET6:
                    try:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    except Exception:
                        pass
                    bind_addr = (addr, port, 0, 0)
                else:
                    bind_addr = (addr, port)
                sock.bind(bind_addr)
                return True
            except OSError:
                return False
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        if not _try_bind(socket.AF_INET, socket.SOCK_STREAM, "0.0.0.0"):
            return False
        if not _try_bind(socket.AF_INET, socket.SOCK_DGRAM, "0.0.0.0"):
            return False
        try:
            if not _try_bind(socket.AF_INET6, socket.SOCK_STREAM, "::"):
                return False
            if not _try_bind(socket.AF_INET6, socket.SOCK_DGRAM, "::"):
                return False
        except Exception:
            pass
        return True

    def _embedded_rebuild_appsettings(self, appsettings_base: Path, appsettings_out: Path, fragments_dir: Path) -> None:
        tmp = appsettings_out.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fp:
            fp.write(appsettings_base.read_text(encoding="utf-8"))
            for frag in sorted(fragments_dir.glob("*.yml")):
                fp.write(frag.read_text(encoding="utf-8"))
        tmp.replace(appsettings_out)

    def _embedded_watchdog_layout(self, slug: str) -> tuple[Path, Path, Path]:
        template_root = Path(_env("SS14_WD_ROOT", "/opt/ss14/wds/watchdog") or "/opt/ss14/wds/watchdog")
        dedicated_base = Path(
            _env(
                "SS14_WD_DEDICATED_BASE",
                str(template_root.parent.parent if template_root.parent.name == "wds" else template_root.parent),
            )
            or str(template_root.parent.parent if template_root.parent.name == "wds" else template_root.parent)
        )
        wd_root = dedicated_base / f"{template_root.name}-{slug}"
        return template_root, dedicated_base, wd_root

    def _embedded_fragment_path(self, slug: str) -> Path:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            raise ValueError("payload.slug is required")
        template_root, _, wd_root = self._embedded_watchdog_layout(slug_norm)
        dedicated_frag = wd_root / "instances.d" / f"{slug_norm}.yml"
        legacy_frag = template_root / "instances.d" / f"{slug_norm}.yml"
        if dedicated_frag.exists():
            return dedicated_frag
        if legacy_frag.exists():
            return legacy_frag
        raise ValueError(f"watchdog fragment for '{slug_norm}' does not exist")

    def _embedded_instance_config_path(self, slug: str) -> Path:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            raise ValueError("payload.slug is required")
        template_root, _, wd_root = self._embedded_watchdog_layout(slug_norm)
        dedicated_cfg = wd_root / "instances" / slug_norm / "config.toml"
        legacy_cfg = template_root / "instances" / slug_norm / "config.toml"
        if dedicated_cfg.exists():
            return dedicated_cfg
        if legacy_cfg.exists():
            return legacy_cfg
        raise ValueError(f"config.toml for '{slug_norm}' does not exist")

    def _embedded_config_contains_slug(self, slug: str, content: str) -> bool:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return False
        pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(slug_norm)}(?![A-Za-z0-9])", re.IGNORECASE)
        return bool(pattern.search(content or ""))

    def _embedded_get_instance_config(self, slug: str) -> tuple[bool, dict[str, Any], str | None]:
        try:
            cfg_path = self._embedded_instance_config_path(slug)
            content = cfg_path.read_text(encoding="utf-8", errors="ignore")
            return (
                True,
                {
                    "slug": str(slug or "").strip().lower(),
                    "content": content,
                    "config_path": str(cfg_path),
                    "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                },
                None,
            )
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        except Exception as exc:
            return False, {}, str(exc)

    def _embedded_set_instance_config(self, slug: str, content: str) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        text = content if content is not None else ""
        if not text.strip():
            return False, {"status_code": 400}, "content is empty"
        if not self._embedded_config_contains_slug(slug_norm, text):
            return False, {"status_code": 400}, f"config must contain instance slug '{slug_norm}' (case-insensitive)"
        try:
            cfg_path = self._embedded_instance_config_path(slug_norm)
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        try:
            backup = cfg_path.with_suffix(".toml.bak")
            try:
                backup.write_text(cfg_path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            except Exception:
                pass
            cfg_path.write_text(text, encoding="utf-8")
            return (
                True,
                {
                    "slug": slug_norm,
                    "status": "config_updated",
                    "content": text,
                    "config_path": str(cfg_path),
                    "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                },
                None,
            )
        except Exception as exc:
            return False, {}, str(exc)

    def _embedded_read_update_policy_from_fragment(self, content: str) -> dict[str, Any]:
        txt = str(content or "")
        api_token_match = re.search(r'^\s*ApiToken:\s*"([^"]+)"\s*$', txt, re.MULTILINE)
        api_port_match = re.search(r'^\s*ApiPort:\s*(\d+)\s*$', txt, re.MULTILINE)
        repo_match = re.search(r'^\s*BaseUrl:\s*"([^"]+)"\s*$', txt, re.MULTILINE)
        branch_match = re.search(r'^\s*Branch:\s*"([^"]+)"\s*$', txt, re.MULTILINE)
        update_type_match = re.search(r'^\s*UpdateType:\s*"([^"]+)"\s*$', txt, re.MULTILINE)
        manifest_match = re.search(r'^\s*ManifestUrl:\s*"([^"]+)"\s*$', txt, re.MULTILINE)
        update_type = str(update_type_match.group(1) or "").strip().lower() if update_type_match else "git"
        update_mode = "cdn" if update_type == "manifest" else "git"
        return {
            "api_token": str(api_token_match.group(1) or "").strip() if api_token_match else "",
            "api_port": int(api_port_match.group(1)) if api_port_match else 0,
            "repo": str(repo_match.group(1) or "").strip() if repo_match else "",
            "branch": (str(branch_match.group(1) or "").strip() if branch_match else "master") or "master",
            "update_mode": update_mode,
            "manifest_url": (str(manifest_match.group(1) or "").strip() if manifest_match else "") or None,
        }

    def _embedded_render_update_policy_fragment(
        self,
        *,
        slug: str,
        api_token: str,
        api_port: int,
        repo: str,
        branch: str,
        update_mode: str,
        manifest_url: str | None,
    ) -> str:
        base = (
            f"    {slug}:\n"
            f"      Name: \"{slug}\"\n"
            f"      ApiToken: \"{api_token}\"\n"
            f"      ApiPort: {int(api_port)}\n"
            f"      ConfigFileName: \"config.toml\"\n"
        )
        if str(update_mode or "").strip().lower() == "cdn":
            manifest = str(manifest_url or "").strip()
            if not manifest:
                manifest = f"https://cdn.thun-der.ru/api/ss14/instances/{slug}/manifest"
            update_block = (
                f"      UpdateType: \"Manifest\"\n"
                f"      Updates:\n"
                f"        ManifestUrl: \"{manifest}\"\n"
            )
        else:
            update_block = (
                f"      UpdateType: \"Git\"\n"
                f"      Updates:\n"
                f"        BaseUrl: \"{repo}\"\n"
                f"        Branch: \"{branch}\"\n"
            )
        return base + update_block + "      TimeoutSeconds: 120\n"

    def _embedded_get_instance_update_policy(self, slug: str) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        try:
            frag_path = self._embedded_fragment_path(slug_norm)
            content = frag_path.read_text(encoding="utf-8", errors="ignore")
            data = self._embedded_read_update_policy_from_fragment(content)
            return True, {
                "slug": slug_norm,
                "repo": data.get("repo"),
                "branch": data.get("branch"),
                "update_mode": data.get("update_mode"),
                "manifest_url": data.get("manifest_url"),
                "fragment_path": str(frag_path),
                "status": "ok",
            }, None
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        except Exception as exc:
            return False, {}, str(exc)

    def _embedded_set_instance_update_policy(
        self,
        slug: str,
        update_mode: str,
        manifest_url: str | None = None,
        repo: str | None = None,
        branch: str | None = None,
    ) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        mode = str(update_mode or "").strip().lower() or "git"
        if mode not in {"git", "cdn"}:
            return False, {"status_code": 400}, "update_mode must be git or cdn"
        try:
            frag_path = self._embedded_fragment_path(slug_norm)
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        try:
            content = frag_path.read_text(encoding="utf-8", errors="ignore")
            current = self._embedded_read_update_policy_from_fragment(content)
            api_token = str(current.get("api_token") or "").strip()
            api_port = int(current.get("api_port") or 0)
            resolved_repo = str(repo or current.get("repo") or "").strip()
            resolved_branch = str(branch or current.get("branch") or "master").strip() or "master"
            if not api_token or api_port <= 0:
                return False, {"status_code": 500}, f"invalid watchdog fragment for '{slug_norm}'"
            if not resolved_repo:
                return False, {"status_code": 400}, "repo is required"
            next_content = self._embedded_render_update_policy_fragment(
                slug=slug_norm,
                api_token=api_token,
                api_port=api_port,
                repo=resolved_repo,
                branch=resolved_branch,
                update_mode=mode,
                manifest_url=(str(manifest_url or "").strip() or None),
            )
            frag_path.write_text(next_content, encoding="utf-8")
            template_root, _, wd_root = self._embedded_watchdog_layout(slug_norm)
            fragments_dir = wd_root / "instances.d"
            appsettings_base = wd_root / "appsettings.base.yml"
            appsettings_out = wd_root / "appsettings.yml"
            if not fragments_dir.exists():
                fragments_dir = template_root / "instances.d"
            if not appsettings_base.exists():
                appsettings_base = template_root / "appsettings.base.yml"
            if not appsettings_out.parent.exists():
                appsettings_out = template_root / "appsettings.yml"
            self._embedded_rebuild_appsettings(appsettings_base, appsettings_out, fragments_dir)
            data = self._embedded_read_update_policy_from_fragment(next_content)
            runtime_info = None
            if str(data.get("update_mode") or "").strip().lower() == "cdn":
                runtime_info = self._embedded_ensure_runtime_for_manifest_url(str(data.get("manifest_url") or "").strip() or None)
            payload = {
                "slug": slug_norm,
                "repo": data.get("repo"),
                "branch": data.get("branch"),
                "update_mode": data.get("update_mode"),
                "manifest_url": data.get("manifest_url"),
                "fragment_path": str(frag_path),
                "appsettings_path": str(appsettings_out),
                "status": "update_policy_updated",
            }
            if runtime_info:
                payload["runtime"] = runtime_info
            return True, payload, None
        except Exception as exc:
            return False, {}, str(exc)

    def _embedded_manifest_build_platform(self) -> str:
        return (
            str(_env("SS14_ROBUST_CDN_BUILD_PLATFORM") or _env("SS14_MANIFEST_BUILD_PLATFORM") or "linux-x64").strip()
            or "linux-x64"
        )

    def _runtime_requirement_from_runtimeconfig_payload(self, payload: Any) -> dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        runtime_options = payload.get("runtimeOptions")
        if not isinstance(runtime_options, dict):
            return None
        frameworks: list[dict[str, Any]] = []
        framework = runtime_options.get("framework")
        if isinstance(framework, dict):
            frameworks.append(framework)
        multi = runtime_options.get("frameworks")
        if isinstance(multi, list):
            frameworks.extend(item for item in multi if isinstance(item, dict))
        preferred = None
        fallback = None
        for item in frameworks:
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip()
            if not name or not version:
                continue
            candidate = {"framework": name, "version": version}
            if fallback is None:
                fallback = candidate
            if name == "Microsoft.NETCore.App":
                preferred = candidate
                break
        return preferred or fallback

    def _runtime_requirement_from_manifest_payload(self, payload: Any) -> dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        builds = payload.get("builds")
        if not isinstance(builds, dict):
            return None
        platform = self._embedded_manifest_build_platform()
        ordered = sorted(
            builds.items(),
            key=lambda item: str(((item[1] or {}).get("time") if isinstance(item[1], dict) else "") or item[0]),
            reverse=True,
        )
        for _, build in ordered:
            if not isinstance(build, dict):
                continue
            server = build.get("server")
            if not isinstance(server, dict):
                continue
            platform_info = server.get(platform) if isinstance(server.get(platform), dict) else None
            if platform_info is None:
                for value in server.values():
                    if isinstance(value, dict):
                        platform_info = value
                        break
            if not isinstance(platform_info, dict):
                continue
            runtime = platform_info.get("runtime")
            if isinstance(runtime, dict):
                framework = str(runtime.get("framework") or "").strip()
                version = str(runtime.get("version") or "").strip()
                if framework and version:
                    return {"framework": framework, "version": version}
        return None

    def _embedded_fetch_manifest_runtime_requirement(self, manifest_url: str | None) -> dict[str, Any] | None:
        url = str(manifest_url or "").strip()
        if not url:
            return None
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        payload = response.json()
        return self._runtime_requirement_from_manifest_payload(payload)

    def _embedded_instance_runtime_requirement(self, slug: str) -> dict[str, Any] | None:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return None
        _, _, wd_root = self._embedded_watchdog_layout(slug_norm)
        bin_dir = wd_root / "instances" / slug_norm / "bin"
        candidates = [
            bin_dir / "Robust.Server.runtimeconfig.json",
            bin_dir / "Content.Server.runtimeconfig.json",
        ]
        for path in candidates:
            if not path.exists():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            requirement = self._runtime_requirement_from_runtimeconfig_payload(payload)
            if requirement:
                requirement["runtimeconfig_path"] = str(path)
                return requirement
        return None

    def _replace_toml_section(self, content: str, section: str, body_lines: list[str]) -> str:
        section_name = str(section or "").strip()
        if not section_name:
            return str(content or "")
        lines = str(content or "").splitlines()
        sec_re = re.compile(r'^\s*\[([^\]]+)\]\s*$')
        start = -1
        end = len(lines)
        for idx, line in enumerate(lines):
            m = sec_re.match(line)
            if not m:
                continue
            if str(m.group(1) or "").strip().lower() == section_name.lower():
                start = idx
                break
        if start >= 0:
            for idx in range(start + 1, len(lines)):
                if sec_re.match(lines[idx]):
                    end = idx
                    break
        block = [f"[{section_name}]"] + [str(line or "") for line in (body_lines or [])]
        out = lines[:start] + block + lines[end:] if start >= 0 else lines + ([""] if lines else []) + block
        return "\n".join(out).rstrip() + "\n"

    def _database_values_from_config(self, content: str) -> dict[str, str]:
        keys = ("engine", "pg_host", "pg_port", "pg_database", "pg_username", "pg_password")
        values: dict[str, str] = {k: "" for k in keys}
        lines = str(content or "").splitlines()
        in_section = False
        for line in lines:
            sec = re.match(r'^\s*\[([^\]]+)\]\s*$', line)
            if sec:
                in_section = str(sec.group(1) or "").strip().lower() == "database"
                continue
            if not in_section:
                continue
            m = re.match(r'^\s*(#\s*)?([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$', line)
            if not m:
                continue
            key = str(m.group(2) or "").strip().lower()
            if key not in values:
                continue
            if m.group(1):
                continue
            raw = str(m.group(3) or "").strip()
            if raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            raw = raw.strip()
            values[key] = raw
        return values

    def _watchdog_token_from_config(self, content: str) -> str:
        lines = str(content or "").splitlines()
        in_section = False
        fallback = ""
        for line in lines:
            sec = re.match(r'^\s*\[([^\]]+)\]\s*$', line)
            if sec:
                in_section = str(sec.group(1) or "").strip().lower() == "watchdog"
                continue
            if not in_section:
                continue
            m = re.match(r'^\s*(#\s*)?token\s*=\s*(".*?"|\S+)\s*$', line)
            if not m:
                continue
            raw = str(m.group(2) or "").strip()
            if raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            if m.group(1):
                if not fallback:
                    fallback = raw
                continue
            return raw
        return fallback

    @staticmethod
    def _pg_ident(value: str) -> str:
        return '"' + str(value or "").replace('"', '""') + '"'

    @staticmethod
    def _pg_literal(value: str) -> str:
        return "'" + str(value or "").replace("'", "''") + "'"

    def _postgres_superuser_cmd(self, psql_args: list[str]) -> list[str]:
        args = list(psql_args or [])
        if os.geteuid() == 0 and shutil.which("runuser"):
            return ["runuser", "-u", "postgres", "--", "psql"] + args
        if shutil.which("sudo"):
            return ["sudo", "-n", "-u", "postgres", "psql"] + args
        return ["psql", "-U", "postgres"] + args

    def _ensure_postgres_installed(self) -> tuple[bool, str | None]:
        if shutil.which("psql"):
            return True, None
        if not _env_bool("AGENT_POSTGRES_AUTO_INSTALL", True):
            return False, "psql is missing and AGENT_POSTGRES_AUTO_INSTALL=0"
        if os.geteuid() != 0:
            return False, "psql is missing and auto-install requires root privileges"
        if not shutil.which("apt-get"):
            return False, "psql is missing and apt-get is unavailable for auto-install"
        try:
            subprocess.run(["apt-get", "update"], check=False, timeout=120)
            proc = subprocess.run(
                ["apt-get", "install", "-y", "postgresql", "postgresql-client"],
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )
        except Exception as exc:
            return False, f"postgres auto-install failed: {exc}"
        if proc.returncode != 0:
            tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-1500:]
            return False, f"postgres auto-install failed with code {proc.returncode}: {tail}"
        return (True, None) if shutil.which("psql") else (False, "postgres auto-install finished but psql is still missing")

    def _ensure_postgres_service(self) -> None:
        if not shutil.which("systemctl"):
            return
        for unit in ("postgresql.service", "postgresql"):
            try:
                subprocess.run(["systemctl", "enable", "--now", unit], check=False, timeout=30)
            except Exception:
                continue

    def _embedded_postgres_provision(self, *, dbname: str, username: str, password: str) -> tuple[bool, dict[str, Any], str | None]:
        ok_install, install_error = self._ensure_postgres_installed()
        if not ok_install:
            return False, {"provisioned": False}, install_error
        self._ensure_postgres_service()
        role_lit = self._pg_literal(username)
        role_ident = self._pg_ident(username)
        db_lit = self._pg_literal(dbname)
        db_ident = self._pg_ident(dbname)
        pass_lit = self._pg_literal(password)

        def run_sql(sql: str, *, timeout: int = 45) -> tuple[bool, str]:
            cmd = self._postgres_superuser_cmd(["-v", "ON_ERROR_STOP=1", "-d", "postgres", "-tAc", sql])
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            except Exception as exc:
                return False, str(exc)
            if proc.returncode != 0:
                tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-1200:]
                return False, tail or f"psql exited with code {proc.returncode}"
            return True, (proc.stdout or "").strip()

        exists_role_ok, exists_role_out = run_sql(f"SELECT 1 FROM pg_roles WHERE rolname = {role_lit};")
        if not exists_role_ok:
            return False, {"provisioned": False}, f"failed to check postgres role: {exists_role_out}"
        if exists_role_out.strip() == "1":
            role_ok, role_out = run_sql(f"ALTER ROLE {role_ident} WITH LOGIN PASSWORD {pass_lit};")
        else:
            role_ok, role_out = run_sql(f"CREATE ROLE {role_ident} WITH LOGIN PASSWORD {pass_lit};")
        if not role_ok:
            return False, {"provisioned": False}, f"failed to configure postgres role: {role_out}"

        exists_db_ok, exists_db_out = run_sql(f"SELECT 1 FROM pg_database WHERE datname = {db_lit};")
        if not exists_db_ok:
            return False, {"provisioned": False}, f"failed to check postgres database: {exists_db_out}"
        if exists_db_out.strip() != "1":
            db_ok, db_out = run_sql(f"CREATE DATABASE {db_ident} OWNER {role_ident};", timeout=90)
            if not db_ok:
                return False, {"provisioned": False}, f"failed to create postgres database: {db_out}"

        grant_ok, grant_out = run_sql(f"GRANT ALL PRIVILEGES ON DATABASE {db_ident} TO {role_ident};")
        if not grant_ok:
            return False, {"provisioned": False}, f"failed to grant database privileges: {grant_out}"

        return True, {"provisioned": True}, None

    def _embedded_postgres_connectivity_check(
        self,
        *,
        pg_host: str,
        pg_port: int,
        pg_database: str,
        pg_username: str,
        pg_password: str,
    ) -> dict[str, Any]:
        check: dict[str, Any] = {"ok": False, "error": None, "detail": None}
        if not shutil.which("psql"):
            check["error"] = "psql is not installed"
            return check
        env = dict(os.environ)
        env["PGPASSWORD"] = str(pg_password or "")
        cmd = [
            "psql",
            "-h",
            str(pg_host),
            "-p",
            str(pg_port),
            "-U",
            str(pg_username),
            "-d",
            str(pg_database),
            "-tAc",
            "SELECT current_database(), current_user;",
        ]
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30, check=False)
        except Exception as exc:
            check["error"] = str(exc)
            return check
        if proc.returncode != 0:
            tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-1200:]
            check["error"] = tail or f"psql exited with code {proc.returncode}"
            return check
        row = str(proc.stdout or "").strip().splitlines()
        first = row[0] if row else ""
        parts = [part.strip() for part in first.split("|", 1)] if first else []
        if len(parts) == 2:
            check["detail"] = {"current_database": parts[0], "current_user": parts[1]}
        else:
            check["detail"] = {"raw": first}
        check["ok"] = True
        return check

    def _embedded_database_state_from_content(self, slug: str, content: str) -> dict[str, Any]:
        slug_norm = str(slug or "").strip().lower()
        vals = self._database_values_from_config(content)
        mode = "postgres" if str(vals.get("engine") or "").strip().lower() == "postgres" else "sqlite"
        token = str(self._watchdog_token_from_config(content) or vals.get("pg_password") or "").strip()
        if not token:
            token = secrets.token_hex(16)
        pg_host = str(
            vals.get("pg_host")
            or _env("SS14_INSTANCE_PG_HOST")
            or _env("SS14_PG_CONFIG_HOST")
            or _env("AGENT_PG_HOST")
            or "127.0.0.1"
        ).strip()
        pg_port_raw = str(
            vals.get("pg_port")
            or _env("SS14_INSTANCE_PG_PORT")
            or _env("SS14_PG_CONFIG_PORT")
            or _env("SS14_PG_PORT")
            or _env("AGENT_PG_PORT")
            or "5432"
        ).strip()
        try:
            pg_port = int(pg_port_raw)
        except Exception:
            pg_port = 5432
        dbname = str(vals.get("pg_database") or slug_norm).strip() or slug_norm
        username = str(vals.get("pg_username") or slug_norm).strip() or slug_norm
        password = str(vals.get("pg_password") or token).strip() or token
        out: dict[str, Any] = {
            "slug": slug_norm,
            "mode": mode,
            "postgres": {
                "pg_host": pg_host,
                "pg_port": int(pg_port),
                "pg_database": dbname,
                "pg_username": username,
                "pg_password": password,
                "connect_uri": f"postgresql://{username}:{password}@{pg_host}:{int(pg_port)}/{dbname}",
            },
        }
        if mode != "postgres":
            out["check"] = {"ok": False, "error": None, "detail": "sqlite mode"}
            return out
        install_ok, install_error = self._ensure_postgres_installed()
        if install_ok:
            self._ensure_postgres_service()
        else:
            out["check"] = {"ok": False, "error": str(install_error or "psql is not installed"), "detail": None}
            return out
        check = self._embedded_postgres_connectivity_check(
            pg_host=pg_host,
            pg_port=int(pg_port),
            pg_database=dbname,
            pg_username=username,
            pg_password=password,
        )
        error_text = str(check.get("error") or "").lower()
        should_repair = (
            not bool(check.get("ok"))
            and ("password authentication failed" in error_text or "role" in error_text)
            and _env_bool("AGENT_POSTGRES_AUTO_REPAIR_AUTH", True)
        )
        if should_repair:
            repaired_ok, repaired_meta, repaired_error = self._embedded_postgres_provision(
                dbname=dbname,
                username=username,
                password=password,
            )
            check["repair"] = dict(repaired_meta or {})
            if repaired_ok:
                check = self._embedded_postgres_connectivity_check(
                    pg_host=pg_host,
                    pg_port=int(pg_port),
                    pg_database=dbname,
                    pg_username=username,
                    pg_password=password,
                )
                check["repair"] = {"ok": True, **dict(repaired_meta or {})}
            else:
                check["repair"] = {"ok": False, "error": str(repaired_error or "postgres auth repair failed"), **dict(repaired_meta or {})}
        out["check"] = check
        return out

    def _embedded_set_instance_database_mode(self, slug: str, mode: str) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        target_mode = str(mode or "").strip().lower()
        if target_mode not in {"postgres", "sqlite"}:
            return False, {"status_code": 400}, "mode must be postgres or sqlite"
        try:
            cfg_path = self._embedded_instance_config_path(slug_norm)
            content = cfg_path.read_text(encoding="utf-8", errors="ignore")
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        except Exception as exc:
            return False, {}, str(exc)

        db_state = self._embedded_database_state_from_content(slug_norm, content)
        pg = db_state.get("postgres") if isinstance(db_state.get("postgres"), dict) else {}
        lines = [
            'engine = "postgres"',
            f'pg_host = "{str(pg.get("pg_host") or "127.0.0.1").strip()}"',
            f'pg_port = {int(pg.get("pg_port") or 5432)}',
            f'pg_database = "{str(pg.get("pg_database") or slug_norm).strip()}"',
            f'pg_username = "{str(pg.get("pg_username") or slug_norm).strip()}"',
            f'pg_password = "{str(pg.get("pg_password") or "").strip()}"',
        ]
        if target_mode == "sqlite":
            lines = [f"# {line}" for line in lines]
        next_content = self._replace_toml_section(content, "database", lines)
        try:
            backup = cfg_path.with_suffix(".toml.bak")
            try:
                backup.write_text(content, encoding="utf-8")
            except Exception:
                pass
            cfg_path.write_text(next_content, encoding="utf-8")
        except Exception as exc:
            return False, {}, str(exc)

        payload = self._embedded_database_state_from_content(slug_norm, next_content)
        payload["updated"] = True
        payload["config_path"] = str(cfg_path)
        payload["content_sha256"] = hashlib.sha256(next_content.encode("utf-8")).hexdigest()
        if target_mode == "postgres":
            pg_now = payload.get("postgres") if isinstance(payload.get("postgres"), dict) else {}
            ok, prov, prov_error = self._embedded_postgres_provision(
                dbname=str(pg_now.get("pg_database") or slug_norm),
                username=str(pg_now.get("pg_username") or slug_norm),
                password=str(pg_now.get("pg_password") or ""),
            )
            payload["provision"] = dict(prov or {})
            if not ok:
                payload["provision"]["provisioned"] = False
                return False, payload, str(prov_error or "postgres provisioning failed")
            payload["check"] = self._embedded_postgres_connectivity_check(
                pg_host=str(pg_now.get("pg_host") or "127.0.0.1"),
                pg_port=int(pg_now.get("pg_port") or 5432),
                pg_database=str(pg_now.get("pg_database") or slug_norm),
                pg_username=str(pg_now.get("pg_username") or slug_norm),
                pg_password=str(pg_now.get("pg_password") or ""),
            )
        return True, payload, None

    def _embedded_get_instance_database(self, slug: str) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        try:
            cfg_path = self._embedded_instance_config_path(slug_norm)
            content = cfg_path.read_text(encoding="utf-8", errors="ignore")
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        except Exception as exc:
            return False, {}, str(exc)
        payload = self._embedded_database_state_from_content(slug_norm, content)
        payload["config_path"] = str(cfg_path)
        payload["content_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return True, payload, None

    def _embedded_reset_instance_sqlite(
        self,
        slug: str,
        *,
        delete_database: bool,
        delete_data: bool,
    ) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return False, {"status_code": 400}, "slug is required"
        if not delete_database and not delete_data:
            return False, {"status_code": 400}, "nothing selected to delete"
        try:
            cfg_path = self._embedded_instance_config_path(slug_norm)
            content = cfg_path.read_text(encoding="utf-8", errors="ignore")
        except ValueError as exc:
            return False, {"status_code": 404}, str(exc)
        except Exception as exc:
            return False, {}, str(exc)
        payload = self._embedded_database_state_from_content(slug_norm, content)
        if str(payload.get("mode") or "").strip().lower() != "sqlite":
            return False, {"status_code": 400}, "sqlite reset is available only when database mode is sqlite"
        instance_dir = cfg_path.parent
        deleted_paths: list[str] = []
        sqlite_patterns = (
            "*.db",
            "*.db-shm",
            "*.db-wal",
            "*.sqlite",
            "*.sqlite-shm",
            "*.sqlite-wal",
            "*.sqlite3",
            "*.sqlite3-shm",
            "*.sqlite3-wal",
        )
        seen: set[Path] = set()

        def _remove_path(path: Path) -> None:
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=False)
                else:
                    path.unlink(missing_ok=True)
                deleted_paths.append(str(path))
            except FileNotFoundError:
                return

        if delete_database:
            search_roots = [instance_dir]
            data_dir = instance_dir / "data"
            if data_dir.exists():
                search_roots.append(data_dir)
            for root in search_roots:
                for pattern in sqlite_patterns:
                    for candidate in root.glob(pattern):
                        if candidate in seen:
                            continue
                        seen.add(candidate)
                        _remove_path(candidate)

        if delete_data:
            data_dir = instance_dir / "data"
            if data_dir.exists():
                _remove_path(data_dir)

        result = self._embedded_database_state_from_content(slug_norm, content)
        result["deleted_paths"] = deleted_paths
        result["delete_database"] = bool(delete_database)
        result["delete_data"] = bool(delete_data)
        result["updated"] = bool(deleted_paths)
        result["config_path"] = str(cfg_path)
        result["content_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return True, result, None

    def _embedded_resolve_instance_data_path(
        self,
        slug: str,
        relative_path: str = "",
        *,
        allow_directory: bool = True,
    ) -> tuple[Path, Path, str]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            raise ValueError("slug is required")
        cfg_path = self._embedded_instance_config_path(slug_norm)
        instance_dir = cfg_path.parent
        data_dir = instance_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        raw_relative = str(relative_path or "").replace("\\", "/").strip()
        cleaned_parts: list[str] = []
        for part in raw_relative.split("/"):
            piece = str(part or "").strip()
            if not piece or piece == ".":
                continue
            if piece == "..":
                raise ValueError("path must stay inside data")
            cleaned_parts.append(piece)
        normalized_relative = "/".join(cleaned_parts)
        target = data_dir.joinpath(*cleaned_parts) if cleaned_parts else data_dir
        try:
            target.relative_to(data_dir)
        except ValueError as exc:
            raise ValueError("path must stay inside data") from exc
        if target.exists():
            if target.is_dir() and not allow_directory:
                raise ValueError("path must point to a file inside data")
        elif not allow_directory and normalized_relative.endswith("/"):
            raise ValueError("path must point to a file inside data")
        return data_dir, target, normalized_relative

    def _embedded_list_instance_data(self, slug: str, path: str = "") -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        try:
            data_dir, target, normalized_relative = self._embedded_resolve_instance_data_path(
                slug_norm,
                path,
                allow_directory=True,
            )
        except ValueError as exc:
            detail = str(exc)
            code = 404 if "does not exist" in detail else 400
            return False, {"status_code": code}, detail
        except Exception as exc:
            return False, {}, str(exc)
        if not target.exists():
            return False, {"status_code": 404}, f"data path '{normalized_relative or '.'}' does not exist"
        if not target.is_dir():
            return False, {"status_code": 400}, "data path must point to a directory"
        items: list[dict[str, Any]] = []
        for entry in sorted(target.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
            stat_result = entry.stat()
            items.append(
                {
                    "name": entry.name,
                    "path": entry.relative_to(data_dir).as_posix(),
                    "type": "directory" if entry.is_dir() else "file",
                    "size": None if entry.is_dir() else int(stat_result.st_size),
                    "modified_at": float(stat_result.st_mtime),
                }
            )
        return True, {
            "slug": slug_norm,
            "root": "data",
            "path": normalized_relative,
            "items": items,
        }, None

    def _embedded_download_instance_data_file(self, slug: str, path: str) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        try:
            _, target, normalized_relative = self._embedded_resolve_instance_data_path(
                slug_norm,
                path,
                allow_directory=False,
            )
        except ValueError as exc:
            detail = str(exc)
            code = 404 if "does not exist" in detail else 400
            return False, {"status_code": code}, detail
        except Exception as exc:
            return False, {}, str(exc)
        if not target.exists():
            return False, {"status_code": 404}, f"data file '{normalized_relative}' does not exist"
        if not target.is_file():
            return False, {"status_code": 400}, "path must point to a file inside data"
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        try:
            content = target.read_bytes()
        except Exception as exc:
            return False, {}, str(exc)
        return True, {
            "slug": slug_norm,
            "root": "data",
            "path": normalized_relative,
            "name": target.name,
            "media_type": media_type,
            "content_base64": base64.b64encode(content).decode("ascii"),
            "size": len(content),
        }, None

    def _embedded_upload_instance_data_file(
        self,
        slug: str,
        *,
        path: str = "",
        filename: str,
        content_base64: str,
    ) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        safe_name = Path(str(filename or "").strip()).name
        if not safe_name or safe_name in {".", ".."}:
            return False, {"status_code": 400}, "filename is required"
        try:
            content = base64.b64decode(str(content_base64 or "").encode("ascii"), validate=True)
        except Exception:
            return False, {"status_code": 400}, "content_base64 must be valid base64"
        try:
            data_dir, target_dir, normalized_relative = self._embedded_resolve_instance_data_path(
                slug_norm,
                path,
                allow_directory=True,
            )
        except ValueError as exc:
            detail = str(exc)
            code = 404 if "does not exist" in detail else 400
            return False, {"status_code": code}, detail
        except Exception as exc:
            return False, {}, str(exc)
        if target_dir.exists() and not target_dir.is_dir():
            return False, {"status_code": 400}, "upload path must point to a directory inside data"
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / safe_name
            target.write_bytes(content)
            stat_result = target.stat()
        except Exception as exc:
            return False, {}, str(exc)
        return True, {
            "slug": slug_norm,
            "root": "data",
            "path": target.relative_to(data_dir).as_posix(),
            "name": target.name,
            "type": "file",
            "size": int(stat_result.st_size),
            "modified_at": float(stat_result.st_mtime),
            "uploaded": True,
            "directory": normalized_relative,
        }, None

    def _embedded_fix_ownership(self, path: Path, user: str, group: str, recursive: bool = True) -> None:
        try:
            uid = pwd.getpwnam(user).pw_uid
            gid = grp.getgrnam(group).gr_gid
        except Exception:
            return
        targets = [path]
        if recursive and path.is_dir():
            targets.extend(path.rglob("*"))
        for target in targets:
            try:
                os.chown(target, uid, gid)
            except Exception:
                pass

    def _embedded_service_account_home(self, wd_root: Path) -> Path:
        default_home = wd_root.parent / ".service-account"
        return Path(_env("SS14_WD_ACCOUNT_HOME", str(default_home)) or str(default_home))

    def _embedded_ensure_service_account(self, user: str, group: str, home: Path) -> None:
        service_home = self._embedded_service_account_home(home)
        try:
            service_home.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        try:
            grp.getgrnam(group)
        except KeyError:
            subprocess.run(
                ["groupadd", "--system", group],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=20,
            )
        try:
            existing = pwd.getpwnam(user)
        except KeyError:
            subprocess.run(
                [
                    "useradd",
                    "--system",
                    "--no-create-home",
                    "--home-dir",
                    str(service_home),
                    "--shell",
                    "/usr/sbin/nologin",
                    "--gid",
                    group,
                    user,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=20,
            )
        else:
            current_home = str(getattr(existing, "pw_dir", "") or "").strip()
            if current_home and current_home != str(service_home):
                subprocess.run(
                    ["usermod", "--home", str(service_home), user],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=20,
                )
        self._embedded_fix_ownership(service_home, user, group, recursive=False)

    def _embedded_guess_watchdog_services(self, service_name: str) -> list[str]:
        candidates: list[str] = []
        explicit = str(service_name or "").strip()
        wd_root = str((_env("SS14_WD_ROOT", "/opt/ss14/wds/watchdog") or "/opt/ss14/wds/watchdog")).strip().lower()
        if explicit:
            candidates.append(explicit)
            if not explicit.endswith(".service"):
                candidates.append(f"{explicit}.service")
        candidates.extend(
            [
                "SS14.Watchdog",
                "SS14.Watchdog.service",
                "ss14-watchdog",
                "ss14-watchdog.service",
            ]
        )
        try:
            proc = subprocess.run(
                ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                name = line.strip().split(None, 1)[0]
                low = name.lower()
                if "watchdog" in low and "ss14" in low:
                    candidates.append(name)
        except Exception:
            pass
        discovered: list[str] = []
        for candidate in list(candidates):
            normalized = candidate.strip()
            if not normalized:
                continue
            try:
                proc = subprocess.run(
                    [
                        "systemctl",
                        "show",
                        normalized,
                        "--no-pager",
                        "--property=Id,Names,Description,FragmentPath,ExecStart",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except Exception:
                continue
            if proc.returncode != 0:
                continue
            text = (proc.stdout or "").strip()
            if not text:
                continue
            low = text.lower()
            if (
                "ss14.watchdog" in low
                or (wd_root and wd_root in low)
                or ("/opt/ss14" in low and "watchdog" in low)
            ):
                discovered.append(normalized)
                continue
            names: list[str] = []
            for line in text.splitlines():
                if line.startswith("Names="):
                    names.extend(part.strip() for part in line.split("=", 1)[1].split() if part.strip())
            for name in names:
                name_low = name.lower()
                if "watchdog" in name_low and ("ss14" in name_low or "/opt/ss14" in low):
                    discovered.append(name)
        candidates.extend(discovered)
        try:
            proc = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                name = line.strip().split(None, 1)[0]
                if not name:
                    continue
                try:
                    meta = subprocess.run(
                        [
                            "systemctl",
                            "show",
                            name,
                            "--no-pager",
                            "--property=Description,FragmentPath,ExecStart",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                except Exception:
                    continue
                low = ((meta.stdout or "") + "\n" + name).lower()
                if (
                    "watchdog" in low
                    and (
                        "ss14.watchdog" in low
                        or (wd_root and wd_root in low)
                        or "/opt/ss14" in low
                    )
                ):
                    candidates.append(name)
        except Exception:
            pass
        seen: set[str] = set()
        ordered: list[str] = []
        for candidate in candidates:
            normalized = candidate.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered

    def _embedded_normalize_service_name(self, service_name: str) -> str:
        normalized = str(service_name or "").strip()
        if normalized and not normalized.endswith(".service"):
            normalized = f"{normalized}.service"
        return normalized

    def _embedded_expected_watchdog_description(self, unit_name: str) -> str:
        raw = self._embedded_normalize_service_name(unit_name)
        if raw.endswith(".service"):
            raw = raw[:-8]
        low = raw.lower()
        if low.startswith("ss14.watchdog-"):
            slug = raw[len("SS14.Watchdog-") :].strip()
            if slug:
                return f"SS14 Watchdog ({slug})"
        if low.startswith("ss14-watchdog-"):
            slug = raw[len("ss14-watchdog-") :].strip()
            if slug:
                return f"SS14 Watchdog ({slug})"
        return "SS14 Watchdog"

    def _embedded_repair_watchdog_service_env(self, service_name: str) -> bool:
        unit_name = self._embedded_normalize_service_name(service_name)
        if not unit_name:
            return False
        try:
            proc = subprocess.run(
                [
                    "systemctl",
                    "show",
                    unit_name,
                    "--no-pager",
                    "--property=ExecStart,Environment,Description,Restart,RestartSec,RestartPreventExitStatus,OOMPolicy",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            return False
        if proc.returncode != 0:
            return False
        text = (proc.stdout or "").strip()
        if not text:
            return False
        exec_line = ""
        env_line = ""
        description_line = ""
        restart_line = ""
        restart_sec_line = ""
        restart_prevent_line = ""
        oom_policy_line = ""
        for line in text.splitlines():
            if line.startswith("ExecStart="):
                exec_line = line
            elif line.startswith("Environment="):
                env_line = line
            elif line.startswith("Description="):
                description_line = line
            elif line.startswith("Restart="):
                restart_line = line
            elif line.startswith("RestartSec="):
                restart_sec_line = line
            elif line.startswith("RestartPreventExitStatus="):
                restart_prevent_line = line
            elif line.startswith("OOMPolicy="):
                oom_policy_line = line
        if not exec_line:
            return False
        match = re.search(r"(/[^\\s\"';=]+/dotnet)\\b", exec_line)
        needs_reload = False
        patched_sections: list[str] = []
        if match:
            dotnet_bin = match.group(1)
            dotnet_root = str(Path(dotnet_bin).parent)
            if dotnet_root not in {"/usr/bin", "/bin"}:
                env_low = env_line.lower()
                dotnet_root_low = dotnet_root.lower()
                has_dotnet_root = f"dotnet_root={dotnet_root_low}" in env_low
                has_dotnet_root_x64 = f"dotnet_root_x64={dotnet_root_low}" in env_low
                has_dotnet_path = "path=" in env_low and dotnet_root_low in env_low
                if not (has_dotnet_root and has_dotnet_root_x64 and has_dotnet_path):
                    system_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    dropin_dir = Path("/etc/systemd/system") / f"{unit_name}.d"
                    dropin_path = dropin_dir / "20-dotnet-path.conf"
                    dropin_body = (
                        "[Service]\n"
                        f"Environment=DOTNET_ROOT={dotnet_root}\n"
                        f"Environment=DOTNET_ROOT_X64={dotnet_root}\n"
                        f"Environment=PATH={dotnet_root}:{system_path}\n"
                    )
                    try:
                        dropin_dir.mkdir(parents=True, exist_ok=True)
                        existing = dropin_path.read_text(encoding="utf-8") if dropin_path.exists() else ""
                        if existing != dropin_body:
                            dropin_path.write_text(dropin_body, encoding="utf-8")
                            needs_reload = True
                            patched_sections.append("env")
                    except Exception:
                        return False

        restart_policy = _watchdog_restart_policy()
        restart_sec = _watchdog_restart_sec()
        restart_prevent_exit_status = _watchdog_restart_prevent_exit_status()
        oom_policy = _watchdog_oom_policy()
        current_restart = (restart_line.removeprefix("Restart=").strip().lower() if restart_line else "")
        current_restart_sec = (restart_sec_line.removeprefix("RestartSec=").strip() if restart_sec_line else "")
        current_restart_prevent = (
            restart_prevent_line.removeprefix("RestartPreventExitStatus=").strip().upper()
            if restart_prevent_line
            else ""
        )
        current_oom_policy = (oom_policy_line.removeprefix("OOMPolicy=").strip().lower() if oom_policy_line else "")
        if (
            current_restart != restart_policy.lower()
            or current_restart_sec != restart_sec
            or current_restart_prevent != restart_prevent_exit_status.upper()
            or current_oom_policy != oom_policy
        ):
            dropin_dir = Path("/etc/systemd/system") / f"{unit_name}.d"
            dropin_path = dropin_dir / "30-watchdog-policy.conf"
            dropin_body = (
                "[Service]\n"
                f"Restart={restart_policy}\n"
                f"RestartSec={restart_sec}\n"
                f"RestartPreventExitStatus={restart_prevent_exit_status}\n"
                f"OOMPolicy={oom_policy}\n"
            )
            try:
                dropin_dir.mkdir(parents=True, exist_ok=True)
                existing = dropin_path.read_text(encoding="utf-8") if dropin_path.exists() else ""
                if existing != dropin_body:
                    dropin_path.write_text(dropin_body, encoding="utf-8")
                    needs_reload = True
                    patched_sections.append("policy")
            except Exception:
                return False

        expected_description = self._embedded_expected_watchdog_description(unit_name)
        current_description = description_line.removeprefix("Description=").strip() if description_line else ""
        if expected_description and current_description != expected_description:
            dropin_dir = Path("/etc/systemd/system") / f"{unit_name}.d"
            dropin_path = dropin_dir / "40-watchdog-description.conf"
            dropin_body = (
                "[Unit]\n"
                f"Description={expected_description}\n"
            )
            try:
                dropin_dir.mkdir(parents=True, exist_ok=True)
                existing = dropin_path.read_text(encoding="utf-8") if dropin_path.exists() else ""
                if existing != dropin_body:
                    dropin_path.write_text(dropin_body, encoding="utf-8")
                    needs_reload = True
                    patched_sections.append("description")
            except Exception:
                return False

        if not needs_reload:
            return False

        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
        logger.info("Applied watchdog service fix for %s (%s)", unit_name, ", ".join(patched_sections) or "none")
        return True

    def _embedded_reconcile_watchdog_services(self) -> None:
        try:
            if os.geteuid() != 0:
                return
        except Exception:
            return
        explicit = str(_env("SS14_WD_SYSTEMD_SERVICE", "") or "").strip()
        patched: list[str] = []
        for candidate in self._embedded_guess_watchdog_services(explicit):
            try:
                if self._embedded_repair_watchdog_service_env(candidate):
                    normalized = self._embedded_normalize_service_name(candidate)
                    if normalized:
                        patched.append(normalized)
            except Exception:
                continue
        for unit_name in patched:
            try:
                subprocess.run(
                    ["systemctl", "restart", unit_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except Exception:
                pass
        if patched:
            logger.info("Reconciled watchdog systemd env for: %s", ", ".join(patched))

    def _embedded_find_watchdog_command(self, wd_root: Path) -> list[str]:
        candidates = [
            wd_root / "SS14.Watchdog",
            wd_root / "SS14.Watchdog.dll",
            wd_root / "bin" / "SS14.Watchdog",
            wd_root / "bin" / "SS14.Watchdog.dll",
        ]
        try:
            candidates.extend(wd_root.rglob("SS14.Watchdog"))
            candidates.extend(wd_root.rglob("SS14.Watchdog.dll"))
        except Exception:
            pass
        seen: set[str] = set()
        for candidate in candidates:
            try:
                path = candidate.resolve()
            except Exception:
                path = candidate
            key = str(path)
            if key in seen or not path.exists():
                continue
            seen.add(key)
            if path.name.endswith(".dll"):
                return ["dotnet", str(path)]
            if os.access(path, os.X_OK):
                return [str(path)]
        raise RuntimeError(f"SS14.Watchdog executable not found under {wd_root}")

    def _embedded_dotnet_command(self) -> list[str]:
        candidates = [
            _env("SS14_DOTNET", None),
            shutil.which("dotnet"),
            "/opt/dotnet/dotnet",
            "/usr/bin/dotnet",
        ]
        for candidate in candidates:
            value = str(candidate or "").strip()
            if not value:
                continue
            path = Path(value)
            if path.exists() or shutil.which(value):
                return [value]
        raise RuntimeError("dotnet SDK/runtime not found; install .NET 10 SDK or set SS14_DOTNET")

    def _embedded_list_installed_sdks(self, dotnet_cmd: list[str]) -> set[str]:
        try:
            proc = subprocess.run(
                [*dotnet_cmd, "--list-sdks"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except Exception:
            return set()
        if proc.returncode != 0:
            return set()
        versions: set[str] = set()
        for raw_line in (proc.stdout or "").splitlines():
            line = str(raw_line or "").strip()
            if not line:
                continue
            version = line.split(" ", 1)[0].strip()
            if version:
                versions.add(version)
        return versions

    def _embedded_list_installed_runtimes(self, dotnet_cmd: list[str]) -> dict[str, set[str]]:
        try:
            proc = subprocess.run(
                [*dotnet_cmd, "--list-runtimes"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except Exception:
            return {}
        if proc.returncode != 0:
            return {}
        runtimes: dict[str, set[str]] = {}
        for raw_line in (proc.stdout or "").splitlines():
            line = str(raw_line or "").strip()
            if not line:
                continue
            match = re.match(r"^(?P<name>\S+)\s+(?P<version>\S+)\s+\[", line)
            if not match:
                continue
            name = str(match.group("name") or "").strip()
            version = str(match.group("version") or "").strip()
            if not name or not version:
                continue
            runtimes.setdefault(name, set()).add(version)
        return runtimes

    def _embedded_required_sdk_versions(self, source_dir: Path) -> list[str]:
        global_json = source_dir / "global.json"
        if not global_json.exists():
            return []
        try:
            parsed = json.loads(global_json.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []
        sdk = parsed.get("sdk") if isinstance(parsed, dict) else None
        version = str((sdk or {}).get("version") or "").strip() if isinstance(sdk, dict) else ""
        if not version:
            return []
        return [version]

    def _embedded_sync_git_repo(self, source_dir: Path, repo_url: str, branch: str, *, recursive: bool = True) -> None:
        source_dir.parent.mkdir(parents=True, exist_ok=True)
        git_cmd = shutil.which("git")
        if not git_cmd:
            raise RuntimeError("git not found; cannot sync repository")
        if not (source_dir / ".git").exists():
            subprocess.run(
                [git_cmd, "clone", "--recursive", repo_url, str(source_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600,
                check=True,
            )
        subprocess.run([git_cmd, "fetch", "--all", "--prune"], cwd=source_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=300, check=True)
        subprocess.run([git_cmd, "checkout", branch], cwd=source_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=120, check=True)
        subprocess.run([git_cmd, "pull", "--ff-only", "origin", branch], cwd=source_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=300, check=True)
        if recursive:
            subprocess.run([git_cmd, "submodule", "update", "--init", "--recursive"], cwd=source_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=600, check=True)

    def _embedded_prepare_dotnet_install(self) -> tuple[Path, list[str], Path, dict[str, str], str, Path]:
        preferred = Path(_env("SS14_DOTNET", "/opt/dotnet/dotnet") or "/opt/dotnet/dotnet")
        try:
            existing = self._embedded_dotnet_command()
        except RuntimeError:
            existing = [str(preferred)]
        install_script = Path("/tmp/dotnet-install.sh")
        installer_url = _env("SS14_DOTNET_INSTALL_URL", "https://dot.net/v1/dotnet-install.sh") or "https://dot.net/v1/dotnet-install.sh"
        try:
            res = requests.get(installer_url, timeout=60)
            res.raise_for_status()
            install_script.write_text(res.text, encoding="utf-8")
            install_script.chmod(0o755)
        except Exception as exc:
            raise RuntimeError(f"failed to download dotnet-install.sh: {exc}")
        install_dir = preferred.parent
        install_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.setdefault("DOTNET_CLI_HOME", "/tmp")
        bash = shutil.which("bash") or "/bin/bash"
        return preferred, existing, install_dir, env, bash, install_script

    def _embedded_ensure_dotnet_sdk(self, required_versions: list[str] | None = None) -> list[str]:
        preferred, existing, install_dir, env, bash, install_script = self._embedded_prepare_dotnet_install()
        installed = self._embedded_list_installed_sdks(existing)
        wanted_versions: list[str] = []
        for raw in required_versions or []:
            version = str(raw or "").strip()
            if version and version not in wanted_versions:
                wanted_versions.append(version)
        has_dotnet_10 = any(version.startswith("10.") for version in installed)
        missing_versions = [version for version in wanted_versions if version not in installed]
        if has_dotnet_10 and not missing_versions:
            return existing
        if not has_dotnet_10:
            try:
                subprocess.run(
                    [bash, str(install_script), "--channel", "10.0", "--install-dir", str(install_dir)],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=1800,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                stderr_tail = str(exc.stderr or "").strip()[-1200:]
                raise RuntimeError(f"dotnet-install.sh failed with code {exc.returncode}: {stderr_tail or 'no stderr'}")
        for version in missing_versions:
            try:
                subprocess.run(
                    [bash, str(install_script), "--version", version, "--install-dir", str(install_dir)],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=1800,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                stderr_tail = str(exc.stderr or "").strip()[-1200:]
                raise RuntimeError(f"dotnet-install.sh failed for SDK {version} with code {exc.returncode}: {stderr_tail or 'no stderr'}")
        if not preferred.exists():
            raise RuntimeError(f"dotnet 10 installation completed but {preferred} was not found")
        return [str(preferred)]

    def _embedded_ensure_dotnet_runtime(self, framework_name: str | None, version: str | None) -> list[str]:
        framework = str(framework_name or "").strip()
        version_text = str(version or "").strip()
        if not framework or not version_text:
            raise RuntimeError("framework and version are required to install dotnet runtime")
        runtime_kind = {
            "Microsoft.NETCore.App": "dotnet",
            "Microsoft.AspNetCore.App": "aspnetcore",
        }.get(framework)
        if not runtime_kind:
            raise RuntimeError(f"unsupported .NET runtime framework: {framework}")
        preferred, existing, install_dir, env, bash, install_script = self._embedded_prepare_dotnet_install()
        installed = self._embedded_list_installed_runtimes(existing)
        if version_text in installed.get(framework, set()):
            return existing
        try:
            subprocess.run(
                [bash, str(install_script), "--runtime", runtime_kind, "--version", version_text, "--install-dir", str(install_dir)],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1800,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr_tail = str(exc.stderr or "").strip()[-1200:]
            raise RuntimeError(
                f"dotnet-install.sh failed for runtime {framework} {version_text} with code {exc.returncode}: {stderr_tail or 'no stderr'}"
            )
        if not preferred.exists():
            raise RuntimeError(f".NET runtime installation completed but {preferred} was not found")
        return [str(preferred)]

    def _embedded_ensure_runtime_requirement(self, requirement: dict[str, Any] | None, *, source: str) -> dict[str, Any] | None:
        if not isinstance(requirement, dict):
            return None
        framework = str(requirement.get("framework") or "").strip()
        version = str(requirement.get("version") or "").strip()
        if not framework or not version:
            return None
        preferred = Path(_env("SS14_DOTNET", "/opt/dotnet/dotnet") or "/opt/dotnet/dotnet")
        try:
            dotnet_cmd = self._embedded_dotnet_command()
        except RuntimeError:
            dotnet_cmd = [str(preferred)]
        installed_before = self._embedded_list_installed_runtimes(dotnet_cmd)
        already_present = version in installed_before.get(framework, set())
        if not already_present:
            self._embedded_ensure_dotnet_runtime(framework, version)
        return {
            "source": source,
            "framework": framework,
            "version": version,
            "installed": not already_present,
            "already_present": already_present,
        }

    def _embedded_ensure_runtime_for_manifest_url(self, manifest_url: str | None) -> dict[str, Any] | None:
        url = str(manifest_url or "").strip()
        if not url:
            return None
        requirement = self._embedded_fetch_manifest_runtime_requirement(url)
        return self._embedded_ensure_runtime_requirement(requirement, source=f"manifest:{url}")

    def _embedded_ensure_runtime_for_instance(self, slug: str) -> dict[str, Any] | None:
        requirement = self._embedded_instance_runtime_requirement(slug)
        return self._embedded_ensure_runtime_requirement(requirement, source=f"instance:{str(slug or '').strip().lower()}")

    def _embedded_ensure_watchdog_source(self, source_dir: Path, repo_url: str, branch: str) -> None:
        self._embedded_sync_git_repo(source_dir, repo_url, branch, recursive=True)

    def _embedded_install_watchdog(self, wd_root: Path) -> list[str]:
        repo_url = _env("SS14_WD_SOURCE_REPO", "https://github.com/space-wizards/SS14.Watchdog") or "https://github.com/space-wizards/SS14.Watchdog"
        branch = _env("SS14_WD_SOURCE_BRANCH", "master") or "master"
        source_dir = Path(_env("SS14_WD_SOURCE_DIR", str(wd_root.parent / "src" / "SS14.Watchdog")) or str(wd_root.parent / "src" / "SS14.Watchdog"))
        publish_dir = Path(_env("SS14_WD_PUBLISH_DIR", str(wd_root.parent / "publish")) or str(wd_root.parent / "publish"))
        dotnet_cmd = self._embedded_ensure_dotnet_sdk()
        self._embedded_ensure_watchdog_source(source_dir, repo_url, branch)
        if publish_dir.exists():
            shutil.rmtree(publish_dir, ignore_errors=True)
        publish_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.setdefault("DOTNET_CLI_HOME", "/tmp")
        publish_ok = False
        try:
            subprocess.run(
                [*dotnet_cmd, "publish", "-c", "Release", "-r", "linux-x64", "--no-self-contained", "-o", str(publish_dir)],
                cwd=source_dir,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1800,
                check=True,
            )
            publish_ok = True
        except subprocess.CalledProcessError:
            publish_ok = False
        wd_root.mkdir(parents=True, exist_ok=True)
        if publish_ok:
            for entry in publish_dir.iterdir():
                if entry.name in {"appsettings.yml", "appsettings.base.yml"} and (wd_root / entry.name).exists():
                    continue
                target = wd_root / entry.name
                if entry.is_dir():
                    if target.exists():
                        shutil.rmtree(target, ignore_errors=True)
                    shutil.copytree(entry, target)
                else:
                    shutil.copy2(entry, target)
            return self._embedded_find_watchdog_command(wd_root)

        subprocess.run(
            [*dotnet_cmd, "build", "-c", "Release"],
            cwd=source_dir,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1800,
            check=True,
        )
        built_dlls = sorted(source_dir.glob("**/bin/Release/**/SS14.Watchdog.dll"))
        for dll in built_dlls:
            if dll.is_file():
                return ["dotnet", str(dll)]
        raise RuntimeError("SS14.Watchdog build succeeded but SS14.Watchdog.dll was not found")

    def _embedded_bootstrap_watchdog_service(self, service_name: str, wd_root: Path, user: str, group: str) -> str:
        unit_name = self._embedded_normalize_service_name(service_name) or "ss14-watchdog.service"
        try:
            exec_parts = self._embedded_find_watchdog_command(wd_root)
        except RuntimeError:
            exec_parts = self._embedded_install_watchdog(wd_root)
        service_home = self._embedded_service_account_home(wd_root)
        dotnet_cli_home = service_home / ".dotnet"
        nuget_packages = service_home / ".nuget" / "packages"
        xdg_data_home = service_home / ".local" / "share"
        xdg_cache_home = service_home / ".cache"
        for path in (service_home, dotnet_cli_home, nuget_packages, xdg_data_home, xdg_cache_home):
            try:
                path.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            self._embedded_fix_ownership(path, user, group, recursive=False)
        dotnet_root = ""
        if exec_parts:
            first = Path(exec_parts[0])
            dll_path = wd_root / "SS14.Watchdog.dll"
            if first.name == "SS14.Watchdog" and dll_path.exists():
                dotnet_cmd = self._embedded_ensure_dotnet_sdk()
                exec_parts = [*dotnet_cmd, str(dll_path)]
                dotnet_root = str(Path(dotnet_cmd[0]).resolve().parent)
            elif first.name == "dotnet":
                try:
                    dotnet_root = str(first.resolve().parent)
                except Exception:
                    dotnet_root = str(first.parent)
        exec_start = " ".join(shlex.quote(part) for part in exec_parts)
        env_block = ""
        system_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        if dotnet_root:
            env_block = (
                f"Environment=DOTNET_ROOT={dotnet_root}\n"
                f"Environment=DOTNET_ROOT_X64={dotnet_root}\n"
                f"Environment=PATH={dotnet_root}:{system_path}\n"
            )
        env_block += (
            f"Environment=HOME={service_home}\n"
            f"Environment=DOTNET_CLI_HOME={dotnet_cli_home}\n"
            f"Environment=NUGET_PACKAGES={nuget_packages}\n"
            f"Environment=XDG_DATA_HOME={xdg_data_home}\n"
            f"Environment=XDG_CACHE_HOME={xdg_cache_home}\n"
            "Environment=DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1\n"
            "Environment=DOTNET_CLI_TELEMETRY_OPTOUT=1\n"
            "Environment=DOTNET_NOLOGO=1\n"
        )
        restart_policy = _watchdog_restart_policy()
        restart_sec = _watchdog_restart_sec()
        restart_prevent_exit_status = _watchdog_restart_prevent_exit_status()
        oom_policy = _watchdog_oom_policy()
        unit_path = Path("/etc/systemd/system") / unit_name
        unit_body = (
            "[Unit]\n"
            "Description=SS14 Watchdog\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={wd_root}\n"
            f"{env_block}"
            f"ExecStart={exec_start}\n"
            f"User={user}\n"
            f"Group={group}\n"
            f"Restart={restart_policy}\n"
            f"RestartSec={restart_sec}\n"
            f"RestartPreventExitStatus={restart_prevent_exit_status}\n"
            f"OOMPolicy={oom_policy}\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        unit_path.write_text(unit_body, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
        subprocess.run(["systemctl", "enable", unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
        return unit_name

    def _embedded_restart_watchdog(self, service_name: str, wd_root: Path, user: str, group: str) -> str:
        errors: list[str] = []
        explicit = self._embedded_normalize_service_name(service_name)
        legacy_names = {
            "SS14.Watchdog",
            "SS14.Watchdog.service",
            "ss14-watchdog",
            "ss14-watchdog.service",
        }
        if explicit and explicit not in legacy_names:
            bootstrapped = self._embedded_bootstrap_watchdog_service(explicit, wd_root, user, group)
            proc = subprocess.run(
                ["systemctl", "restart", bootstrapped],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
            if proc.returncode == 0:
                return bootstrapped
            errors.append(f"{bootstrapped}: rc={proc.returncode} {(proc.stderr or '').strip()}")
            raise RuntimeError("watchdog restart failed; tried: " + " | ".join(errors[-4:]))
        for candidate in self._embedded_guess_watchdog_services(service_name):
            try:
                self._embedded_repair_watchdog_service_env(candidate)
            except Exception:
                pass
            proc = subprocess.run(
                ["systemctl", "restart", candidate],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
            if proc.returncode == 0:
                return candidate
            errors.append(f"{candidate}: rc={proc.returncode} {(proc.stderr or '').strip()}")
        if errors and all("not found" in err.lower() or "could not be found" in err.lower() for err in errors):
            bootstrapped = self._embedded_bootstrap_watchdog_service(service_name, wd_root, user, group)
            proc = subprocess.run(
                ["systemctl", "restart", bootstrapped],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
            if proc.returncode == 0:
                return bootstrapped
            errors.append(f"{bootstrapped}: rc={proc.returncode} {(proc.stderr or '').strip()}")
        raise RuntimeError("watchdog restart failed; tried: " + " | ".join(errors[-4:]))

    def _embedded_watchdog_failure_context(self, service_name: str) -> str:
        parts: list[str] = []
        try:
            proc = subprocess.run(
                ["systemctl", "status", service_name, "--no-pager", "--full"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            status_tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-self.output_tail_chars :]
            if status_tail:
                parts.append(f"systemctl: {status_tail}")
        except Exception:
            pass
        try:
            proc = subprocess.run(
                ["journalctl", "-u", service_name, "-n", "80", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            journal_tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-self.output_tail_chars :]
            if journal_tail:
                parts.append(f"journal: {journal_tail}")
        except Exception:
            pass
        return " | ".join(parts)

    def _embedded_wait_watchdog_api(self, watchdog_url: str, service_name: str) -> None:
        try:
            parsed = urlparse(watchdog_url)
            host = parsed.hostname or "127.0.0.1"
            port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
        except Exception:
            host, port = "127.0.0.1", 8000
        deadline = time.time() + max(5, int(_env("SS14_WD_READY_TIMEOUT_SECONDS", "25") or "25"))
        last_error = ""
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2.0):
                    return
            except OSError as exc:
                last_error = str(exc)
                time.sleep(1.0)
        parts = [f"watchdog API did not become ready at {watchdog_url}"]
        if last_error:
            parts.append(last_error)
        context = self._embedded_watchdog_failure_context(service_name)
        if context:
            parts.append(context)
        raise RuntimeError(" | ".join(parts))

    def _embedded_notify_watchdog_update(self, watchdog_url: str, slug: str, api_token: str, service_name: str) -> dict[str, Any]:
        try:
            parsed = urlparse(watchdog_url)
            if parsed.scheme and parsed.netloc:
                watchdog_url = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            watchdog_url = watchdog_url.rstrip("/")
        last_error = ""
        for _ in range(max(1, int(_env("SS14_WD_UPDATE_RETRIES", "5") or "5"))):
            try:
                res = requests.post(
                    f"{watchdog_url.rstrip('/')}/instances/{slug}/update",
                    auth=(slug, api_token),
                    timeout=max(5, self.timeout),
                )
                return {
                    "status_code": res.status_code,
                    "body_tail": (res.text or "")[-self.output_tail_chars :],
                }
            except requests.RequestException as exc:
                last_error = str(exc)
                time.sleep(1.0)
        context = self._embedded_watchdog_failure_context(service_name)
        message = f"watchdog update failed at {watchdog_url.rstrip('/')}/instances/{slug}/update"
        if last_error:
            message += f": {last_error}"
        if context:
            message += f" | {context}"
        raise RuntimeError(message)

    def _validate_create_slug_command_result(self, body: dict[str, Any], result: dict[str, Any] | None = None) -> dict[str, Any]:
        slug = str((body or {}).get("slug") or "").strip().lower()
        if not slug:
            raise RuntimeError("payload.body.slug is required")

        template_root, _, wd_root = self._embedded_watchdog_layout(slug)
        dedicated_cfg = wd_root / "instances" / slug / "config.toml"
        legacy_cfg = template_root / "instances" / slug / "config.toml"
        cfg_path = dedicated_cfg if dedicated_cfg.exists() else legacy_cfg
        if not cfg_path.exists():
            raise RuntimeError(f"create-slug command returned success but config.toml was not created for '{slug}'")

        explicit_service = _env("SS14_WD_SYSTEMD_SERVICE", f"SS14.Watchdog-{slug}") or f"SS14.Watchdog-{slug}"
        watchdog_url = ""
        try:
            watchdog_url, _ = self._resolve_watchdog_api_base_url(slug)
        except Exception:
            watchdog_url = ""
        if not watchdog_url:
            try:
                watchdog_port = int((body or {}).get("watchdog_port") or 0)
            except Exception:
                watchdog_port = 0
            if watchdog_port > 0:
                watchdog_url = f"http://127.0.0.1:{watchdog_port}"
        if not watchdog_url:
            raise RuntimeError(
                f"create-slug command returned success but watchdog API base URL could not be resolved for '{slug}'"
            )
        self._embedded_wait_watchdog_api(watchdog_url, explicit_service)
        out = dict(result or {})
        out["validated_slug"] = slug
        out["config_path"] = str(cfg_path)
        out["watchdog_url"] = watchdog_url
        out["watchdog_service"] = explicit_service
        return out

    def _embedded_create_slug(self, body: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        slug = str(body.get("slug") or "").strip().lower()
        repo = str(body.get("repo") or "").strip()
        branch = str(body.get("branch") or "master").strip() or "master"
        public_host = _normalize_host(str(body.get("public_host") or _env("SS14_PUBLIC_HOST", "ss-14.ru") or "ss-14.ru"))
        host_user = str(body.get("host_user") or "Ren0san").strip() or "Ren0san"

        if not slug:
            return False, {}, "payload.body.slug is required"
        if not repo.startswith("https://"):
            return False, {}, "Repository URL must start with https://"
        if not (3 <= len(slug) <= 64 and all(ch in "abcdefghijklmnopqrstuvwxyz0123456789_-" for ch in slug)):
            return False, {}, "Slug must be 3..64 characters of a-z, 0-9, '-' or '_'"

        template_root = Path(_env("SS14_WD_ROOT", "/opt/ss14/wds/watchdog") or "/opt/ss14/wds/watchdog")
        dedicated_base = Path(
            _env(
                "SS14_WD_DEDICATED_BASE",
                str(template_root.parent.parent if template_root.parent.name == "wds" else template_root.parent),
            )
            or str(template_root.parent.parent if template_root.parent.name == "wds" else template_root.parent)
        )
        wd_root = dedicated_base / f"{template_root.name}-{slug}"
        instances_dir = wd_root / "instances"
        fragments_dir = wd_root / "instances.d"
        appsettings_base = wd_root / "appsettings.base.yml"
        appsettings_out = wd_root / "appsettings.yml"
        inst_dir = instances_dir / slug
        frag_file = fragments_dir / f"{slug}.yml"
        try:
            explicit_watchdog_port = int(body.get("watchdog_port") or 0)
        except Exception:
            return False, {}, "watchdog_port must be an integer"

        try:
            explicit_port = int(body.get("port") or 1)
        except Exception:
            return False, {}, "Port must be an integer"

        try:
            legacy_instances_dir = template_root / "instances"
            legacy_fragments_dir = template_root / "instances.d"
            port = self._embedded_allocate_port(explicit_port, legacy_instances_dir, legacy_fragments_dir)
        except Exception as exc:
            return False, {}, str(exc)
        try:
            watchdog_port = self._embedded_allocate_watchdog_port(
                explicit_watchdog_port,
                dedicated_base,
                template_root,
                {port},
            )
        except Exception as exc:
            return False, {}, str(exc)
        watchdog_url = f"http://127.0.0.1:{int(watchdog_port)}"
        watchdog_service = _env("SS14_WD_SYSTEMD_SERVICE", f"SS14.Watchdog-{slug}") or f"SS14.Watchdog-{slug}"
        wd_fs_user = _env("SS14_WD_FS_USER") or _env("SS14_WD_USER") or "ss14"
        wd_fs_group = _env("SS14_WD_FS_GROUP") or _env("SS14_WD_GROUP") or wd_fs_user

        if wd_root.exists():
            return False, {"watchdog_root": str(wd_root)}, f"Watchdog root for instance '{slug}' already exists"
        if inst_dir.exists():
            return False, {"dir_path": str(inst_dir)}, f"Directory for instance '{slug}' already exists"
        if frag_file.exists():
            return False, {"fragment_path": str(frag_file)}, f"Watchdog fragment for instance '{slug}' already exists"

        api_token = secrets.token_hex(8)
        server_url = _build_server_url(public_host, slug, port)
        udp_host = public_host or "127.0.0.1"
        loki_host = _normalize_host(_env("AGENT_LOKI_HOST") or "") or public_host or "127.0.0.1"
        config_content = (
            f"[net]\n"
            f"tickrate = 30\n"
            f"port = {port}\n"
            f"log_late_msg = false\n"
            f"#bindto = \"0.0.0.0\"\n\n"
            f"[hub]\n"
            f"advertise = true\n"
            f"server_url = \"{server_url}\"\n"
            f"hub_urls = \"https://hub.spacestation14.com/,https://hub.singularity14.co.uk/\"\n"
            f"tags = \"lang:ru,region:eu_e\"\n\n"
            f"[status]\n"
            f"bind = \"*:{port}\"\n"
            f"connectaddress = \"udp://{udp_host}:{port}\"\n\n"
            f"[game]\n"
            f"hostname = \"[RU] {slug}\"\n"
            f"desc = \"Авто-инстанс {slug}\"\n"
            f"maxplayers = 30\n"
            f"soft_max_players = 30\n"
            f"auto_pause_empty = true\n"
            f"lobbyenabled = true\n"
            f"lobbyduration = 60\n"
            f"role_timers = false\n"
            f"maxcharacterslots = 3\n"
            f"station_goals = false\n\n"
            f"[loki]\n"
            f"name = \"{slug}\"\n"
            f"username = \"{slug}\"\n"
            f"password = \"{api_token}\"\n"
            f"address = \"http://{loki_host}:3100\"\n"
            f"enabled = true\n\n"
            f"[watchdog]\n"
            f"token = \"{api_token}\"\n\n"
            f"[console]\n"
            f"loginlocal = true\n"
            f"login_host_user = \"{host_user}\"\n"
        )
        yaml_content = (
            f"    {slug}:\n"
            f"      Name: \"{slug}\"\n"
            f"      ApiToken: \"{api_token}\"\n"
            f"      ApiPort: {port}\n"
            f"      ConfigFileName: \"config.toml\"\n"
            f"      UpdateType: \"Git\"\n"
            f"      Updates:\n"
            f"        BaseUrl: \"{repo}\"\n"
            f"        Branch: \"{branch}\"\n"
            f"      TimeoutSeconds: 120\n"
        )

        created_inst_dir = False
        created_frag = False
        try:
            self._embedded_ensure_service_account(wd_fs_user, wd_fs_group, wd_root)
            wd_root.mkdir(parents=True, exist_ok=True)
            instances_dir.mkdir(parents=True, exist_ok=True)
            fragments_dir.mkdir(parents=True, exist_ok=True)
            inst_dir.mkdir(parents=True, exist_ok=False)
            created_inst_dir = True
            (inst_dir / "config.toml").write_text(config_content, encoding="utf-8")
            frag_file.write_text(yaml_content, encoding="utf-8")
            created_frag = True

            appsettings_base.write_text(
                "Serilog:\n"
                "  MinimumLevel:\n"
                "    Default: Information\n"
                "    Override:\n"
                "      SS14: Debug\n"
                "      Microsoft: Warning\n\n"
                f"Urls: \"http://127.0.0.1:{int(watchdog_port)}\"\n"
                f"BaseUrl: \"http://127.0.0.1:{int(watchdog_port)}/\"\n\n"
                "Process:\n"
                "  PersistServers: true\n\n"
                "Servers:\n"
                "  Instances:\n",
                encoding="utf-8",
            )
            self._embedded_rebuild_appsettings(appsettings_base, appsettings_out, fragments_dir)
            try:
                source_dir = inst_dir / "source"
                self._embedded_sync_git_repo(source_dir, repo, branch, recursive=True)
                required_sdk_versions = self._embedded_required_sdk_versions(source_dir)
                if required_sdk_versions:
                    self._embedded_ensure_dotnet_sdk(required_versions=required_sdk_versions)
            except Exception as exc:
                logger.warning("embedded preflight for instance source %s failed: %s", slug, exc)
            self._embedded_fix_ownership(wd_root, wd_fs_user, wd_fs_group)
            self._embedded_fix_ownership(inst_dir, wd_fs_user, wd_fs_group)
            self._embedded_fix_ownership(fragments_dir, wd_fs_user, wd_fs_group, recursive=False)
            self._embedded_fix_ownership(instances_dir, wd_fs_user, wd_fs_group, recursive=False)
            restarted_service = self._embedded_restart_watchdog(watchdog_service, wd_root, wd_fs_user, wd_fs_group)
            self._embedded_wait_watchdog_api(watchdog_url, restarted_service)
            update_result = self._embedded_notify_watchdog_update(watchdog_url, slug, api_token, restarted_service)
            return True, {
                "mode": "embedded",
                "slug": slug,
                "port": port,
                "repo": repo,
                "branch": branch,
                "dir_path": str(inst_dir),
                "fragment_path": str(frag_file),
                "token": api_token,
                "watchdog_root": str(wd_root),
                "watchdog_port": int(watchdog_port),
                "watchdog_service": restarted_service,
                "watchdog_update": update_result,
            }, None
        except Exception as exc:
            try:
                if created_frag and frag_file.exists():
                    frag_file.unlink()
            except Exception:
                pass
            try:
                if created_inst_dir and inst_dir.exists():
                    shutil.rmtree(inst_dir, ignore_errors=True)
            except Exception:
                pass
            try:
                if wd_root.exists():
                    shutil.rmtree(wd_root, ignore_errors=True)
            except Exception:
                pass
            return False, {"mode": "embedded", "slug": slug}, f"embedded create-slug failed: {exc}"

    def _run_create_slug(self, payload: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
        slug = str((body or {}).get("slug") or "").strip()
        if not slug:
            return False, {}, "payload.body.slug is required"

        command = str(payload.get("command") or _env("AGENT_CREATE_SLUG_COMMAND", "") or "").strip()
        timeout_seconds = int(payload.get("timeout_seconds") or _env("AGENT_CREATE_SLUG_TIMEOUT_SECONDS", "900") or "900")
        if command:
            env = os.environ.copy()
            env["FABRICATOR_SLUG"] = slug
            env["FABRICATOR_REPO"] = str((body or {}).get("repo") or "")
            env["FABRICATOR_BRANCH"] = str((body or {}).get("branch") or "master")
            env["FABRICATOR_PORT"] = str(int((body or {}).get("port") or 1))
            env["FABRICATOR_WATCHDOG_PORT"] = str(int((body or {}).get("watchdog_port") or 0))
            env["FABRICATOR_PUBLIC_HOST"] = str((body or {}).get("public_host") or "")
            env["FABRICATOR_HOST_USER"] = str((body or {}).get("host_user") or "")
            try:
                proc = subprocess.run(
                    ["/bin/sh", "-lc", command],
                    capture_output=True,
                    text=True,
                    timeout=max(10, timeout_seconds),
                    env=env,
                )
            except subprocess.TimeoutExpired:
                return False, {"command": command, "timeout_seconds": timeout_seconds}, "create-slug command timed out"
            result = {
                "command": command,
                "returncode": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-self.output_tail_chars :],
                "stderr_tail": (proc.stderr or "")[-self.output_tail_chars :],
            }
            if proc.returncode == 0:
                try:
                    validated = self._validate_create_slug_command_result(body or {}, result)
                except Exception as exc:
                    return False, result, str(exc)
                return True, validated, None
            return False, result, f"create-slug command failed with code {proc.returncode}"

        embedded_enabled = _env_bool("AGENT_EMBEDDED_CREATE_SLUG", True)
        prefer_local_api = _env_bool("AGENT_PREFER_LOCAL_API", False)
        if embedded_enabled and not prefer_local_api:
            return self._embedded_create_slug(body or {})

        local_api = _default_local_api_url()
        token = _local_api_token(self)
        headers = {"X-API-Token": token or "", "Content-Type": "application/json"}
        local_api_error: str | None = None
        try:
            res = requests.post(
                f"{local_api}/api/ss14/instances",
                json=body or {},
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            local_api_error = f"local edge API is unreachable at {local_api}: {exc}"
        else:
            ok = res.status_code < 400
            try:
                data = res.json()
            except Exception:
                data = {"raw": (res.text or "")[-3000:]}
            if ok:
                return True, {"status_code": res.status_code, "response": data, "fallback": "create-instance"}, None
            should_fallback_embedded = res.status_code >= 500 or res.status_code in {404, 405}
            if not should_fallback_embedded or not embedded_enabled:
                return False, {"status_code": res.status_code, "response": data}, "local api fallback failed"
            local_api_error = f"local api fallback failed: status={res.status_code}"

        if embedded_enabled:
            ok, data, error = self._embedded_create_slug(body or {})
            if ok:
                if local_api_error:
                    data = dict(data or {})
                    data["local_api_warning"] = local_api_error
                return ok, data, error
            if local_api_error:
                error = f"{error} | {local_api_error}" if error else local_api_error
            return ok, data, error

        return False, {"local_api": local_api}, local_api_error or "create-slug failed"

    def _require_admin_token(self, token: str | None) -> None:
        expected = self.admin_token
        if not expected:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AGENT_ADMIN_TOKEN is not configured",
            )
        if not token or not secrets.compare_digest(token, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent admin token")

    def _resolve_watchdog_api_base_url(self, slug: str) -> tuple[str, str]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return "", "missing-slug"
        template_root, _, wd_root = self._embedded_watchdog_layout(slug_norm)
        candidates = [
            wd_root / "appsettings.yml",
            wd_root / "appsettings.base.yml",
            template_root / "appsettings.yml",
            template_root / "appsettings.base.yml",
        ]
        patterns = [
            re.compile(r"^\s*BaseUrl\s*:\s*\"?([^\"\s]+)\"?\s*$", re.IGNORECASE),
            re.compile(r"^\s*Urls\s*:\s*\"?([^\"\s]+)\"?\s*$", re.IGNORECASE),
        ]
        for appsettings_path in candidates:
            try:
                if not appsettings_path.is_file():
                    continue
                for line in appsettings_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    value = ""
                    for pattern in patterns:
                        match = pattern.match(line)
                        if match:
                            value = str(match.group(1) or "").strip()
                            break
                    if not value:
                        continue
                    parsed = urlparse(value if "://" in value else f"http://{value}")
                    if parsed.scheme and parsed.netloc:
                        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/"), str(appsettings_path)
            except Exception:
                logger.exception(
                    "Failed to parse watchdog appsettings for slug=%s path=%s",
                    slug_norm,
                    appsettings_path,
                )
        env_url = str(_env("AGENT_WATCHDOG_API_URL") or "").strip()
        if env_url:
            parsed = urlparse(env_url if "://" in env_url else f"http://{env_url}")
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}".rstrip("/"), "AGENT_WATCHDOG_API_URL"
        return "", "not-found"

    def _resolve_watchdog_instance_token(self, slug: str) -> tuple[str, str]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return "", "missing-slug"
        try:
            cfg_path = self._embedded_instance_config_path(slug_norm)
        except Exception:
            cfg_path = None
        if cfg_path and cfg_path.is_file():
            try:
                parsed = tomllib.loads(cfg_path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(parsed, dict):
                    watchdog = parsed.get("watchdog") if isinstance(parsed.get("watchdog"), dict) else {}
                    token = str((watchdog or {}).get("token") or "").strip()
                    if token:
                        return token, str(cfg_path)
                    loki = parsed.get("loki") if isinstance(parsed.get("loki"), dict) else {}
                    token = str((loki or {}).get("password") or "").strip()
                    if token:
                        return token, f"{cfg_path}#loki.password"
            except Exception:
                logger.exception("Failed to parse watchdog token from config slug=%s path=%s", slug_norm, cfg_path)
        token = _local_api_token(self)
        if token:
            return token, "local-api-token-fallback"
        return "", "not-found"

    def _execute_watchdog_http_action(
        self,
        *,
        instruction_id: str,
        kind: str,
        slug: str,
        action: str,
        reason: str | None = None,
    ) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return False, {}, "payload.slug is required"
        base_url, base_source = self._resolve_watchdog_api_base_url(slug_norm)
        if not base_url:
            return False, {"slug": slug_norm, "source": base_source}, "watchdog API base URL is not configured"
        token, token_source = self._resolve_watchdog_instance_token(slug_norm)
        if not token:
            return False, {"slug": slug_norm, "source": token_source}, "watchdog token is not configured"
        url = f"{base_url.rstrip('/')}/instances/{slug_norm}/{action}"
        headers: dict[str, str] = {}
        reason_text = str(reason or "").strip()
        if reason_text:
            headers["X-Reason"] = reason_text
        timeout_default = max(30.0, float(self.timeout))
        timeout_env_map = {
            "stop": "AGENT_WATCHDOG_STOP_TIMEOUT_SECONDS",
            "update": "AGENT_WATCHDOG_UPDATE_TIMEOUT_SECONDS",
        }
        timeout_env_name = timeout_env_map.get(action, "AGENT_WATCHDOG_HTTP_TIMEOUT_SECONDS")
        timeout_seconds = timeout_default
        try:
            timeout_seconds = max(5.0, float(_env(timeout_env_name, str(timeout_default)) or str(timeout_default)))
        except Exception:
            timeout_seconds = timeout_default
        curl_preview = f'curl -s -u "{slug_norm}:***" -X POST "{url}"'
        if reason_text:
            safe_reason = reason_text.replace('"', '\\"')
            curl_preview += f' -H "X-Reason: {safe_reason}"'
        curl_preview += ' -w " -> HTTP %{http_code}\\n"'
        logger.info(
            "Executing instruction id=%s kind=%s slug=%s via POST %s auth_user=%s token_source=%s url_source=%s timeout_seconds=%.1f curl=%s",
            instruction_id,
            kind,
            slug_norm,
            url,
            slug_norm,
            token_source,
            base_source,
            timeout_seconds,
            curl_preview,
        )
        try:
            res = requests.post(
                url,
                auth=(slug_norm, token),
                headers=headers or None,
                timeout=timeout_seconds,
            )
        except requests.ReadTimeout as exc:
            logger.error(
                "Instruction id=%s kind=%s slug=%s watchdog request timed out url=%s timeout_seconds=%.1f error=%s",
                instruction_id,
                kind,
                slug_norm,
                url,
                timeout_seconds,
                exc,
            )
            return (
                False,
                {
                    "watchdog_url": base_url,
                    "url": url,
                    "timeout_seconds": timeout_seconds,
                    "curl": curl_preview,
                },
                f"watchdog request timed out after {int(round(timeout_seconds))}s: {exc}",
            )
        except requests.RequestException as exc:
            logger.error(
                "Instruction id=%s kind=%s slug=%s watchdog request failed url=%s error=%s",
                instruction_id,
                kind,
                slug_norm,
                url,
                exc,
            )
            return (
                False,
                {
                    "watchdog_url": base_url,
                    "url": url,
                    "timeout_seconds": timeout_seconds,
                    "curl": curl_preview,
                },
                f"watchdog request failed: {exc}",
            )
        try:
            data: Any = res.json()
        except Exception:
            data = {"raw": (res.text or "")[-3000:]}
        ok = res.status_code < 400
        logger.info(
            "Instruction id=%s kind=%s slug=%s watchdog response status=%s body=%s",
            instruction_id,
            kind,
            slug_norm,
            res.status_code,
            _log_tail(data),
        )
        if ok:
            result = {"status_code": res.status_code, "response": data, "url": url}
            if action == "update":
                runtime_info = self._embedded_ensure_runtime_for_instance(slug_norm)
                if runtime_info:
                    result["runtime"] = runtime_info
            return True, result, None
        return (
            False,
            {
                "status_code": res.status_code,
                "response": data,
                "watchdog_url": base_url,
                "url": url,
                "timeout_seconds": timeout_seconds,
                "curl": curl_preview,
            },
            "watchdog api call failed",
        )

    def _execute_watchdog_service_restart(
        self,
        *,
        instruction_id: str,
        kind: str,
        slug: str,
    ) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return False, {}, "payload.slug is required"
        try:
            runtime_info = self._embedded_ensure_runtime_for_instance(slug_norm)
        except Exception as exc:
            return False, {"slug": slug_norm}, f"failed to prepare .NET runtime for instance '{slug_norm}': {exc}"
        base = f"SS14.Watchdog-{slug_norm}"
        candidates: list[str] = [
            base,
            f"{base}.service",
            f"ss14-watchdog-{slug_norm}",
            f"ss14-watchdog-{slug_norm}.service",
        ]
        extra = self._embedded_guess_watchdog_services(base)
        for item in extra:
            name = str(item or "").strip()
            if name and name not in candidates:
                candidates.append(name)
        errors: list[str] = []
        for unit in candidates:
            logger.info(
                "Executing instruction id=%s kind=%s slug=%s via systemctl restart %s",
                instruction_id,
                kind,
                slug_norm,
                unit,
            )
            try:
                proc = subprocess.run(
                    ["systemctl", "restart", unit],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except Exception as exc:
                errors.append(f"{unit}: {exc}")
                continue
            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if proc.returncode != 0:
                errors.append(f"{unit}: rc={proc.returncode} out={output[-600:] if output else '-'}")
                continue
            active = "unknown"
            try:
                active_proc = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                active = str((active_proc.stdout or "").strip() or (active_proc.stderr or "").strip() or "unknown")
            except Exception:
                pass
            return (
                True,
                {
                    "status_code": 200,
                    "service": unit,
                    "service_active": active,
                    "command": f"systemctl restart {unit}",
                    "runtime": runtime_info,
                },
                None,
            )
        tail = " | ".join(errors[-4:]) if errors else "no candidates"
        return False, {"service_candidates": candidates}, f"watchdog systemd restart failed: {tail}"

    def _execute_watchdog_service_stop(
        self,
        *,
        instruction_id: str,
        kind: str,
        slug: str,
    ) -> tuple[bool, dict[str, Any], str | None]:
        slug_norm = str(slug or "").strip().lower()
        if not slug_norm:
            return False, {}, "payload.slug is required"
        base = f"SS14.Watchdog-{slug_norm}"
        candidates: list[str] = [
            base,
            f"{base}.service",
            f"ss14-watchdog-{slug_norm}",
            f"ss14-watchdog-{slug_norm}.service",
        ]
        extra = self._embedded_guess_watchdog_services(base)
        for item in extra:
            name = str(item or "").strip()
            if name and name not in candidates:
                candidates.append(name)
        errors: list[str] = []
        for unit in candidates:
            logger.info(
                "Executing instruction id=%s kind=%s slug=%s via systemctl stop %s",
                instruction_id,
                kind,
                slug_norm,
                unit,
            )
            try:
                proc = subprocess.run(
                    ["systemctl", "stop", unit],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except Exception as exc:
                errors.append(f"{unit}: {exc}")
                continue
            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if proc.returncode != 0:
                errors.append(f"{unit}: rc={proc.returncode} out={output[-600:] if output else '-'}")
                continue
            active = "unknown"
            try:
                active_proc = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                active = str((active_proc.stdout or "").strip() or (active_proc.stderr or "").strip() or "unknown")
            except Exception:
                pass
            return (
                True,
                {
                    "status_code": 200,
                    "service": unit,
                    "service_active": active,
                    "command": f"systemctl stop {unit}",
                },
                None,
            )
        tail = " | ".join(errors[-4:]) if errors else "no candidates"
        return False, {"service_candidates": candidates}, f"watchdog systemd stop failed: {tail}"

    def _execute_instruction(self, item: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        kind = str(item.get("kind") or "").strip().lower()
        payload = item.get("payload") or {}
        if kind == "ping":
            return True, {"pong": True, "ts": time.time()}, None
        if kind == "set-poll-seconds":
            try:
                new_value = int(payload.get("seconds"))
                if new_value < 1:
                    raise ValueError("seconds must be >= 1")
                self.poll_seconds = new_value
                return True, {"poll_seconds": self.poll_seconds}, None
            except Exception as exc:
                return False, {}, str(exc)
        if kind == "refresh-config":
            cfg, cfg_sha = self._read_config()
            if self.api_token:
                self._register(cfg, cfg_sha)
            self.status["config_sha256"] = cfg_sha
            return True, {"config_sha256": cfg_sha}, None
        if kind == "run-diagnostic":
            timeout_seconds = int(payload.get("timeout_seconds") or self.diagnostic_timeout)
            return self._run_diagnostic(str(payload.get("name") or ""), timeout_seconds=timeout_seconds)
        if kind == "get-watchdog-logs":
            return self._get_watchdog_logs(payload if isinstance(payload, dict) else {})
        if kind == "install-watchdog":
            return False, {}, "install-watchdog is disabled; use fixed instruction kinds only"
        if kind == "self-update-agent":
            return self._run_self_update(payload if isinstance(payload, dict) else {})
        if kind == "create-slug":
            return self._run_create_slug(payload if isinstance(payload, dict) else {})
        if kind == "get-instance-config":
            return self._embedded_get_instance_config(str(payload.get("slug") or ""))
        if kind == "set-instance-config":
            return self._embedded_set_instance_config(
                str(payload.get("slug") or ""),
                str(payload.get("content") or ""),
            )
        if kind == "get-instance-update-policy":
            return self._embedded_get_instance_update_policy(str(payload.get("slug") or ""))
        if kind == "set-instance-update-policy":
            return self._embedded_set_instance_update_policy(
                str(payload.get("slug") or ""),
                str(payload.get("update_mode") or ""),
                str(payload.get("manifest_url") or "").strip() or None,
                str(payload.get("repo") or "").strip() or None,
                str(payload.get("branch") or "").strip() or None,
            )
        if kind == "get-instance-database":
            return self._embedded_get_instance_database(str(payload.get("slug") or ""))
        if kind == "set-instance-database":
            return self._embedded_set_instance_database_mode(
                str(payload.get("slug") or ""),
                str(payload.get("mode") or ""),
            )
        if kind == "reset-instance-sqlite":
            return self._embedded_reset_instance_sqlite(
                str(payload.get("slug") or ""),
                delete_database=bool(payload.get("delete_database")),
                delete_data=bool(payload.get("delete_data")),
            )
        if kind == "list-instance-data":
            return self._embedded_list_instance_data(
                str(payload.get("slug") or ""),
                str(payload.get("path") or ""),
            )
        if kind == "download-instance-data-file":
            return self._embedded_download_instance_data_file(
                str(payload.get("slug") or ""),
                str(payload.get("path") or ""),
            )
        if kind == "upload-instance-data-file":
            return self._embedded_upload_instance_data_file(
                str(payload.get("slug") or ""),
                path=str(payload.get("path") or ""),
                filename=str(payload.get("filename") or ""),
                content_base64=str(payload.get("content_base64") or ""),
            )
        if kind in {"restart-instance", "update-instance", "stop-instance"}:
            instruction_id = str(item.get("id") or "").strip() or "-"
            slug = str(payload.get("slug") or "").strip()
            if kind == "restart-instance":
                ok, result, error = self._execute_watchdog_service_restart(
                    instruction_id=instruction_id,
                    kind=kind,
                    slug=slug,
                )
            elif kind == "update-instance":
                ok, result, error = self._execute_watchdog_http_action(
                    instruction_id=instruction_id,
                    kind=kind,
                    slug=slug,
                    action="update",
                )
                runtime_info = (result or {}).get("runtime") if isinstance(result, dict) else None
                if ok and isinstance(runtime_info, dict) and bool(runtime_info.get("installed")):
                    restart_ok, restart_result, restart_error = self._execute_watchdog_service_restart(
                        instruction_id=instruction_id,
                        kind="restart-instance",
                        slug=slug,
                    )
                    if not restart_ok:
                        merged = dict(result or {})
                        merged["runtime_restart_error"] = restart_error
                        merged["runtime_restart_result"] = restart_result
                        return False, merged, f"watchdog update succeeded and .NET runtime was installed, but restart failed: {restart_error}"
                    merged = dict(result or {})
                    merged["runtime_restart"] = restart_result
                    return True, merged, None
            else:
                ok, result, error = self._execute_watchdog_http_action(
                    instruction_id=instruction_id,
                    kind=kind,
                    slug=slug,
                    action="stop",
                    reason=str(payload.get("reason") or "").strip() or None,
                )
            if ok:
                return True, result, None
            if kind == "stop-instance" and _env_bool("AGENT_WATCHDOG_STOP_SYSTEMCTL_FALLBACK", True):
                stop_ok, stop_result, stop_error = self._execute_watchdog_service_stop(
                    instruction_id=instruction_id,
                    kind=kind,
                    slug=slug,
                )
                if stop_ok:
                    merged = dict(stop_result or {})
                    merged["fallback"] = "systemctl-stop"
                    merged["watchdog_http_error"] = error
                    merged["watchdog_http_result"] = result
                    logger.warning(
                        "Instruction id=%s kind=%s slug=%s direct watchdog HTTP failed; systemctl stop fallback succeeded",
                        instruction_id,
                        kind,
                        slug or "-",
                    )
                    return True, merged, None
                logger.warning(
                    "Instruction id=%s kind=%s slug=%s direct watchdog HTTP failed; systemctl stop fallback also failed: %s result=%s",
                    instruction_id,
                    kind,
                    slug or "-",
                    str(stop_error or "-"),
                    _log_tail(stop_result or {}),
                )
            logger.warning(
                "Instruction id=%s kind=%s slug=%s direct watchdog path failed; fallback to local API. error=%s result=%s",
                instruction_id,
                kind,
                slug or "-",
                str(error or "-"),
                _log_tail(result or {}),
            )
        if kind in {
            "create-instance",
            "delete-instance",
            "restart-instance",
            "stop-instance",
            "update-instance",
            "repair-instance",
        }:
            local_api = self.local_api_url or _default_local_api_url()
            token = _local_api_token(self)
            endpoints = {
                "create-instance": ("POST", "/api/ss14/instances"),
                "delete-instance": ("DELETE", f"/api/ss14/instances/{payload.get('slug', '')}"),
                "restart-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/restart"),
                "stop-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/stop"),
                "update-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/update"),
                "repair-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/repair"),
                "get-instance-update-policy": ("GET", f"/api/ss14/admin/instances/{payload.get('slug', '')}/update-policy"),
                "set-instance-update-policy": ("POST", f"/api/ss14/admin/instances/{payload.get('slug', '')}/update-policy"),
            }
            method, path = endpoints[kind]
            if kind != "create-instance" and not str(payload.get("slug") or "").strip():
                return False, {}, "payload.slug is required"
            url = f"{local_api}{path}"
            headers = {"X-API-Token": token or "", "Content-Type": "application/json"}
            kwargs: dict[str, Any] = {"headers": headers, "timeout": self.timeout}
            if kind == "create-instance":
                kwargs["json"] = payload.get("body") or {}
            elif kind == "set-instance-update-policy":
                kwargs["json"] = {
                    "update_mode": str(payload.get("update_mode") or "").strip(),
                    "manifest_url": (str(payload.get("manifest_url") or "").strip() or None),
                    "repo": (str(payload.get("repo") or "").strip() or None),
                    "branch": (str(payload.get("branch") or "").strip() or None),
                }
            elif kind == "stop-instance":
                reason = str(payload.get("reason") or "").strip()
                if reason:
                    headers["X-Reason"] = reason
            instruction_id = str(item.get("id") or "").strip() or "-"
            slug = str(payload.get("slug") or "").strip() or "-"
            logger.info(
                "Executing instruction id=%s kind=%s slug=%s via %s %s",
                instruction_id,
                kind,
                slug,
                method,
                url,
            )
            try:
                res = requests.request(method, url, **kwargs)
            except requests.RequestException as exc:
                logger.error(
                    "Instruction id=%s kind=%s slug=%s request failed url=%s error=%s",
                    instruction_id,
                    kind,
                    slug,
                    url,
                    exc,
                )
                return False, {"local_api": local_api}, f"local edge API is unreachable at {local_api}: {exc}"
            ok = res.status_code < 400
            data: Any
            try:
                data = res.json()
            except Exception:
                data = {"raw": (res.text or "")[-3000:]}
            logger.info(
                "Instruction id=%s kind=%s slug=%s local API response status=%s body=%s",
                instruction_id,
                kind,
                slug,
                res.status_code,
                _log_tail(data),
            )
            if (
                ok
                and isinstance(data, dict)
                and bool(data.get("remote_managed"))
                and isinstance(data.get("instruction"), dict)
            ):
                msg = (
                    "local API returned remote-dispatch payload instead of local execution; "
                    "check AGENT_LOCAL_API_URL (expected local edge API)"
                )
                logger.error(
                    "Instruction id=%s kind=%s slug=%s rejected as non-local result: %s",
                    instruction_id,
                    kind,
                    slug,
                    _log_tail(data),
                )
                return (
                    False,
                    {"status_code": res.status_code, "response": data, "local_api": local_api, "url": url},
                    msg,
                )
            if ok:
                if kind == "update-instance":
                    try:
                        self._embedded_reconcile_watchdog_services()
                    except Exception:
                        logger.exception("watchdog service reconcile after update-instance failed")
                return True, {"status_code": res.status_code, "response": data}, None
            logger.warning(
                "Instruction id=%s kind=%s slug=%s local API failed status=%s body=%s",
                instruction_id,
                kind,
                slug,
                res.status_code,
                _log_tail(data),
            )
            return False, {"status_code": res.status_code, "response": data}, "local api call failed"
        return False, {}, f"unsupported instruction kind: {kind}"

    def loop(self) -> None:
        while not self._stop.is_set():
            cycle_error: str | None = None
            sleep_seconds = float(self.poll_seconds)
            self._cycle_seq += 1
            cycle_seq = int(self._cycle_seq)
            cycle_started_at = time.time()
            cycle_started_monotonic = time.monotonic()
            self.status["loop_cycle_seq"] = cycle_seq
            self.status["last_cycle_started_at"] = cycle_started_at
            logger.info(
                "Agent loop cycle start seq=%s poll_seconds=%s wait_seconds=%s heartbeat_seconds=%s paired=%s has_runtime_token=%s",
                cycle_seq,
                self.poll_seconds,
                self.instruction_wait_seconds,
                self.heartbeat_seconds,
                bool(self.status.get("paired")),
                bool(self.agent_token),
            )
            try:
                if not self.agent_token:
                    if not self.status.get("claim_code"):
                        self._enroll_request()
                    self._enroll_complete()
                cfg, cfg_sha = self._read_config()
                if not self.agent_token and self.api_token and not self._legacy_auth_disabled and not self.status.get("registered"):
                    self._register(cfg, cfg_sha)
                elif (
                    (not self.agent_token)
                    and self.api_token
                    and (not self._legacy_auth_disabled)
                    and self.status.get("config_sha256") != cfg_sha
                ):
                    # Re-register when config changed.
                    self._register(cfg, cfg_sha)
                if self._heartbeat_due():
                    self._heartbeat(cfg_sha)
                if self._config_sync_due():
                    try:
                        self._sync_config_snapshots()
                    except Exception as exc:
                        self.status["last_config_snapshot_error"] = str(exc)
                        logger.exception("Config snapshot sync failed")
                if self._watchdog_log_sync_due():
                    try:
                        self._sync_watchdog_logs()
                    except Exception as exc:
                        self.status["last_watchdog_log_sync_error"] = str(exc)
                        logger.exception("Watchdog log sync failed")
                items, next_poll_seconds = self._pull()
                self.status["last_instruction_count"] = len(items)
                sleep_seconds = float(next_poll_seconds if not items else 0.0)
                logger.info(
                    "Agent loop cycle pull result seq=%s instruction_count=%s next_poll_seconds=%s sleep_seconds=%s",
                    cycle_seq,
                    len(items),
                    next_poll_seconds,
                    sleep_seconds,
                )
                for item in items:
                    instruction_id = str(item.get("id") or "")
                    instruction_kind = str(item.get("kind") or "").strip().lower() or None
                    logger.info(
                        "Instruction received id=%s kind=%s status=%s execution_state=%s stage=%s delivery_count=%s leased_at=%s lease_expires_at=%s status_message=%s payload=%s",
                        instruction_id or "-",
                        instruction_kind or "-",
                        str(item.get("status") or "-"),
                        str(item.get("execution_state") or "-"),
                        str(item.get("stage") or "-"),
                        int(item.get("delivery_count") or 0),
                        str(item.get("leased_at") if item.get("leased_at") is not None else "-"),
                        str(item.get("lease_expires_at") if item.get("lease_expires_at") is not None else "-"),
                        str(item.get("status_message") or "-"),
                        _log_tail((item or {}).get("payload") or {}),
                    )
                    self.status["last_instruction_id"] = instruction_id or None
                    self.status["last_instruction_kind"] = instruction_kind
                    self.status["last_instruction_at"] = time.time()
                    if instruction_id:
                        try:
                            self._progress(
                                instruction_id,
                                execution_state="accepted",
                                stage="accepted",
                                message="instruction accepted by agent",
                            )
                        except Exception:
                            logger.exception("Instruction progress update failed stage=accepted id=%s", instruction_id)
                    try:
                        instruction_started_monotonic = time.monotonic()
                        if instruction_id:
                            try:
                                self._progress(
                                    instruction_id,
                                    execution_state="running",
                                    stage="running",
                                    message="instruction execution started",
                                )
                            except Exception:
                                logger.exception("Instruction progress update failed stage=running id=%s", instruction_id)
                        ok, result, error = self._execute_instruction(item)
                    except Exception as exc:
                        ok, result, error = False, {}, str(exc)
                    instruction_elapsed_ms = (time.monotonic() - instruction_started_monotonic) * 1000.0
                    if instruction_id and instruction_kind in {"get-instance-config", "set-instance-config"}:
                        try:
                            self._progress(
                                instruction_id,
                                execution_state="completed" if ok else "failed",
                                stage="result",
                                message=(None if ok else (str(error or "").strip() or "instruction failed")),
                                result=result or None,
                            )
                            logger.info(
                                "Instruction terminal progress sent kind=%s id=%s ok=%s",
                                instruction_kind,
                                instruction_id,
                                ok,
                            )
                        except Exception:
                            logger.exception(
                                "Instruction terminal progress failed kind=%s id=%s",
                                instruction_kind,
                                instruction_id,
                            )
                    self.status["last_instruction_ok"] = bool(ok)
                    self.status["last_instruction_error"] = error
                    self.status["last_instruction_result"] = result or {}
                    logger.info(
                        "Instruction finished id=%s kind=%s ok=%s duration_ms=%.1f error=%s result=%s",
                        instruction_id or "-",
                        instruction_kind or "-",
                        bool(ok),
                        instruction_elapsed_ms,
                        str(error or "") or "-",
                        _log_tail(result or {}),
                    )
                    if error:
                        cycle_error = error
                    if ok and instruction_kind in {"create-slug", "create-instance"}:
                        self._next_config_sync_at = 0.0
                        self._next_watchdog_log_sync_at = 0.0
                    if instruction_id:
                        try:
                            self._ack(
                                instruction_id,
                                ok=ok,
                                result=result,
                                error=error,
                                instruction_kind=instruction_kind,
                            )
                            logger.info(
                                "Instruction ack sent id=%s kind=%s ok=%s",
                                instruction_id,
                                instruction_kind or "-",
                                bool(ok),
                            )
                        except Exception:
                            logger.exception(
                                "Instruction ack failed id=%s kind=%s",
                                instruction_id,
                                instruction_kind or "-",
                            )
                self.status["last_error"] = cycle_error
            except Exception as exc:
                if isinstance(exc, HTTPError) and getattr(exc, "response", None) is not None:
                    response = exc.response
                    request_url = getattr(getattr(exc, "request", None), "url", None)
                    self.status["last_error"] = f"{response.status_code} {response.reason}: {request_url or ''}".strip()
                    logger.warning(
                        "Agent loop cycle failed seq=%s http_status=%s reason=%s url=%s",
                        cycle_seq,
                        response.status_code,
                        response.reason,
                        request_url or "-",
                    )
                else:
                    self.status["last_error"] = str(exc)
                    logger.exception("Agent loop cycle failed seq=%s", cycle_seq)
                sleep_seconds = float(self.poll_seconds)
            cycle_duration_ms = (time.monotonic() - cycle_started_monotonic) * 1000.0
            self.status["last_cycle_completed_at"] = time.time()
            self.status["last_cycle_duration_ms"] = round(cycle_duration_ms, 3)
            self.status["last_cycle_sleep_seconds"] = max(0.0, float(sleep_seconds))
            logger.info(
                "Agent loop cycle end seq=%s duration_ms=%.1f sleep_seconds=%s last_error=%s",
                cycle_seq,
                cycle_duration_ms,
                max(0.0, float(sleep_seconds)),
                str(self.status.get("last_error") or "-"),
            )
            self._stop.wait(max(0.0, sleep_seconds))

    def start(self) -> None:
        if self.test_mode:
            self.status["last_error"] = None
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self.loop, name="fabricator-agent", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)


runtime = AgentRuntime()
app = FastAPI(title="Fabricator Agent", version=AGENT_VERSION_DISPLAY)


class DiagnosticRunRequest(BaseModel):
    name: str
    timeout_seconds: int | None = None


@app.on_event("startup")
def on_startup() -> None:
    runtime.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    runtime.stop()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": runtime.status.get("last_error") is None, "error": runtime.status.get("last_error")}


@app.get("/status")
def status() -> dict[str, Any]:
    http_port_raw = _env("AGENT_HTTP_PORT", "8010") or "8010"
    try:
        http_port = int(http_port_raw)
    except Exception:
        http_port = 8010
    status_payload = dict(runtime.status)
    registered_runtime = bool(runtime.agent_token)
    registered_legacy = bool(status_payload.get("last_register_at"))
    status_payload["registered_runtime"] = registered_runtime
    status_payload["registered_legacy"] = registered_legacy
    status_payload["registered"] = bool(registered_runtime or registered_legacy)

    return {
        "agent_id": runtime.agent_id,
        "backend_url": runtime.backend_url,
        "poll_seconds": runtime.poll_seconds,
        "instruction_wait_seconds": runtime.instruction_wait_seconds,
        "heartbeat_seconds": runtime.heartbeat_seconds,
        "config_sync_seconds": runtime.config_sync_seconds,
        "runtime_pid": os.getpid(),
        "http_port": http_port,
        "config_path": str(runtime.config_path),
        "app": _build_info(),
        "supported_instruction_kinds": runtime.supported_instruction_kinds(),
        "diagnostics": sorted(runtime._diagnostic_specs().keys()),
        "status": status_payload,
    }


@app.get("/version")
def version() -> dict[str, Any]:
    return _build_info()


@app.get("/instructions")
def instructions() -> dict[str, Any]:
    return {"supported_instruction_kinds": runtime.supported_instruction_kinds()}


@app.get("/diagnostics")
def diagnostics() -> dict[str, Any]:
    return {"diagnostics": sorted(runtime._diagnostic_specs().keys())}


@app.post("/diagnostics/run")
def run_diagnostic(
    body: DiagnosticRunRequest,
    x_agent_admin_token: str | None = Header(None, alias="X-Agent-Admin-Token"),
) -> dict[str, Any]:
    runtime._require_admin_token(x_agent_admin_token)
    ok, result, error = runtime._run_diagnostic(body.name, timeout_seconds=body.timeout_seconds)
    return {"ok": ok, "result": result, "error": error}
