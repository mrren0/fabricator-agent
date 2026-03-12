"""Lightweight remote agent for fabricator.

The agent reads local config.toml, registers itself on the core backend and
long-polls for instructions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import pwd
import grp
import secrets
import shlex
import shutil
import socket
import subprocess
import threading
import time
import uuid
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
    return (
        "if [ -d /root/fabricator-agent/.git ]; then "
        "cd /root/fabricator-agent && git fetch --all --prune && git checkout main && "
        "git pull --ff-only origin main && bash scripts/remote_deploy.sh /root/fabricator-agent; "
        "elif [ -d /opt/fabricator-agent-src/.git ]; then "
        "cd /opt/fabricator-agent-src && git fetch --all --prune && git checkout main && "
        "git pull --ff-only origin main && bash scripts/remote_deploy.sh /opt/fabricator-agent-src; "
        "else "
        "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade fabricator-agent; "
        "fi"
    )


def _detached_popen(cmd: str, *, env: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        ["/bin/sh", "-lc", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        env=env,
        text=True,
        start_new_session=True,
    )


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
        self.diagnostic_timeout = int(_env("AGENT_DIAG_TIMEOUT_SECONDS", "45") or "45")
        self.output_tail_chars = int(_env("AGENT_OUTPUT_TAIL_CHARS", "4000") or "4000")
        self.fabricator_service_name = _env("AGENT_FABRICATOR_SERVICE", "ss14-provisioner") or "ss14-provisioner"
        self._legacy_auth_disabled = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status: dict[str, Any] = {
            "registered": False,
            "last_error": None,
            "last_register_at": None,
            "last_heartbeat_at": None,
            "last_pull_at": None,
            "last_instruction_count": 0,
            "last_instruction_id": None,
            "last_instruction_kind": None,
            "last_instruction_at": None,
            "last_instruction_ok": None,
            "last_instruction_error": None,
            "last_instruction_result": None,
            "config_sha256": None,
            "claim_code": None,
            "paired": False,
            "legacy_auth_disabled": False,
            "last_diagnostic_name": None,
            "last_diagnostic_at": None,
            "last_diagnostic_ok": None,
            "mode": "test-local" if self.test_mode else "runtime",
        }
        self._load_token_file()

    @staticmethod
    def supported_instruction_kinds() -> list[str]:
        return [
            "ping",
            "set-poll-seconds",
            "refresh-config",
            "run-diagnostic",
            "self-update-agent",
            "create-slug",
            "create-instance",
            "delete-instance",
            "restart-instance",
            "stop-instance",
            "update-instance",
            "repair-instance",
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

    def _read_config(self) -> tuple[dict[str, Any] | None, str | None]:
        if not self.config_path.exists():
            return None, None
        raw = self.config_path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        parsed = tomllib.loads(raw.decode("utf-8", errors="ignore"))
        return parsed, sha

    def _register(self, cfg: dict[str, Any] | None, cfg_sha: str | None) -> None:
        if not self.api_token or self._legacy_auth_disabled:
            return
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "location": self.location,
            "config_path": str(self.config_path),
            "config_sha256": cfg_sha,
            "config": cfg,
            "capabilities": ["config.toml", "heartbeat", "instruction-pull"],
            "tags": [],
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

    def _heartbeat(self, cfg_sha: str | None) -> None:
        if self.agent_token:
            payload = {
                "status": "ok",
                "config_sha256": cfg_sha,
                "metrics": {},
                "details": {
                    "public_ip": self.public_ip or None,
                    "agent_version": APP_VERSION,
                    "agent_version_full": AGENT_VERSION_DISPLAY,
                    "agent_version_base": APP_VERSION,
                    "agent_build": AGENT_BUILD,
                    "agent_installed_at": AGENT_INSTALLED_AT,
                },
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
            return

        # Legacy mode: heartbeat is available only with AGENT_API_TOKEN/SS14_API_TOKEN.
        if not self.api_token or self._legacy_auth_disabled:
            return

        payload = {
            "agent_id": self.agent_id,
            "status": "ok",
            "config_sha256": cfg_sha,
            "metrics": {},
            "details": {
                "public_ip": self.public_ip or None,
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

    def _pull(self) -> list[dict[str, Any]]:
        if self.agent_token:
            res = requests.get(
                f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions",
                params={"limit": 25},
                headers=self._runtime_headers(),
                timeout=self.timeout,
            )
            if res.status_code == 401:
                self._invalidate_runtime_token("Runtime token rejected while pulling; re-enrolling")
                return []
            res.raise_for_status()
            data = res.json() if res.content else {}
            self.status["last_pull_at"] = time.time()
            items = data.get("instructions") or []
            self.status["last_instruction_count"] = len(items)
            return items

        # Legacy mode: pull is available only with AGENT_API_TOKEN/SS14_API_TOKEN.
        if not self.api_token or self._legacy_auth_disabled:
            return []

        res = requests.get(
            f"{self.backend_url}/api/agent/instructions/{self.agent_id}",
            params={"limit": 25},
            headers=self._headers(),
            timeout=self.timeout,
        )
        if res.status_code == 401:
            self._legacy_auth_disabled = True
            self.status["legacy_auth_disabled"] = True
            return []
        res.raise_for_status()
        data = res.json() if res.content else {}
        self.status["last_pull_at"] = time.time()
        items = data.get("instructions") or []
        self.status["last_instruction_count"] = len(items)
        return items

    def _ack(self, instruction_id: str, ok: bool, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        if self.agent_token:
            res = requests.post(
                f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions/{instruction_id}/ack",
                json={"ok": bool(ok), "result": result or {}, "error": error},
                headers=self._runtime_headers(),
                timeout=self.timeout,
            )
            if res.status_code == 401:
                self._invalidate_runtime_token("Runtime token rejected while ack; re-enrolling")
                return
            res.raise_for_status()
            return
        if self._legacy_auth_disabled:
            return
        res = requests.post(
            f"{self.backend_url}/api/agent/instructions/{self.agent_id}/{instruction_id}/ack",
            json={"ok": bool(ok), "result": result or {}, "error": error},
            headers=self._headers(),
            timeout=self.timeout,
        )
        if res.status_code == 401:
            self._legacy_auth_disabled = True
            self.status["legacy_auth_disabled"] = True
            return
        res.raise_for_status()

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
        res = requests.post(
            f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions/{instruction_id}/progress",
            json={
                "execution_state": str(execution_state or "").strip().lower(),
                "stage": str(stage or "").strip().lower() or None,
                "message": str(message or "").strip() or None,
                "result": result or None,
            },
            headers=self._runtime_headers(),
            timeout=self.timeout,
        )
        if res.status_code == 401:
            self._invalidate_runtime_token("Runtime token rejected while sending progress; re-enrolling")
            return
        res.raise_for_status()

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

    def _run_self_update(self, payload: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        payload_command = str(payload.get("command") or "").strip()
        cmd = payload_command or (
            _env(
                "AGENT_SELF_UPDATE_COMMAND",
                _default_self_update_command(),
            )
            or ""
        ).strip()
        if not cmd:
            return False, {}, "AGENT_SELF_UPDATE_COMMAND is empty"
        if "restart" in payload:
            restart_enabled = bool(payload.get("restart"))
        else:
            restart_enabled = _env_bool("AGENT_SELF_UPDATE_RESTART", True)
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
            try:
                proc = _detached_popen(cmd, env=env)
            except Exception as exc:
                return False, {}, f"failed to start detached self-update: {exc}"
            return (
                True,
                {
                    "mode": "detached",
                    "pid": int(proc.pid),
                    "command": cmd,
                    "restart": True,
                    "source_repo": env["FABRICATOR_AGENT_SOURCE_REPO"] or None,
                    "source_branch": env["FABRICATOR_AGENT_SOURCE_BRANCH"] or None,
                    "target_version": env["FABRICATOR_AGENT_TARGET_VERSION"] or None,
                    "target_build": env["FABRICATOR_AGENT_TARGET_BUILD"] or None,
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

    def _embedded_allocate_port(self, requested_port: int, instances_dir: Path, fragments_dir: Path) -> int:
        try:
            port_min = int(_env("SS14_PORT_MIN", "1212") or "1212")
            port_max = int(_env("SS14_PORT_MAX", "2211") or "2211")
        except Exception as exc:
            raise RuntimeError(f"invalid SS14_PORT_MIN/SS14_PORT_MAX: {exc}")

        if requested_port not in (0, 1):
            if not self._embedded_is_port_free(requested_port):
                raise RuntimeError(f"Port {requested_port} is already in use")
            return requested_port

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
        for port in range(port_min, port_max + 1):
            if port in used_ports:
                continue
            if self._embedded_is_port_free(port):
                return port
        raise RuntimeError(f"No free ports available in range {port_min}..{port_max}")

    def _embedded_allocate_watchdog_port(self, requested_port: int, dedicated_base: Path, template_root: Path) -> int:
        try:
            port_min = int(_env("SS14_WD_PORT_MIN", "8000") or "8000")
            port_max = int(_env("SS14_WD_PORT_MAX", "8999") or "8999")
        except Exception as exc:
            raise RuntimeError(f"invalid SS14_WD_PORT_MIN/SS14_WD_PORT_MAX: {exc}")

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

        if requested_port not in (0, 1):
            if requested_port in used_ports or not self._embedded_is_port_free(requested_port):
                raise RuntimeError(f"Watchdog port {requested_port} is already in use")
            return requested_port

        for port in range(port_min, port_max + 1):
            if port in used_ports:
                continue
            if self._embedded_is_port_free(port):
                return port
        raise RuntimeError(f"No free watchdog ports available in range {port_min}..{port_max}")

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

    def _embedded_ensure_service_account(self, user: str, group: str, home: Path) -> None:
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
            pwd.getpwnam(user)
        except KeyError:
            subprocess.run(
                [
                    "useradd",
                    "--system",
                    "--no-create-home",
                    "--home-dir",
                    str(home),
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

    def _embedded_ensure_dotnet_sdk(self, required_versions: list[str] | None = None) -> list[str]:
        preferred = Path(_env("SS14_DOTNET", "/opt/dotnet/dotnet") or "/opt/dotnet/dotnet")
        try:
            existing = self._embedded_dotnet_command()
        except RuntimeError:
            existing = [str(preferred)]
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
        unit_name = str(service_name or "").strip() or "ss14-watchdog.service"
        if not unit_name.endswith(".service"):
            unit_name = f"{unit_name}.service"
        try:
            exec_parts = self._embedded_find_watchdog_command(wd_root)
        except RuntimeError:
            exec_parts = self._embedded_install_watchdog(wd_root)
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
        if dotnet_root:
            env_block = (
                f"Environment=DOTNET_ROOT={dotnet_root}\n"
                f"Environment=DOTNET_ROOT_X64={dotnet_root}\n"
            )
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
            "Restart=always\n"
            "RestartSec=5\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        unit_path.write_text(unit_body, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
        subprocess.run(["systemctl", "enable", unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
        return unit_name

    def _embedded_restart_watchdog(self, service_name: str, wd_root: Path, user: str, group: str) -> str:
        errors: list[str] = []
        explicit = str(service_name or "").strip()
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
            watchdog_port = self._embedded_allocate_watchdog_port(explicit_watchdog_port, dedicated_base, template_root)
        except Exception as exc:
            return False, {}, str(exc)
        watchdog_url = f"http://127.0.0.1:{int(watchdog_port)}"
        watchdog_service = _env("SS14_WD_SYSTEMD_SERVICE", f"SS14.Watchdog-{slug}") or f"SS14.Watchdog-{slug}"
        wd_fs_user = _env("SS14_WD_FS_USER") or _env("SS14_WD_USER") or "ss14"
        wd_fs_group = _env("SS14_WD_FS_GROUP") or _env("SS14_WD_GROUP") or wd_fs_user

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

        if wd_root.exists():
            return False, {"watchdog_root": str(wd_root)}, f"Watchdog root for instance '{slug}' already exists"
        if inst_dir.exists():
            return False, {"dir_path": str(inst_dir)}, f"Directory for instance '{slug}' already exists"
        if frag_file.exists():
            return False, {"fragment_path": str(frag_file)}, f"Watchdog fragment for instance '{slug}' already exists"

        api_token = secrets.token_hex(8)
        server_url = _build_server_url(public_host, slug, port)
        udp_host = public_host or "127.0.0.1"
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
            f"address = \"http://127.0.0.1:3100\"\n"
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
                return True, result, None
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
        if kind == "install-watchdog":
            return False, {}, "install-watchdog is disabled; use fixed instruction kinds only"
        if kind == "self-update-agent":
            return self._run_self_update(payload if isinstance(payload, dict) else {})
        if kind == "create-slug":
            return self._run_create_slug(payload if isinstance(payload, dict) else {})
        if kind in {
            "create-instance",
            "delete-instance",
            "restart-instance",
            "stop-instance",
            "update-instance",
            "repair-instance",
        }:
            local_api = _default_local_api_url()
            token = _local_api_token(self)
            endpoints = {
                "create-instance": ("POST", "/api/ss14/instances"),
                "delete-instance": ("DELETE", f"/api/ss14/instances/{payload.get('slug', '')}"),
                "restart-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/restart"),
                "stop-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/stop"),
                "update-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/update"),
                "repair-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/repair"),
            }
            method, path = endpoints[kind]
            if kind != "create-instance" and not str(payload.get("slug") or "").strip():
                return False, {}, "payload.slug is required"
            url = f"{local_api}{path}"
            headers = {"X-API-Token": token or "", "Content-Type": "application/json"}
            kwargs: dict[str, Any] = {"headers": headers, "timeout": self.timeout}
            if kind == "create-instance":
                kwargs["json"] = payload.get("body") or {}
            elif kind == "stop-instance":
                reason = str(payload.get("reason") or "").strip()
                if reason:
                    headers["X-Reason"] = reason
            try:
                res = requests.request(method, url, **kwargs)
            except requests.RequestException as exc:
                return False, {"local_api": local_api}, f"local edge API is unreachable at {local_api}: {exc}"
            ok = res.status_code < 400
            data: Any
            try:
                data = res.json()
            except Exception:
                data = {"raw": (res.text or "")[-3000:]}
            if ok:
                return True, {"status_code": res.status_code, "response": data}, None
            return False, {"status_code": res.status_code, "response": data}, "local api call failed"
        return False, {}, f"unsupported instruction kind: {kind}"

    def loop(self) -> None:
        while not self._stop.is_set():
            cycle_error: str | None = None
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
                self._heartbeat(cfg_sha)
                items = self._pull()
                self.status["last_instruction_count"] = len(items)
                for item in items:
                    instruction_id = str(item.get("id") or "")
                    instruction_kind = str(item.get("kind") or "").strip().lower() or None
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
                    self.status["last_instruction_ok"] = bool(ok)
                    self.status["last_instruction_error"] = error
                    self.status["last_instruction_result"] = result or {}
                    if error:
                        cycle_error = error
                    if instruction_id:
                        self._ack(instruction_id, ok=ok, result=result, error=error)
                self.status["last_error"] = cycle_error
            except Exception as exc:
                if isinstance(exc, HTTPError) and getattr(exc, "response", None) is not None:
                    response = exc.response
                    request_url = getattr(getattr(exc, "request", None), "url", None)
                    self.status["last_error"] = f"{response.status_code} {response.reason}: {request_url or ''}".strip()
                else:
                    self.status["last_error"] = str(exc)
            self._stop.wait(self.poll_seconds)

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
