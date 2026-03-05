"""Lightweight remote agent for fabricator.

The agent reads local config.toml, registers itself on the core backend and
long-polls for instructions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
import socket
import subprocess
import threading
import time
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any

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


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


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
        "version": AGENT_VERSION_DISPLAY,
        "version_base": APP_VERSION,
        "build": AGENT_BUILD,
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
                    "agent_version": AGENT_VERSION_DISPLAY,
                    "agent_build": AGENT_BUILD,
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
                "agent_version": AGENT_VERSION_DISPLAY,
                "agent_build": AGENT_BUILD,
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
                "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade fabricator-agent",
            )
            or ""
        ).strip()
        if not cmd:
            return False, {}, "AGENT_SELF_UPDATE_COMMAND is empty"
        timeout_seconds = int(_env("AGENT_SELF_UPDATE_TIMEOUT_SECONDS", "900") or "900")
        proc = subprocess.run(
            ["/bin/sh", "-lc", cmd],
            capture_output=True,
            text=True,
            timeout=max(10, timeout_seconds),
        )
        stdout_tail = (proc.stdout or "")[-self.output_tail_chars :]
        stderr_tail = (proc.stderr or "")[-self.output_tail_chars :]
        if proc.returncode != 0:
            return (
                False,
                {
                    "command": cmd,
                    "returncode": proc.returncode,
                    "stdout_tail": stdout_tail,
                    "stderr_tail": stderr_tail,
                },
                f"self-update failed with code {proc.returncode}",
            )

        if "restart" in payload:
            restart_enabled = bool(payload.get("restart"))
        else:
            restart_enabled = _env_bool("AGENT_SELF_UPDATE_RESTART", True)
        restart_scheduled = False
        restart_error = None
        if restart_enabled:
            try:
                subprocess.run(
                    ["/bin/sh", "-lc", "nohup /bin/sh -c 'sleep 2; systemctl restart fabricator-agent' >/dev/null 2>&1 &"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                restart_scheduled = True
            except Exception as exc:
                restart_error = str(exc)

        return (
            True,
            {
                "command": cmd,
                "returncode": 0,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "restart_enabled": restart_enabled,
                "restart_scheduled": restart_scheduled,
                "restart_error": restart_error,
            },
            None,
        )

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

        # Fallback for legacy setups: reuse local create-instance API.
        local_api = (_env("AGENT_LOCAL_API_URL", "http://127.0.0.1:8000") or "").rstrip("/")
        token = _env("AGENT_LOCAL_API_TOKEN") or self.api_token
        headers = {"X-API-Token": token or "", "Content-Type": "application/json"}
        res = requests.post(
            f"{local_api}/api/ss14/instances",
            json=body or {},
            headers=headers,
            timeout=self.timeout,
        )
        ok = res.status_code < 400
        try:
            data: Any = res.json()
        except Exception:
            data = {"raw": (res.text or "")[-3000:]}
        if ok:
            return True, {"status_code": res.status_code, "response": data, "fallback": "create-instance"}, None
        return False, {"status_code": res.status_code, "response": data}, "local api fallback failed"

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
            local_api = (_env("AGENT_LOCAL_API_URL", "http://127.0.0.1:8000") or "").rstrip("/")
            token = _env("AGENT_LOCAL_API_TOKEN") or self.api_token
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
            res = requests.request(method, url, **kwargs)
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
                for item in self._pull():
                    instruction_id = str(item.get("id") or "")
                    ok, result, error = self._execute_instruction(item)
                    if instruction_id:
                        self._ack(instruction_id, ok=ok, result=result, error=error)
                self.status["last_error"] = None
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
