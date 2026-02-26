"""Lightweight remote agent for fabricator.

The agent reads local config.toml, registers itself on the core backend and
long-polls for instructions.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import threading
import time
import tomllib
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


class AgentRuntime:
    def __init__(self) -> None:
        self.backend_url = (_env("AGENT_BACKEND_URL", "http://127.0.0.1:8000") or "").rstrip("/")
        self.api_token = _env("AGENT_API_TOKEN") or _env("SS14_API_TOKEN")
        self.agent_token = _env("AGENT_TOKEN")
        self.agent_id = _env("AGENT_ID", socket.gethostname()) or socket.gethostname()
        self.hostname = socket.gethostname()
        self.location = _env("AGENT_LOCATION")
        self.config_path = Path(_env("AGENT_CONFIG_PATH", "./config.toml") or "./config.toml")
        self.public_key = _env("AGENT_PUBLIC_KEY")
        self.token_file = Path(_env("AGENT_TOKEN_FILE", "./agent.token") or "./agent.token")
        self.poll_seconds = int(_env("AGENT_POLL_SECONDS", "10") or "10")
        self.timeout = int(_env("AGENT_HTTP_TIMEOUT_SECONDS", "10") or "10")
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
        }
        self._load_token_file()

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

    def _read_config(self) -> tuple[dict[str, Any] | None, str | None]:
        if not self.config_path.exists():
            return None, None
        raw = self.config_path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        parsed = tomllib.loads(raw.decode("utf-8", errors="ignore"))
        return parsed, sha

    def _register(self, cfg: dict[str, Any] | None, cfg_sha: str | None) -> None:
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
                "details": {},
            }
            res = requests.post(
                f"{self.backend_url}/api/agent/runtime/{self.agent_id}/heartbeat",
                json=payload,
                headers=self._runtime_headers(),
                timeout=self.timeout,
            )
            res.raise_for_status()
            self.status["last_heartbeat_at"] = time.time()
            self.status["paired"] = True
            return

        payload = {
            "agent_id": self.agent_id,
            "status": "ok",
            "config_sha256": cfg_sha,
            "metrics": {},
            "details": {},
        }
        res = requests.post(
            f"{self.backend_url}/api/agent/heartbeat",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
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
            res.raise_for_status()
            data = res.json() if res.content else {}
            self.status["last_pull_at"] = time.time()
            items = data.get("instructions") or []
            self.status["last_instruction_count"] = len(items)
            return items

        res = requests.get(
            f"{self.backend_url}/api/agent/instructions/{self.agent_id}",
            params={"limit": 25},
            headers=self._headers(),
            timeout=self.timeout,
        )
        res.raise_for_status()
        data = res.json() if res.content else {}
        self.status["last_pull_at"] = time.time()
        items = data.get("instructions") or []
        self.status["last_instruction_count"] = len(items)
        return items

    def _ack(self, instruction_id: str, ok: bool, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        if self.agent_token:
            requests.post(
                f"{self.backend_url}/api/agent/runtime/{self.agent_id}/instructions/{instruction_id}/ack",
                json={"ok": bool(ok), "result": result or {}, "error": error},
                headers=self._runtime_headers(),
                timeout=self.timeout,
            ).raise_for_status()
            return
        requests.post(
            f"{self.backend_url}/api/agent/instructions/{self.agent_id}/{instruction_id}/ack",
            json={"ok": bool(ok), "result": result or {}, "error": error},
            headers=self._headers(),
            timeout=self.timeout,
        ).raise_for_status()

    def _enroll_request(self) -> None:
        payload = {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "hostname": self.hostname,
            "details": {"location": self.location},
        }
        res = requests.post(
            f"{self.backend_url}/api/agent/enroll/request",
            json=payload,
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
        if res.status_code in (400, 409):
            # Not bound yet or invalid state: keep polling.
            return False
        res.raise_for_status()
        data = res.json() if res.content else {}
        token = str(data.get("agent_token") or "").strip()
        if not token:
            return False
        self.agent_token = token
        self.status["paired"] = True
        self._save_token_file()
        return True

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
        if kind == "install-watchdog":
            cmd = str(payload.get("command") or os.getenv("AGENT_WATCHDOG_INSTALL_CMD") or "").strip()
            if not cmd:
                return False, {}, "install command is not provided (payload.command or AGENT_WATCHDOG_INSTALL_CMD)"
            timeout = int(payload.get("timeout_seconds") or 1800)
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            ok = proc.returncode == 0
            result = {
                "returncode": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-3000:],
                "stderr_tail": (proc.stderr or "")[-3000:],
            }
            return ok, result, None if ok else "watchdog install command failed"
        if kind in {"create-instance", "delete-instance", "restart-instance", "stop-instance", "update-instance"}:
            local_api = (_env("AGENT_LOCAL_API_URL", "http://127.0.0.1:8000") or "").rstrip("/")
            token = _env("AGENT_LOCAL_API_TOKEN") or self.api_token
            endpoints = {
                "create-instance": ("POST", "/api/ss14/instances"),
                "delete-instance": ("DELETE", f"/api/ss14/instances/{payload.get('slug', '')}"),
                "restart-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/restart"),
                "stop-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/stop"),
                "update-instance": ("POST", f"/api/ss14/instances/{payload.get('slug', '')}/update"),
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
                if not self.agent_token and self.api_token and not self.status.get("registered"):
                    self._register(cfg, cfg_sha)
                elif (not self.agent_token) and self.api_token and self.status.get("config_sha256") != cfg_sha:
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
                self.status["last_error"] = str(exc)
            self._stop.wait(self.poll_seconds)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self.loop, name="fabricator-agent", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)


runtime = AgentRuntime()
app = FastAPI(title="Fabricator Agent", version="0.1.0")


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
    return {
        "agent_id": runtime.agent_id,
        "backend_url": runtime.backend_url,
        "poll_seconds": runtime.poll_seconds,
        "config_path": str(runtime.config_path),
        "status": dict(runtime.status),
    }
