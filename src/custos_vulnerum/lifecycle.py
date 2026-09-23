"""Docker Compose lifecycle for lab projects (up/down/status/logs/readiness)."""

from __future__ import annotations

import json
import subprocess  # nosec B404 - docker argv is static, never shell-interpreted
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

import httpx

from .catalog import LoadedLab
from .errors import LifecycleError

Variant = Literal["vulnerable", "mitigated"]

_COMPOSE_TIMEOUT = 300.0
_READY_TIMEOUT = 120.0


def _as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


@dataclass(frozen=True)
class PortBinding:
    """One published port binding observed on a container."""

    container_port: str
    host_ip: str
    host_port: str


@dataclass(frozen=True)
class ContainerInfo:
    """A container of a lab compose project, as observed via docker inspect."""

    id: str
    name: str
    service: str
    labels: dict[str, str] = field(default_factory=dict)
    bindings: tuple[PortBinding, ...] = ()


class LabEnvironment:
    """One compose project variant (vulnerable or mitigated) of a lab."""

    def __init__(self, lab: LoadedLab, variant: Variant) -> None:
        self.lab = lab
        self.variant = variant
        self.mitigated = variant == "mitigated"
        suffix = "-mit" if self.mitigated else ""
        self.project = f"{lab.meta.compose.project}{suffix}"
        self.compose_file = lab.compose_file(self.mitigated)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.lab.meta.compose.port}"

    # -- compose plumbing ---------------------------------------------------

    def _compose(self, *args: str, timeout: float = _COMPOSE_TIMEOUT) -> str:
        cmd = [
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            str(self.compose_file),
            *args,
        ]
        try:
            proc = subprocess.run(  # nosec B603, B607 - static argv, no shell
                cmd,
                cwd=self.lab.directory,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise LifecycleError("docker CLI not found; install Docker to run labs") from exc
        except subprocess.TimeoutExpired as exc:
            raise LifecycleError(f"`{' '.join(cmd)}` timed out after {timeout:.0f}s") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise LifecycleError(f"`{' '.join(cmd)}` failed (exit {proc.returncode}): {detail}")
        return proc.stdout

    def up(self) -> None:
        self._compose("up", "-d", "--remove-orphans", timeout=_COMPOSE_TIMEOUT)

    def down(self) -> None:
        self._compose("down", "-v", "--remove-orphans", timeout=_COMPOSE_TIMEOUT)

    def is_running(self) -> bool:
        return bool(self.containers())

    # -- observation --------------------------------------------------------

    def containers(self) -> list[ContainerInfo]:
        """Running containers of this project with labels and port bindings."""
        out = self._compose("ps", "-q", timeout=60.0)
        ids = [line.strip() for line in out.splitlines() if line.strip()]
        if not ids:
            return []
        try:
            proc = subprocess.run(  # nosec B603, B607 - static argv, no shell
                ["docker", "inspect", *ids],
                capture_output=True,
                text=True,
                timeout=60.0,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise LifecycleError(f"docker inspect failed: {exc}") from exc
        if proc.returncode != 0:
            raise LifecycleError(f"docker inspect failed: {proc.stderr.strip()}")
        infos = json.loads(proc.stdout)
        return [self._to_container_info(item) for item in infos]

    @staticmethod
    def _to_container_info(item: dict[str, object]) -> ContainerInfo:
        config = _as_dict(item.get("Config"))
        host_config = _as_dict(item.get("HostConfig"))
        labels = {str(k): str(v) for k, v in _as_dict(config.get("Labels")).items()}
        bindings: list[PortBinding] = []
        port_bindings = _as_dict(host_config.get("PortBindings"))
        for container_port, entries in port_bindings.items():
            for entry in _as_list(entries):
                entry_map = _as_dict(entry)
                bindings.append(
                    PortBinding(
                        container_port=str(container_port),
                        host_ip=str(entry_map.get("HostIp") or ""),
                        host_port=str(entry_map.get("HostPort") or ""),
                    )
                )
        name = str(item.get("Name") or "").lstrip("/")
        service = labels.get("com.docker.compose.service", "")
        return ContainerInfo(
            id=str(item.get("Id") or "")[:12],
            name=name,
            service=service,
            labels=labels,
            bindings=tuple(bindings),
        )

    def logs(self, service: str, since: datetime | None = None) -> str:
        """Container logs for one service, optionally only since a timestamp (UTC)."""
        args = ["logs", "--no-color", "--timestamps"]
        if since is not None:
            moment = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")
            args += ["--since", moment]
        args.append(service)
        try:
            return self._compose(*args, timeout=60.0)
        except LifecycleError:
            return ""

    def wait_ready(self, timeout: float = _READY_TIMEOUT) -> None:
        """Poll the lab's loopback URL until any HTTP response arrives."""
        import time

        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with httpx.Client(timeout=2.0, trust_env=False) as client:
                    client.get(f"{self.base_url}/")
                return
            except httpx.HTTPError as exc:
                last_error = exc
                time.sleep(1.0)
        raise LifecycleError(
            f"{self.base_url} did not answer within {timeout:.0f}s (last error: {last_error})"
        )


def environments(lab: LoadedLab) -> dict[Variant, LabEnvironment]:
    """Both variants of a lab, keyed by variant name."""
    return {
        "vulnerable": LabEnvironment(lab, "vulnerable"),
        "mitigated": LabEnvironment(lab, "mitigated"),
    }
