"""Constitution I enforcement: loopback-only reachability, managed containers only.

Nothing in Custos Vulnerum sends traffic anywhere else. Every request is addressed to
``127.0.0.1`` on a port published by a lab container that this tool launched and
labelled. This module is the single gate in front of any network send.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .catalog import LoadedLab
from .errors import SafetyError
from .lifecycle import ContainerInfo, LabEnvironment

MANAGED_LABEL_PROJECT = "io.custos.project"
MANAGED_LABEL_LAB = "io.custos.lab"
MANAGED_PROJECT_VALUE = "vulnerum"

ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})


@dataclass(frozen=True)
class LabTarget:
    """The only legitimate PoC target: a managed lab's loopback endpoint."""

    lab_id: str
    variant: str
    base_url: str
    host: str
    port: int
    project: str


def assert_loopback_url(url: str) -> None:
    """Refuse any URL that does not target the loopback interface."""
    parsed = urlsplit(url)
    if parsed.scheme != "http":
        raise SafetyError(f"refusing non-HTTP scheme {parsed.scheme!r} in {url!r}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise SafetyError(f"refusing non-loopback target {parsed.hostname!r} in {url!r}")


def assert_managed(env: LabEnvironment) -> list[ContainerInfo]:
    """Verify the environment's containers are ours and reachable on loopback only.

    Checks, per running container:
    - ``io.custos.project`` label is ``vulnerum`` and ``io.custos.lab`` matches the lab;
    - every published port binding uses host IP ``127.0.0.1``/``localhost``;
    - the lab's configured port is actually published by one of them.
    """
    containers = env.containers()
    if not containers:
        raise SafetyError(
            f"lab {env.lab.id!r} ({env.variant}) is not running — "
            f"`custos lab up {env.lab.id}` first"
        )
    published_ports: set[str] = set()
    for container in containers:
        project_label = container.labels.get(MANAGED_LABEL_PROJECT)
        lab_label = container.labels.get(MANAGED_LABEL_LAB)
        if project_label != MANAGED_PROJECT_VALUE or lab_label != env.lab.id:
            raise SafetyError(
                f"container {container.name!r} is not a Custos Vulnerum container "
                f"({MANAGED_LABEL_PROJECT}={project_label!r}, "
                f"{MANAGED_LABEL_LAB}={lab_label!r}) — refusing"
            )
        for binding in container.bindings:
            if binding.host_ip not in ALLOWED_HOSTS and binding.host_ip != "":
                raise SafetyError(
                    f"container {container.name!r} publishes {binding.container_port} "
                    f"on {binding.host_ip}:{binding.host_port} — not loopback-only, refusing"
                )
            published_ports.add(binding.host_port)
    expected_port = str(env.lab.meta.compose.port)
    if expected_port not in published_ports:
        raise SafetyError(
            f"lab port {expected_port} is not published by managed containers of "
            f"project {env.project!r} — refusing"
        )
    return containers


def resolve_target(env: LabEnvironment) -> LabTarget:
    """Return the PoC target after passing the full safety gate."""
    lab: LoadedLab = env.lab
    host = "127.0.0.1"
    port = lab.meta.compose.port
    base_url = f"http://{host}:{port}"
    assert_loopback_url(base_url)
    assert_managed(env)
    return LabTarget(
        lab_id=lab.id,
        variant=env.variant,
        base_url=base_url,
        host=host,
        port=port,
        project=env.project,
    )
