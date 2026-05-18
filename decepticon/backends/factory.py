"""Backend factory — env-driven selection between DockerSandbox and HTTPSandbox.

The agent code shouldn't know how it's deployed; it just asks for a backend.
Today's call sites instantiate `DockerSandbox(container_name=...)` directly,
which only works when there's a host docker daemon and a sibling sandbox
container — perfect for dev / local-docker / GCE Spot VMs, broken on
Cloud Run multi-container deployments where docker exec is impossible.

`build_sandbox_backend()` lets the operator pick the transport via
`DECEPTICON_FILESYSTEM_BACKEND`:

  - ``docker`` (default): existing behaviour, no change for dev / silo plane.
  - ``http``: HTTPSandbox talking to a sandbox daemon — used on Cloud Run
    pool plane where the daemon runs as a sibling container reachable on
    ``http://localhost:9999``.

Pool-plane agents (Soundwave + the Decepticon orchestrator) use only file
IO, which BaseSandbox derives from `execute()`. They are the agents that
benefit from this factory. Silo-plane sub-agents (recon/exploit/...) call
DockerSandbox's tmux/background-job extensions that aren't in
BaseSandbox, so they should stay on `docker` for now.

The factory is intentionally cheap to call — no caching, no validation
beyond the env switch — so every agent factory can call it on instantiation
without coordinating singletons.
"""

from __future__ import annotations

import os

from decepticon.backends.docker_sandbox import DockerSandbox
from decepticon.backends.http_sandbox import HTTPSandbox


def build_sandbox_backend(container_name: str):
    """Build a sandbox backend appropriate for the current deploy target.

    Args:
        container_name: Name of the dev-/silo-plane sibling sandbox
            container. Used by DockerSandbox to know which container to
            ``docker exec`` into. Ignored by HTTPSandbox, which routes
            via URL instead — but accepted in the signature so call
            sites can pass it unconditionally.

    Returns:
        A `DockerSandbox` (default) or `HTTPSandbox` instance.

    Env:
        DECEPTICON_FILESYSTEM_BACKEND
            ``docker`` (default) or ``http``. Anything else falls back
            to ``docker`` so a typo doesn't silently route traffic
            somewhere unexpected.
        SAAS_SANDBOX_URL
            HTTP-only. Base URL of the sandbox daemon. Default
            ``http://localhost:9999`` (Cloud Run sibling loopback).
        SAAS_SANDBOX_TOKEN
            HTTP-only. Shared bearer token. Optional, but recommended
            even on loopback as defence-in-depth.
    """
    kind = (os.environ.get("DECEPTICON_FILESYSTEM_BACKEND") or "docker").strip().lower()
    if kind == "http":
        base_url = os.environ.get("SAAS_SANDBOX_URL", "http://localhost:9999")
        token = os.environ.get("SAAS_SANDBOX_TOKEN") or None
        return HTTPSandbox(base_url=base_url, token=token)
    return DockerSandbox(container_name=container_name)
