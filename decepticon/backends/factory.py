"""Backend factory — HTTP-transport sandbox builder.

The agent code shouldn't know how the sandbox is deployed; it just asks
for a sandbox object. ``build_sandbox_backend()`` returns an
``HTTPSandbox`` that talks to a sandbox daemon over HTTP, which works in
every deployment target Decepticon supports today:

  - Dev / local-docker: sandbox container exposes the FastAPI daemon
    on ``localhost:9999``.
  - GCE Spot VMs (SaaS silo plane): same — sandbox sibling container on
    the VM, daemon reachable on loopback.
  - Cloud Run (SaaS pool plane): sandbox runs as a sidecar in the same
    Cloud Run revision, reachable on ``localhost:9999`` via the shared
    network namespace.

Earlier versions of this factory had a ``DECEPTICON_FILESYSTEM_BACKEND``
env switch picking between DockerSandbox (``docker exec`` transport) and
HTTPSandbox. The DockerSandbox path required a docker socket on the host
which is a security concern in some environments and outright impossible
on Cloud Run. Consolidating on HTTP keeps a single tested code path
across all targets — and the daemon now exposes the full agent API
(``execute``, ``execute_tmux``, ``start_background``, file IO, ...) so
every agent role can use it.

DockerSandbox is retained in ``decepticon/backends/docker_sandbox.py``
for backward-compat / direct test use, but production agent factories
should always go through ``build_sandbox_backend`` (or the higher-level
``make_agent_backend`` wrapper in ``decepticon/backends/__init__.py``).
"""

from __future__ import annotations

import os

from decepticon.backends.http_sandbox import HTTPSandbox


def build_sandbox_backend(container_name: str):
    """Build the HTTP-transport sandbox backend.

    Args:
        container_name: kept for API compatibility with the legacy
            DockerSandbox-driven factory signature so call sites can
            pass it unconditionally. HTTPSandbox routes via URL, not
            container name, so the value is otherwise unused.

    Returns:
        An ``HTTPSandbox`` instance pointed at the daemon URL.

    Env:
        SAAS_SANDBOX_URL
            Base URL of the sandbox daemon. Default
            ``http://localhost:9999`` (sibling-container / sidecar
            loopback).
        SAAS_SANDBOX_TOKEN
            Optional bearer token for daemon auth — recommended even on
            loopback as defence-in-depth.
    """
    base_url = os.environ.get("SAAS_SANDBOX_URL", "http://localhost:9999")
    token = os.environ.get("SAAS_SANDBOX_TOKEN") or None
    return HTTPSandbox(base_url=base_url, token=token)
