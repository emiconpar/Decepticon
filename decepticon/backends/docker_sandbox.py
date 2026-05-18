"""Agent-side `BaseSandbox` backed by `docker exec` into a sibling container.

Everything except the `docker cp` file-transfer pair is delegated to
``decepticon.sandbox_kernel.base.SandboxBase`` — the shared implementation
class that holds the tmux session management, background-job tracking,
log-offset diff, and the rest of the surface ``BaseSandbox`` consumers
expect.

This split makes the sandbox image free of agent-side transport code:
the daemon (``decepticon.sandbox_server``) imports ``LocalSandbox`` from
``sandbox_kernel.local`` and never sees ``DockerSandbox``. The
``backends/`` package stays an agent-only namespace, mirroring the
pre-refactor boundary where the sandbox image shipped zero decepticon
Python and the langgraph image owned the docker client surface.

Public re-exports
-----------------
The old (pre-refactor) public surface — ``TmuxSessionManager``,
``BackgroundJob``, ``BackgroundJobTracker``, ``PS1_PATTERN``, etc. —
is re-exported here so existing imports
``from decepticon.backends.docker_sandbox import TmuxSessionManager``
(tests, bash tool, OPPLAN middleware) keep working without churn.
"""

from __future__ import annotations

import functools
import io
import logging
import os
import subprocess
import tarfile
import tempfile
import threading
from typing import ClassVar

from deepagents.backends.protocol import (
    FileDownloadResponse,
    FileUploadResponse,
)

from decepticon.sandbox_kernel import (
    AUTO_BACKGROUND_SECONDS,
    MAX_OUTPUT_CHARS,
    POLL_INTERVAL,
    PS1_PATTERN,
    SIZE_WATCHDOG_CHARS,
    SIZE_WATCHDOG_INTERVAL,
    STALL_SECONDS,
    BackgroundJob,
    BackgroundJobTracker,
    TmuxCommandError,
    TmuxSessionManager,
)
from decepticon.sandbox_kernel.base import SandboxBase

# Private helpers — also moved to sandbox_kernel.tmux but re-exported
# here because the existing test suite imports them directly from this
# module. Keeps the test surface stable across the refactor.

__all__ = [
    "AUTO_BACKGROUND_SECONDS",
    "BackgroundJob",
    "BackgroundJobTracker",
    "DockerSandbox",
    "MAX_OUTPUT_CHARS",
    "POLL_INTERVAL",
    "PS1_PATTERN",
    "SIZE_WATCHDOG_CHARS",
    "SIZE_WATCHDOG_INTERVAL",
    "STALL_SECONDS",
    "TmuxCommandError",
    "TmuxSessionManager",
    "check_sandbox_running",
]

log = logging.getLogger("decepticon.backends.docker_sandbox")


@functools.lru_cache(maxsize=1)
def _docker_cfg():
    """Lazy-load DockerConfig to avoid import-time side effects."""
    from decepticon.core.config import load_config

    return load_config().docker


class DockerSandbox(SandboxBase):
    """Agent-side sandbox: shells into a sibling container via ``docker exec``.

    The bulk of the behaviour lives in :class:`SandboxBase`; this class
    just supplies the docker-specific file-transfer pair (``upload_files``
    via ``docker cp``, ``download_files`` via ``docker cp -``) and the
    standard ``docker exec`` command prefix.

    Each subclass redeclares its own ``_jobs`` and ``_log_offsets``
    ClassVars so SandboxNotificationMiddleware's
    ``getattr(sandbox, "_jobs")`` lookup pulls the subclass-specific
    tracker rather than a shared base singleton.
    """

    _jobs: ClassVar[BackgroundJobTracker] = BackgroundJobTracker()
    _log_offsets: ClassVar[dict[str, int]] = {}
    _log_offsets_lock: ClassVar[threading.RLock] = threading.RLock()

    def __init__(
        self,
        container_name: str = "decepticon-sandbox",
        default_timeout: int = 120,
        workspace_path: str = "/workspace",
        exec_prefix: list[str] | None = None,
    ) -> None:
        # When None, fall back to the canonical `docker exec <ctn>` prefix;
        # passing an explicit empty list flips this into "local mode" for
        # tests that want to drive SandboxBase logic without a docker daemon.
        super().__init__(
            container_name=container_name,
            default_timeout=default_timeout,
            workspace_path=workspace_path,
            exec_prefix=(
                list(exec_prefix) if exec_prefix is not None else ["docker", "exec", container_name]
            ),
        )

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        responses: list[FileUploadResponse] = []
        for path, content in files:
            if not path.startswith("/"):
                responses.append(FileUploadResponse(path=path, error="invalid_path"))
                continue
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            try:
                result = subprocess.run(
                    ["docker", "cp", tmp_path, f"{self._container_name}:{path}"],
                    capture_output=True,
                )
                error = None if result.returncode == 0 else "file_not_found"
            finally:
                os.unlink(tmp_path)
            responses.append(FileUploadResponse(path=path, error=error))
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        responses: list[FileDownloadResponse] = []
        for path in paths:
            if not path.startswith("/"):
                responses.append(
                    FileDownloadResponse(path=path, content=None, error="invalid_path")
                )
                continue
            result = subprocess.run(
                ["docker", "cp", f"{self._container_name}:{path}", "-"],
                capture_output=True,
            )
            if result.returncode != 0:
                responses.append(
                    FileDownloadResponse(path=path, content=None, error="file_not_found")
                )
                continue
            try:
                with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
                    member = tar.getmembers()[0]
                    f = tar.extractfile(member)
                    file_bytes = f.read() if f else b""
                responses.append(FileDownloadResponse(path=path, content=file_bytes, error=None))
            except Exception:
                responses.append(
                    FileDownloadResponse(path=path, content=None, error="file_not_found")
                )
        return responses


def check_sandbox_running(container_name: str = "decepticon-sandbox") -> bool:
    """Check if the Docker sandbox container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "true"
    except Exception:
        return False
