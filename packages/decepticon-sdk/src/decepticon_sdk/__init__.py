"""decepticon-sdk — plugin author entrypoint for the Decepticon framework.

Re-exports the ``decepticon-core`` contracts, ships pytest fixtures
under ``decepticon_sdk.testing``, and provides a scaffolding CLI for
creating plugin packages.

Phase 0 skeleton: this module ships only the version sentinel. Phase 3
(per the design spec) implements the re-exports, fixtures, and
``decepticon-sdk plugin new`` CLI.
"""

from __future__ import annotations

__version__ = "0.0.0"

__all__ = ["__version__"]
