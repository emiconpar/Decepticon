"""Utility modules for the Decepticon contract layer.

Pure stdlib + pydantic helpers — config loaders, logging setup. Imported
by the framework (``decepticon.core.config``, ``decepticon.core.logging``
shims) and freely usable by plugin authors.
"""

from __future__ import annotations

from decepticon_core.utils import config, logging

__all__ = ["config", "logging"]
