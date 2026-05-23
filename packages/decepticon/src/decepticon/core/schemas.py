"""Re-export shim — content moved to ``decepticon_core.types.engagement``.

Phase 1 of the core/framework/sdk split relocates pure-pydantic types
into ``decepticon-core`` so plugin authors can depend on the contract
layer without dragging the framework runtime in. This shim keeps the
legacy import path working until Phase 2 rewrites every framework call
site to import directly from ``decepticon_core.types.engagement``.

Removed in the post-redesign ``2.0.0`` release (see spec §7.3).
See ``docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md``.
"""

from __future__ import annotations

from decepticon_core.types.engagement import *  # noqa: F401, F403
