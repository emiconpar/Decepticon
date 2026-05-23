"""Re-export shim — content moved to ``decepticon_core.plugin_loader``.

Phase 1.B of the core/framework/sdk split relocates plugin discovery
contracts into ``decepticon-core`` so plugin authors can import
``PluginBundle`` and ``SubAgentSpec`` without the framework runtime.
Phase 2 (framework retrofit) rewrites every internal call site to
import from ``decepticon_core.plugin_loader`` directly; this shim is
removed at 2.0.0 per spec §7.3.

See ``docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md``.
"""

from __future__ import annotations

from decepticon_core.plugin_loader import *  # noqa: F401, F403
