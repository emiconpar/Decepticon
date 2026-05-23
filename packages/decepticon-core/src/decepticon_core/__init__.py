"""decepticon-core — contract layer for the Decepticon agent framework.

Pure types, protocols, plugin contracts, and registry primitives. This
package never imports ``langchain``, ``langgraph``, ``deepagents``,
``httpx``, or ``fastapi`` — see the umbrella spec at
``docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md``
for the design rationale.

Phase 0 skeleton: this module ships only the version sentinel. Phase 1
(per the spec) extracts ``types``, ``protocols``, ``contracts``,
``registry``, and ``utils`` from the framework package.
"""

from __future__ import annotations

__version__ = "0.0.0"

__all__ = ["__version__"]
