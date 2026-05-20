"""Plugin discovery for Decepticon.

Decepticon supports adding tools, middleware, agents, and callback handlers
without modifying the OSS codebase. External packages declare their
contributions via Python entry-points; agent factories pick them up at
construction time.

Entry-point groups (declared by the consuming package's pyproject.toml):

    [project.entry-points."decepticon.tools"]
    my-tools = "my_pkg.tools:get_tools"

    [project.entry-points."decepticon.middleware"]
    my-mw = "my_pkg.middleware:get_middleware"

    [project.entry-points."decepticon.agents"]
    my-agent = "my_pkg.agents.my_agent"

    [project.entry-points."decepticon.callbacks"]
    my-cb = "my_pkg.callbacks:get_callbacks"

The exported object can be:
  - a ``list``/``tuple`` of items — returned as-is.
  - a callable factory accepting kwargs — called with ``role=<role>`` plus
    any dependency kwargs (e.g. ``backend``); its return value is treated
    as a list.
  - a single runtime instance (tool / middleware / callback) — wrapped in
    a one-element list.

A plugin that raises on load is logged and skipped; the agent factory
falls back to OSS-only behavior. This keeps OSS robust against plugin
bugs and absent plugin environments (pure OSS users see no behavior change).
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

logger = logging.getLogger(__name__)

TOOLS_GROUP = "decepticon.tools"
MIDDLEWARE_GROUP = "decepticon.middleware"
AGENTS_GROUP = "decepticon.agents"
CALLBACKS_GROUP = "decepticon.callbacks"

# Attributes that distinguish a Tool/Middleware/Callback INSTANCE from a
# factory callable. If any of these are present we treat the object as a
# runtime object and skip the "call it as a factory" branch.
_RUNTIME_ATTRS = (
    "invoke",
    "args_schema",
    "before_agent",
    "modify_request",
    "after_agent",
    "on_llm_start",
    "on_tool_start",
)


def _looks_like_runtime_object(obj: Any) -> bool:
    """Heuristic — separate a runtime instance from a factory callable."""
    return any(hasattr(obj, attr) for attr in _RUNTIME_ATTRS)


def _discover(group: str, role: str | None, **deps: Any) -> list[Any]:
    """Discover entry-point contributions for one group."""
    found: list[Any] = []
    try:
        eps = list(entry_points(group=group))
    except Exception:  # pragma: no cover — importlib quirks across versions
        logger.exception("plugin discovery failed for group %s", group)
        return found

    for ep in eps:
        try:
            obj = ep.load()
        except Exception:
            logger.exception("failed to load plugin %s from group %s", ep.name, group)
            continue

        try:
            if callable(obj) and not _looks_like_runtime_object(obj):
                result = obj(role=role, **deps)
            else:
                result = obj
        except Exception:
            logger.exception("failed to invoke plugin factory %s in group %s", ep.name, group)
            continue

        if isinstance(result, (list, tuple)):
            found.extend(result)
        elif result is not None:
            found.append(result)

    return found


def load_plugin_tools(role: str | None = None, **deps: Any) -> list[Any]:
    """Discover tools contributed by external packages.

    Args:
        role: the agent role requesting tools (e.g. ``"recon"``). Plugins
            may use this to scope which tools they contribute.
        **deps: dependency keyword args forwarded to factory plugins
            (commonly ``backend``).
    """
    return _discover(TOOLS_GROUP, role=role, **deps)


def load_plugin_middleware(role: str | None = None, **deps: Any) -> list[Any]:
    """Discover middleware contributed by external packages.

    Args:
        role: the agent role requesting middleware.
        **deps: typically includes ``backend`` so middleware that needs
            sandbox access can be constructed correctly.
    """
    return _discover(MIDDLEWARE_GROUP, role=role, **deps)


def load_plugin_callbacks(role: str | None = None, **deps: Any) -> list[Any]:
    """Discover LangChain callback handlers contributed by external packages."""
    return _discover(CALLBACKS_GROUP, role=role, **deps)


def load_plugin_agents() -> dict[str, str]:
    """Discover agent graph entry-points.

    Returns a mapping of ``agent_name`` → ``module:graph`` paths suitable
    for LangGraph Platform's ``LANGSERVE_GRAPHS`` env or ``langgraph.json``.
    Plugin agent modules MUST expose a module-level ``graph`` attribute,
    matching how OSS agents are wired (``decepticon/agents/recon.py:graph``).
    """
    found: dict[str, str] = {}
    try:
        eps = list(entry_points(group=AGENTS_GROUP))
    except Exception:  # pragma: no cover
        logger.exception("plugin discovery failed for group %s", AGENTS_GROUP)
        return found

    for ep in eps:
        module = ep.value.split(":", 1)[0]
        found[ep.name] = f"{module}:graph"

    return found
