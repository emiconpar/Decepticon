"""LangGraph Platform graph registry — OSS built-ins merged with plugins.

LangGraph Platform expects a graph manifest (``langgraph.json``) or the
``LANGSERVE_GRAPHS`` environment variable mapping each graph name to a
``module:attr`` path. Decepticon's built-in agents are listed in the
``langgraph.json`` shipped with the repo. External packages add their own
agents by declaring entry-points in the ``decepticon.agents`` group.

This module produces a merged manifest at runtime so external plugins
(e.g. a SaaS plugin package shipped separately) can extend the available
graphs without editing ``langgraph.json``.

Typical usage in a container startup script:

    LANGSERVE_GRAPHS="$(python -m decepticon.graph_registry)" \\
        langgraph dev --host 0.0.0.0 --port 2024
"""

from __future__ import annotations

import json

from decepticon.plugin_loader import load_plugin_agents

# Built-in graphs — kept in sync with ``langgraph.json``. When you add a
# graph inside OSS, update both. External packages MUST use entry-points
# in the ``decepticon.agents`` group rather than editing this list.
BUILTIN_GRAPHS: dict[str, str] = {
    "decepticon": "./decepticon/agents/decepticon.py:graph",
    "recon": "./decepticon/agents/recon.py:graph",
    "soundwave": "./decepticon/agents/soundwave.py:graph",
    "exploit": "./decepticon/agents/exploit.py:graph",
    "postexploit": "./decepticon/agents/postexploit.py:graph",
    "analyst": "./decepticon/agents/analyst.py:graph",
    "reverser": "./decepticon/agents/reverser.py:graph",
    "contract_auditor": "./decepticon/agents/contract_auditor.py:graph",
    "cloud_hunter": "./decepticon/agents/cloud_hunter.py:graph",
    "ad_operator": "./decepticon/agents/ad_operator.py:graph",
    "vulnresearch": "./decepticon/agents/vulnresearch.py:graph",
    "scanner": "./decepticon/agents/scanner.py:graph",
    "detector": "./decepticon/agents/detector.py:graph",
    "verifier": "./decepticon/agents/verifier.py:graph",
    "patcher": "./decepticon/agents/patcher.py:graph",
    "exploiter": "./decepticon/agents/exploiter.py:graph",
}


def build_langserve_graphs() -> dict[str, str]:
    """Return ``{name: module:graph}`` merged across OSS + discovered plugins.

    Plugin-contributed agents override built-in entries on name collision —
    callers should treat the result as authoritative.
    """
    merged: dict[str, str] = dict(BUILTIN_GRAPHS)
    merged.update(load_plugin_agents())
    return merged


def emit_langserve_env() -> str:
    """Serialize the merged manifest as compact JSON for ``LANGSERVE_GRAPHS``."""
    return json.dumps(build_langserve_graphs(), separators=(",", ":"))


def main() -> None:
    """CLI entry: print the merged graph manifest as JSON to stdout."""
    print(emit_langserve_env())


if __name__ == "__main__":
    main()
