"""Plugin loader contract tests.

The plugin loader is the OSS↔SaaS extension surface. These tests pin its
behavior so future refactors don't silently break the contract external
plugin packages depend on.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from decepticon import plugin_loader


class _FakeEntryPoint:
    """Stand-in for ``importlib.metadata.EntryPoint`` used in tests."""

    def __init__(self, name: str, value: str, loaded):
        self.name = name
        self.value = value
        self._loaded = loaded

    def load(self):
        return self._loaded


def test_empty_discovery_returns_empty():
    """No entry-points → empty list/dict, no exception."""
    with patch.object(plugin_loader, "entry_points", return_value=[]):
        assert plugin_loader.load_plugin_tools() == []
        assert plugin_loader.load_plugin_middleware() == []
        assert plugin_loader.load_plugin_callbacks() == []
        assert plugin_loader.load_plugin_agents() == {}


def test_list_export_passes_through():
    """A plugin exporting a list is returned as-is (list is not callable)."""
    tool_a = MagicMock(invoke=MagicMock())
    tool_b = MagicMock(invoke=MagicMock())
    ep = _FakeEntryPoint("my-tools", "my_pkg:TOOLS", [tool_a, tool_b])
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_plugin_tools(role="recon")
    assert result == [tool_a, tool_b]


def test_factory_export_is_called_with_role_and_deps():
    """A non-runtime callable export is invoked with role + dep kwargs."""
    captured: dict = {}

    def factory(*, role=None, backend=None):
        captured["role"] = role
        captured["backend"] = backend
        return [MagicMock(invoke=MagicMock())]

    ep = _FakeEntryPoint("my-factory", "my_pkg:factory", factory)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_plugin_tools(role="exploit", backend="sentinel")

    assert captured == {"role": "exploit", "backend": "sentinel"}
    assert len(result) == 1


def test_single_runtime_object_is_wrapped_in_list():
    """A single tool instance (callable but has runtime attrs) is wrapped."""
    tool = MagicMock(invoke=MagicMock())  # passes the runtime-object heuristic
    ep = _FakeEntryPoint("single", "my_pkg:tool", tool)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        assert plugin_loader.load_plugin_tools() == [tool]


def test_broken_load_is_logged_and_skipped(caplog):
    """A plugin that raises in ``.load()`` is skipped; siblings still load."""

    class BrokenEP:
        name = "broken"
        value = "broken_pkg:thing"

        def load(self):
            raise RuntimeError("boom")

    good = MagicMock(invoke=MagicMock())
    eps = [BrokenEP(), _FakeEntryPoint("good", "good:thing", good)]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        with caplog.at_level("ERROR", logger="decepticon.plugin_loader"):
            result = plugin_loader.load_plugin_tools()

    assert result == [good]
    assert any("broken" in record.getMessage() for record in caplog.records)


def test_broken_factory_call_is_logged_and_skipped(caplog):
    """A factory that raises at invocation time is skipped; siblings load."""

    def broken_factory(**kwargs):
        raise RuntimeError("nope")

    good_obj = MagicMock(invoke=MagicMock())
    eps = [
        _FakeEntryPoint("broken-factory", "pkg:f", broken_factory),
        _FakeEntryPoint("good", "pkg:t", good_obj),
    ]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        with caplog.at_level("ERROR", logger="decepticon.plugin_loader"):
            result = plugin_loader.load_plugin_tools()

    assert result == [good_obj]
    assert any("broken-factory" in record.getMessage() for record in caplog.records)


def test_load_plugin_agents_normalizes_to_module_graph():
    """Plugin agent entry-points are normalized to ``module:graph`` paths."""

    class EP:
        def __init__(self, name, value):
            self.name = name
            self.value = value

    eps = [
        EP("compliance", "my_pkg.agents.compliance:create_agent"),
        EP("audit", "my_pkg.agents.audit"),  # module-only form
    ]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        result = plugin_loader.load_plugin_agents()

    assert result == {
        "compliance": "my_pkg.agents.compliance:graph",
        "audit": "my_pkg.agents.audit:graph",
    }


def test_none_result_from_factory_is_dropped():
    """A factory returning None doesn't pollute the output list."""

    def factory(**kwargs):
        return None

    ep = _FakeEntryPoint("noop", "pkg:f", factory)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        assert plugin_loader.load_plugin_tools() == []
