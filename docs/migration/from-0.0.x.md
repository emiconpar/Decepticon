# Migration: `decepticon` 0.0.x → core/framework/sdk split

The Decepticon OSS package split into three coordinated wheels in the
post-0.0.x cycle. The redesign is documented in full at
[`docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md`](../superpowers/specs/2026-05-23-core-framework-sdk-split-design.md);
this guide is the consumer-facing migration list.

## What changed

```text
decepticon                         (was: monolithic wheel)
    │
    ├── decepticon-core            NEW — contract layer (pure types,
    │                                    protocols, registries, plugin
    │                                    contracts). Zero langchain /
    │                                    langgraph / deepagents runtime
    │                                    dependency.
    │
    ├── decepticon                 the opinionated framework (16 agent
    │                              factories, 11 middleware impls,
    │                              tools, LLM router, sandbox client).
    │                              Depends on decepticon-core.
    │
    └── decepticon-sdk             NEW — plugin author entrypoint.
                                   Re-exports the core public API +
                                   pytest fixtures + scaffolding CLI.
```

Pin-and-install advice:

| Consumer | Install | Why |
|----------|---------|-----|
| End-user running the stack | unchanged — Docker images bundle all three | identical UX |
| Library consumer (commercial product, downstream framework) | `pip install decepticon` | composes agents, ships custom bundles |
| Plugin author (community / commercial) | `pip install decepticon-sdk` | protocols + scaffolding + fixtures |
| Type-check-only context | `pip install decepticon-core` | zero runtime deps; cheapest pin |

## Import-path mapping

Every legacy path keeps working for one release via the Phase 1
shim layer. `decepticon.compat.register_legacy_imports()` runs at
import time of `decepticon` and emits a single `DeprecationWarning`
listing the table below so the migration list shows up in test logs.

Opt out of the warning with `DECEPTICON_NO_COMPAT=1` in the environment.

| Legacy path | Canonical path |
|-------------|----------------|
| `decepticon.core.schemas` | `decepticon_core.types.engagement` |
| `decepticon.llm.models` | `decepticon_core.types.llm` |
| `decepticon.tools.research.graph` | `decepticon_core.types.kg` |
| `decepticon.plugin_loader` | `decepticon_core.plugin_loader` |
| `decepticon.core.config` | `decepticon_core.utils.config` |
| `decepticon.core.logging` | `decepticon_core.utils.logging` |
| `decepticon.agents.middleware_slots.MiddlewareSlot` | `decepticon_core.contracts.slots.MiddlewareSlot` |
| `decepticon.agents.middleware_slots.SAFETY_CRITICAL_SLOTS` | `decepticon_core.contracts.slots.SAFETY_CRITICAL_SLOTS` |
| `decepticon.agents.middleware_slots.SLOTS_PER_ROLE` | `decepticon_core.contracts.slots.SLOTS_PER_ROLE` |

The framework's `decepticon.agents.middleware_slots` module keeps the
`DEFAULT_SLOT_FACTORIES` and `skills_sources_for()` exports (those
need langchain at import time, so they stay framework-side).

The shims are **removed at `2.0.0`** — migrate before then.

## New public surface for plugin authors

Plugin authors should import from `decepticon_sdk`:

```python
# One import covers protocols, contributions, registries, plugin
# loader contracts, and slot definitions. Spec §6.3 — the "single
# import line" promise of the SDK package.
from decepticon_sdk import (
    # Runtime-checkable protocols
    BackendProtocol, MiddlewareProtocol, ToolProtocol,
    CallbackProtocol, LLMProtocol, SandboxProtocol, AgentProtocol,
    # Slot enum + per-role applicability
    MiddlewareSlot, SAFETY_CRITICAL_SLOTS, SLOTS_PER_ROLE,
    # Focused contribution dataclasses (spec §7.2 Principle 3)
    ToolContribution, MiddlewareContribution, PromptContribution,
    SubAgentContribution, SafetyDeclaration,
    # Aggregate bundle (back-compat shape)
    PluginBundle, SubAgentSpec, is_bundle_enabled,
    # Pluggable role catalog (closes gap #5)
    RoleRegistry, RoleSpec,
    # Path validator (closes gap #12)
    SkillSourceRegistry,
    # Introspection API (closes gaps #4 + #7)
    PluginRegistry, PluginInfo, PluginConflictWarning, RoleResolution,
)
```

Test fakes live under `decepticon_sdk.testing`:

```python
from decepticon_sdk.testing import FakeBackend, FakeLLM, FakeSandbox

backend = FakeBackend({"/skills/recon/index.md": "..."})
llm = FakeLLM(responses=["mocked output"])
sandbox = FakeSandbox(responses=["hostname output"])
```

## New extension points

These close gaps from spec §8 — every entry is a new capability
plugin authors and downstream consumers couldn't reach before.

### `make_agent_backend(extra_routes=...)` — gap §8 #1

Mount custom prefix-keyed backends on top of the OSS defaults. Routes
are sorted by descending prefix length so the longest match wins —
tenant-specific paths override generic defaults deterministically.

```python
from decepticon.backends import make_agent_backend

backend = make_agent_backend(
    sandbox,
    extra_routes={
        "/skills/tenant/<id>/": tenant_backend,
        "/skills/plugins/apt-emulation/": apt_skill_backend,
    },
)
```

### `RoleRegistry.register()` — gap §8 #5

Register custom agent roles so the framework's middleware assembler
and LLM factory see them as first-class. Idempotent on identical
parameters; multi-process workers all succeed silently.

```python
from decepticon_sdk import RoleRegistry, MiddlewareSlot

RoleRegistry.register(
    "apt",
    slots=frozenset({
        MiddlewareSlot.ENGAGEMENT_CONTEXT,
        MiddlewareSlot.SKILLS,
        MiddlewareSlot.FILESYSTEM,
        MiddlewareSlot.MODEL_FALLBACK,
    }),
    skill_sources=("/skills/apt/",),
    llm_role_fallback="decepticon",
)
```

### `PluginRegistry.introspect_role()` — gap §8 #7

Read-only audit-log primitive. Returns a `RoleResolution` frozen
dataclass (hashable + cacheable on run ID per spec §16.4 #1).

```python
from decepticon_sdk import PluginRegistry

reg = PluginRegistry.load()
for plugin in reg.list_plugins():
    print(plugin.name, plugin.package, plugin.groups)

for collision in reg.detect_collisions():
    print(f"collision: {collision.key} owned by both "
          f"{collision.previous_owner!r} and {collision.owner!r}")
```

### `SafetyDeclaration` — gap §8 #10

Plugins extend the OSS-shipped safety-critical tool/middleware set.
Per spec §16.4 #4 the API is **additive only** — plugins can declare
their own tools / middleware safety-critical, but cannot remove
safety on OSS names.

```python
from decepticon_sdk import SafetyDeclaration

SAFETY_FOR_MY_PLUGIN = SafetyDeclaration(
    tools=("my_dangerous_tool",),
    middleware=("my-policy-enforcement",),
)
```

## Scaffolding a new plugin

The SDK ships a scaffolder. From any directory:

```bash
decepticon-sdk plugin new \
    --kind=middleware \
    --name=my-plugin \
    --path=./my-plugin

cd my-plugin
uv build
pip install dist/*.whl
```

Six plugin kinds are supported: `tool`, `middleware`, `agent`,
`callback`, `skill`, `prompt`. Runnable examples per kind live under
[`packages/decepticon-sdk/examples/`](../../packages/decepticon-sdk/examples/).

## Removal timeline

| Cleanup | Earliest version |
|---------|------------------|
| `decepticon.compat` shims (legacy import paths) | `2.0.0` |
| `PluginBundle` aggregate shape (replaced by focused contributions) | `2.0.0` |
| `decepticon.agents.middleware_slots.MiddlewareSlot` re-export | `2.0.0` |
