# Plugin Author Guide

Audience: someone shipping a `pip install`-able Decepticon plugin —
custom tools, middleware, agents, callbacks, skills, or prompt
fragments.

The Decepticon framework is built around an extensible contract layer
(`decepticon-core`) and an opinionated runtime (`decepticon`). Plugin
authors interact only with the SDK package (`decepticon-sdk`), which
re-exports the contract layer and ships scaffolding + test fakes.

## 1. Install the SDK

```bash
pip install decepticon-sdk
```

Add test fixtures + scaffolding for development:

```bash
pip install "decepticon-sdk[testing]"
```

## 2. Scaffold the plugin

```bash
decepticon-sdk plugin new \
    --kind=middleware \
    --name=my-plugin \
    --path=./my-plugin
```

Six plugin kinds are supported: `tool`, `middleware`, `agent`,
`callback`, `skill`, `prompt`. Each kind generates a buildable
`pyproject.toml` wired to the matching entry-point group, plus a
stub module that conforms to the corresponding Protocol.

## 3. Implement against a Protocol

The contract layer defines a runtime-checkable Protocol per
extension type (spec §7.2 Principle 1: one Protocol per surface so
plugin authors read exactly one document). Implement it and the
framework discovers your contribution automatically.

### Tool

```python
from decepticon_sdk import ToolProtocol


class WhoamiTool:
    name = "whoami_via_curl"
    description = "Resolve the operator identity via a remote echo service."

    def invoke(self, input: object, *, config: object | None = None) -> object:
        # ... real implementation here
        return "operator-id"


def get_tools(role: str | None = None, **_: object) -> list[ToolProtocol]:
    return [WhoamiTool()]
```

`pyproject.toml`:

```toml
[project.entry-points."decepticon.tools"]
whoami = "my_plugin:get_tools"
```

### Middleware

```python
from decepticon_sdk import MiddlewareProtocol, MiddlewareSlot


class AuditLoggingMiddleware:
    name = "audit-log"
    slot: MiddlewareSlot | str = MiddlewareSlot.SKILLS
    priority = 150

    def wrap_model_call(self, state, runtime, config):
        # ... emit audit record
        return state
```

```toml
[project.entry-points."decepticon.middleware"]
audit-log = "my_plugin:get_middleware"
```

### Sub-agent

```python
from decepticon_sdk import SubAgentSpec
from my_plugin.agent import create_agent


SUBAGENT_SPEC = SubAgentSpec(
    name="my_specialist",
    description="...",
    factory=create_agent,
    parent_agents=("decepticon",),
    bundle="my-plugin",
    priority=50,
)
```

```toml
[project.entry-points."decepticon.subagents"]
my_specialist = "my_plugin:SUBAGENT_SPEC"
```

### Skill paths

```python
def get_skill_sources(role: str | None = None) -> list[str]:
    return ["/skills/my-plugin/"]
```

```toml
[project.entry-points."decepticon.skills"]
my-plugin = "my_plugin:get_skill_sources"
```

The `/skills/` prefix is validated by `SkillSourceRegistry` at boot;
malformed paths fail registration loudly. Ship the markdown skill
files as package data:

```toml
[tool.hatch.build.targets.wheel.shared-data]
"skills/my-plugin/" = "skills/my-plugin/"
```

### Prompt fragment (new in this release)

```python
from decepticon_sdk import PromptContribution

def get_contribution() -> PromptContribution:
    return PromptContribution(
        fragments={"recon": "<MY_AUDIT_POLICY>...</MY_AUDIT_POLICY>"},
        mode="append",
        roles=("recon",),
    )
```

```toml
[project.entry-points."decepticon.prompts"]
audit-policy = "my_plugin:get_contribution"
```

## 4. Bundle and safety gates

Bundle activation is controlled by `DECEPTICON_PLUGINS` (or the
`[tool.decepticon.plugins]` config section). Set `bundle="..."` on
your contribution so end users can opt in deliberately:

```python
from decepticon_sdk import PluginBundle


def get_bundle() -> PluginBundle:
    return PluginBundle(
        name="my-plugin-v1",
        activation_label="my-plugin",
        # ...
    )
```

```toml
[project.entry-points."decepticon.bundles"]
my-plugin-v1 = "my_plugin:get_bundle"
```

Operators enable your bundle:

```bash
DECEPTICON_PLUGINS=standard,my-plugin python -m decepticon ...
```

### Safety-critical overrides

The framework gates replacement of safety-critical slots and tools
(`SAFETY_CRITICAL_SLOTS`, `SAFETY_CRITICAL_TOOLS`). Replacements
require `DECEPTICON_ALLOW_SAFETY_OVERRIDES=1`. To declare *your own*
tool / middleware safety-critical (additive only — never removes
safety on OSS names):

```python
from decepticon_sdk import SafetyDeclaration


PLUGIN_SAFETY = SafetyDeclaration(
    tools=("my_dangerous_tool",),
    middleware=("my-policy-enforcement",),
)
```

Spec §16.4 #4: SafetyDeclaration is **additive only**.

## 5. Test hermetically

`decepticon_sdk.testing` ships in-memory fakes that satisfy each
Protocol — your plugin tests run without a live sandbox or LiteLLM
proxy:

```python
from decepticon_sdk.testing import FakeBackend, FakeLLM, FakeSandbox


def test_my_middleware_records_audit():
    backend = FakeBackend({"/skills/my-plugin/policy.md": "..."})
    llm = FakeLLM(responses=["mocked output"])
    sandbox = FakeSandbox(responses=["uid=0(root)"])

    middleware = AuditLoggingMiddleware()
    # ... call middleware methods, assert behavior
```

## 6. Discover and audit at runtime

`PluginRegistry` is the read-only introspection API (spec §16.4 #2):

```python
from decepticon_sdk import PluginRegistry

reg = PluginRegistry.load()

for plugin in reg.list_plugins():
    print(plugin.name, plugin.package, plugin.groups)

for collision in reg.detect_collisions():
    print(f"conflict on {collision.key}: "
          f"{collision.previous_owner} overridden by {collision.owner}")
```

Strict mode for production deployments — surface collisions as
errors at boot:

```bash
DECEPTICON_STRICT_REGISTRY=1
```

## 7. Publishing

Standard PyPI workflow — the wheel is built by hatchling and pinned
against `decepticon-sdk` so consumers automatically get the contract
layer at install time:

```bash
uv build
twine upload dist/*
```

The framework discovers your plugin via entry points the moment a
user installs the wheel. No registration call needed.

## See also

- The redesign spec at
  [`docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md`](superpowers/specs/2026-05-23-core-framework-sdk-split-design.md)
  — full design rationale.
- Example plugins per kind at
  [`packages/decepticon-sdk/examples/`](../packages/decepticon-sdk/examples/).
- Migration from `0.0.x` legacy imports:
  [`docs/migration/from-0.0.x.md`](migration/from-0.0.x.md).
