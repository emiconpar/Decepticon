# decepticon

Opinionated agent framework that builds on top of `decepticon-core`. Carries
the 16 agent factories, 11 middleware implementations, tools, LLM router,
sandbox HTTP client, and skill catalogs.

This package lives in the workspace under `packages/decepticon/`. See the
umbrella [`README.md`](../../README.md) for the project overview,
[`docs/`](../../docs/) for architecture, and the spec at
[`docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md`](../../docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md)
for the rationale behind the core/framework/sdk split.

## Install

```bash
pip install decepticon
```

Plugin authors should depend on `decepticon-sdk` instead.
