# MHBench Benchmark Provider — Operator Guide

PR 1 scaffold. Wires the upstream
[MHBench](https://github.com/PurpleAILAB/MHBench) topology orchestrator into
Decepticon's benchmark harness so Decepticon agents can be scored against
multi-host network attack scenarios.

This document is intended for operators with an OpenStack tenant. There is no
local-Docker substitute for MHBench's VM-based topologies.

## What's wired in PR 1

- `benchmark/providers/mhbench.py` — `MHBenchProvider` wraps
  `benchmark/MHBench/main.py` for setup / teardown.
- `--provider mhbench` flag on `python -m benchmark.runner`.
- `--mhbench-config <path>` flag pointing at the upstream MHBench `config.json`.
- **One challenge end-to-end:** `mhbench/chain2hosts` (smallest topology — 2 hosts).

Out of scope for PR 1:
- The remaining 14 hand-tuned spec environments and 30 generated topologies
  (`EquifaxSmall/Medium/Large`, `ICSEnvironment`, `EnterpriseA/B`, etc.).
  These land in PR 2/3.
- Tight expected-flag verification — PR 1 accepts any `FLAG{<hex>}` string in
  agent output. Operator is responsible for seeding the flag via
  `ansible/goals/addFlag.yml` from within their MHBench compile pipeline.
- Caldera C2 / Falco / SysFlow telemetry integration. PR 4 territory.
- Pre-built smoke YAML config — current CLI flags cover the smoke run.

## Prerequisites

| Requirement                  | Notes                                                                                  |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| OpenStack project + creds    | API access; create networks, routers, floating IPs, compute instances.                 |
| Hardware (local OpenStack)   | 64 vCPU / 128 GB RAM / ~2 TB SSD (per upstream README).                                |
| MHBench `config.json`        | Populate from `benchmark/MHBench/config/config_example.json`. See below.               |
| Decepticon backend up        | `make dev` and wait for LiteLLM + LangGraph healthy (per `feedback_benchmark_startup`). |
| Reachability sandbox→tenant  | Decepticon's sandbox must be able to SSH into the attacker VM's floating IP.           |

## Initial setup

1. **Initialize the submodule.** From the repo root:

   ```bash
   git submodule update --init --recursive benchmark/MHBench
   ```

   The submodule is pinned to the `decepticon` branch of
   `PurpleAILAB/MHBench` (a fork of `bsinger98/MHBench` carrying Decepticon
   patches if/when needed).

2. **Install MHBench dependencies.** From `benchmark/MHBench/`:

   ```bash
   cd benchmark/MHBench
   uv sync
   ```

3. **Create the MHBench config.** Copy and fill in OpenStack credentials,
   external IP, and Elastic/C2 endpoints:

   ```bash
   cp benchmark/MHBench/config/config_example.json \
      benchmark/MHBench/config/config.json
   $EDITOR benchmark/MHBench/config/config.json
   ```

   The path you supply via `--mhbench-config` is passed verbatim to MHBench's
   `main.py --config-file` flag.

4. **(Optional) Pre-compile a topology snapshot.** Compile can take hours on a
   first run because it provisions VMs, installs packages, and snapshots
   images. Subsequent `setup` runs reuse the snapshots:

   ```bash
   cd benchmark/MHBench
   uv run python main.py --type Chain2Hosts --config-file config/config.json compile
   ```

   The provider's `setup()` calls the `setup` subcommand (not `compile`), so
   it expects this step to be done out-of-band.

## Running

```bash
uv run python -m benchmark.runner \
  --provider mhbench \
  --mhbench-config benchmark/MHBench/config/config.json \
  --ids mhbench/chain2hosts \
  --timeout 7200
```

Per-challenge timeout defaults to 1800s; bump it for MHBench since setup is
materially heavier than for Docker-based providers.

## How scoring works in PR 1

1. `MHBenchProvider.setup()` shells out to `main.py … setup` and parses the
   attacker VM's floating IP from stdout. The result is exposed to the agent
   as `target_url=ssh://kali@<ip>:22`.
2. The Decepticon agent attempts to compromise the topology. Its output and
   any workspace artefacts pass through the harness back to
   `MHBenchProvider.evaluate()`.
3. Evaluate returns `passed=True` iff a `FLAG{<hex>}` token appears anywhere
   in agent output. There is no expected-value comparison in PR 1 — the
   operator is trusted to have seeded the flag (typically via
   `ansible/goals/addFlag.yml` invoked from their compile pipeline).
4. `teardown()` shells out to `main.py … teardown` and frees the OpenStack
   resources.

## Known limitations

- **Stdout parsing is best-effort.** The provider scans MHBench's `setup`
  stdout for a line matching `attacker_floating_ip[:= ]<ip>` or
  `attacker_ip[:= ]<ip>`. Upstream does not (yet) emit a stable
  machine-readable marker for this, so the parse falls back to "no endpoint
  found" on format changes. Watch for the explicit error in setup output if
  the run fails immediately.
- **No CI coverage.** GitHub Actions runners do not have an OpenStack tenant.
  The MHBench provider is excluded from `make test` and `make quality`.
- **Sequential only (practically).** Each MHBench environment owns the
  OpenStack quota during setup, so running `--parallel >1` against the same
  tenant will collide. Run sequentially or use separate tenants per worker.

## Roadmap

| PR | Scope |
| -- | ----- |
| **PR 1 (this)** | Foundation + submodule + Chain2Hosts spike. |
| PR 2            | Remaining 14 spec environments + per-env metadata table. |
| PR 3            | 30 generated topologies (`generated_network_*.json`) + ansible-based exfil verification. |
| PR 4 (optional) | Caldera C2 / Falco / SysFlow telemetry — capability-graded scoring. |
