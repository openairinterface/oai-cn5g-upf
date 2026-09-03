<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# pfcpkit — writing PFCP scenarios

A library for driving a UPF over N4/PFCP and asserting on what it did. It supplies the
protocol machinery, the scenario lifecycle and the reporting; **you** supply what is
specific to your UPF. It ships no scenarios of its own.

**Read [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) first.** It walks through a
five-page diagram and covers most of what used to be repeated here:

| To understand | See |
|---|---|
| how the pieces fit, and which package owns what | page 1 |
| what a scenario may observe, and the command that answers each question | page 2 |
| the lifecycle, `execute()` quoted from source, and two real scenarios | page 3 |
| adding a scenario, or porting to another UPF | page 4 |
| what every module exposes | page 5 |

This page holds what a picture cannot: code you can paste, and the reference tables.

- [The shortest useful scenario](#the-shortest-useful-scenario)
- [What a scenario calls](#what-a-scenario-calls)
- [Setting up a new project](#setting-up-a-new-project)
- [Conventions](#conventions)
- [Reference](#reference)

A complete worked version is in [`examples/`](examples/) — an adapter, a base class and
three scenarios, runnable without a UPF.
[`unit/library/test_examples.py`](../unit/library/test_examples.py) runs them, so a library
change that breaks the documented pattern fails the build rather than leaving this page
quietly wrong.

## The shortest useful scenario

```python
from pfcpkit import presets
from pfcpkit.scenarios import register
from pfcpkit.scenarios.base import PfcpScenario


@register
class Establishment(PfcpScenario):
    """Establish a session and check the UPF accepted it."""

    name = "establishment"
    description = "A session establishment request is accepted and returns a UP F-SEID"
    tags = frozenset({"smoke"})
    ue_index = 0

    def act(self) -> None:
        self.session = self.establish(
            presets.basic_ipv4_session(self.ctx.settings, ue_ipv4=self.ue_ip())
        )

    def verify(self) -> None:
        self.report.check("establishment accepted", self.session.active)
        self.report.check(
            "the UPF allocated a UP F-SEID", self.session.up_seid is not None
        )
```

That is complete. Drop it in your scenario package and it is picked up by `--all`,
selectable by name and tag, and collected by pytest — no registration list, no runner
edit. It did not have to open a socket, correlate a sequence number, or delete the
session afterwards.

## What a scenario calls

```python
# drive the UPF
self.establish(spec)                     # send, track for teardown, abort if refused
self.modify(session, delta)
self.delete(session)                     # when deletion IS the subject
self.ue_ip()                             # this scenario's own UE address
self.require_pdrs_installed(seid, ids)   # abort unless those rules really landed

# observe it -- see diagram page 2 for what each protocol offers
self.ctx.rules.installed_pdr_ids(seid)
self.ctx.qos.flow_rate_kbps(seid, qfi)   # -> (rate, ceil) or None
mark = self.ctx.logs.mark()              # then *_since(mark) reads only what followed

# record the result -- soft unless noted
self.report.check(desc, cond, detail)
self.report.check_eq(desc, expected, actual)
self.report.check_count(desc, expected, actual)
self.report.check_in(desc, item, collection)
self.report.check_absent(desc, item, collection)
self.report.warn(message)                # reported, not a failure
self.report.require(desc, cond, detail)  # HARD: aborts the scenario
```

Prefer `check_eq` / `check_count` / `check_absent` over bare `check` where they apply:
they build the "expected X, got Y" detail, so a failure reads without opening the source.

## Setting up a new project

Diagram page 4 has the shape; here are the two files to paste. Only the third item grows
over time.

### 1. An adapter

Implement whichever protocols your UPF can serve, and declare which. These are
`typing.Protocol`, so conformance is structural — there is no base class to inherit.

```python
from pfcpkit.capabilities import Capability

CAPABILITIES = frozenset({Capability.RULE_STATE, Capability.LOG_WINDOW})
ADAPTER_NAME = "my-upf"


class MyRuleState:
    def __init__(self, client):          # however you read state
        self._client = client

    def installed_pdr_ids(self, seid: int) -> list[int]:
        return sorted(self._client.get(f"/sessions/{seid}/pdrs"))

    def installed_qfis(self, seid: int) -> list[int]: ...
    def seid_for_ue_ip(self, ue_ipv4: str) -> int | None: ...
    def session_installed(self, seid: int) -> bool: ...
```

It does not have to be eBPF. Declare only what you actually implement: over-claiming
turns a clean skip into a confusing mid-run failure. Worked version:
[`examples/adapter.py`](examples/adapter.py).

### 2. A harness

```python
from contextlib import contextmanager

from pfcpkit.config import Settings
from pfcpkit.pfcp.client import PfcpClient
from pfcpkit.scenarios import add_discovery_root
from pfcpkit.scenarios.context import ScenarioContext


def register_scenarios() -> None:
    add_discovery_root("my_upf_test.scenarios")


@contextmanager
def build_context(settings=None):
    settings = settings or Settings.from_env()
    register_scenarios()
    state = ...                              # however you reach your UPF

    with PfcpClient(settings) as client:     # opens the association, releases on exit
        yield ScenarioContext(
            settings=settings,
            client=client,
            rules=MyRuleState(state),
            qos=MyQosState(state),
            logs=MyLogSource(state),
            capabilities=CAPABILITIES,
            adapter=ADAPTER_NAME,
        )
```

Keep this the *only* place a context is built. Scenarios then contain no plumbing, and
changing how you reach the UPF is a one-file change.

### 3. A scenario package

`NN-topic.py` modules, one registered class each. Discovery walks the package sorted, so
the number fixes the run order — put anything that can degrade the UPF last.

### If a scenario needs an adapter extra

Adapters grow methods no protocol declares. Reaching one through the context is a type
error, correctly — so narrow it once:

```python
from typing import cast

from pfcpkit.scenarios.base import PfcpScenario


class MyScenario(PfcpScenario):
    @property
    def logs(self) -> MyLogSource:
        return cast(MyLogSource, self.ctx.logs)
```

Scenarios then use `self.logs`. Same object, different declared type. See
[`examples/base.py`](examples/base.py) and
[`upf_test/scenarios/base.py`](../upf_test/scenarios/base.py).

### Running them

`pfcpkit` has no CLI. Copy [`run_scenarios.py`](../run_scenarios.py) — a thin argparse
wrapper over `select()`, `partition_by_capability()` and `SuiteReport` — and point it at
your harness.

## Conventions

Not enforced by the library, but each exists because its absence caused a real problem.
[`unit/test_scenario_conventions.py`](../unit/test_scenario_conventions.py) checks them and
is worth copying; page 4 explains why each one matters.

- **One registered class per file**, named for the behaviour.
- **A unique `ue_index` per scenario**, and always `self.ue_ip()`.
- **State the requirement, not the defect.** "An Update QER changes the enforced rate",
  not "reproduces bug 5" — the requirement is still true after the fix.
- **Resolve rule ids from the session**, via `spec.qer(id)` / `spec.pdrs_for_qer(id)`,
  which raise when absent.
- **Assert a rule was installed before asserting it was removed.**
- **Document what a passing run looks like**, in a `Scenario / Expected behaviour /
  Expected output` docstring.

## Reference

**Scenario class attributes**

| Attribute | Required | Purpose |
|---|---|---|
| `name` | **yes** | Stable identifier for the CLI, registry and reports. |
| `description` | no | One line, shown by `--list`. State the requirement. |
| `requires` | no | `frozenset[Capability]` this scenario observes. |
| `tags` | no | Selection labels for `--tag`. |
| `ue_index` | no | Offset from `UE_IPV4_BASE`. **Must be unique.** |

**Registry**

```python
register(cls)                      # decorator; adds to the registry
add_discovery_root(package)        # your scenario package
discover()                         # import every module in every root
select(names=..., tags=...)        # resolve a selection
partition_by_capability(scs, caps) # -> (runnable, [(scenario, missing), ...])
describe_all()                     # the --list catalogue
```

**Environment**, read by `Settings.from_env()`

| Variable | Purpose |
|---|---|
| `UPF_N4_ADDR` | where PFCP is sent |
| `CP_NODE_ID` | our Node ID / F-SEID address |
| `UPF_N3_ADDR` | uplink F-TEID address |
| `GNB_N3_ADDR` | downlink Outer Header Creation target |
| `UE_IPV4_BASE` | base UE address; `ue_index` offsets from it |
| `PFCP_BIND_PORT` | local source port, for when 8805 is taken |
| `RESPONSE_TIMEOUT`, `REQUEST_RETRIES`, `SETTLE_TIMEOUT` | timing |

Anything about how your UPF is *deployed or observed* belongs in your own settings object,
not here — see [`upf_test/settings.py`](../upf_test/settings.py).

**Layering**, worth preserving if you extend the library

- `scapy` only in `pfcp/codec.py` and `pfcp/transport.py`
- `socket` only in `pfcp/transport.py`
- `subprocess` only in `inspect/runner.py`
- environment variables only in `config.py`

`pfcpkit` must never import a project-specific package.
[`unit/test_boundary.py`](../unit/test_boundary.py) enforces that by parsing every library
module rather than trusting that an import would show up at runtime.
