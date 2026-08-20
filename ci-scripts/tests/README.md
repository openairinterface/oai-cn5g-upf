<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UPF PFCP Integration Tests

Drives the UPF over N4/PFCP and asserts on the result.

Two Python packages, one direction of dependency:

| Package | Contents | Depends on |
|---|---|---|
| **`pfcpkit`** | Machinery: PFCP transport and codec, session models, presets, report, scenario base and registry, capability protocols, generic `bpftool`/`tc`/log inspectors. **No scenarios.** | nothing in this repo |
| **`upf_test`** | Everything about this UPF: BPF map catalogue and key layouts, HTB class-id arithmetic, log strings, deployment settings, harness wiring, and **all 16 scenarios** | `pfcpkit` |

`pfcpkit` never imports `upf_test`, enforced by
[`unit/test_boundary.py`](unit/test_boundary.py). Testing another UPF means writing an
adapter and a harness and adapting the scenarios — see
[`pfcpkit/README.md`](pfcpkit/README.md), which is also the authoring guide, and
[`pfcpkit/examples/`](pfcpkit/examples/) for a version that runs with no UPF at all.

**Prefer a picture?** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) walks through a
five-page diagram with the images inline and pointers into the code. If you
change [`architecture.drawio`](docs/architecture.drawio), re-export the images under
`docs/img/`.

**Every scenario lives in [`upf_test/scenarios/`](upf_test/scenarios/)**, one class per
file, numbered in run order, so the directory listing and `--list` agree.

## Status

Complete and verified against a live UPF: the PFCP client, the scenario framework and
capability gating, the inspection layer, the OAI adapter, all 16 scenarios, and the Compose
environment with its preflight. 228 unit tests run with no UPF and no root.

Twelve of the sixteen scenarios fail on purpose — see below.

## Expect `--tag regression` to fail

The suite has two kinds of scenario, and they are meant to end differently:

```bash
./run_scenarios.py --tag smoke        # exit 0 -- the harness works
./run_scenarios.py --tag regression   # exit 1 -- the UPF bugs are still there
./run_scenarios.py --all              # exit 1, for the same reason
```

`regression` scenarios describe behaviour this UPF does not currently deliver. **A
failure there is the suite doing its job.** They should turn green as the defects are
fixed — that is the point of having them. Use `--tag smoke` when you want a signal that
the harness itself is healthy.

| # | Scenario | Observed today |
|---|---|---|
| [04](upf_test/scenarios/04-map_pruning.py) | `map_pruning` | removed PDRs and the removed QFI all stay in the rule maps |
| [05](upf_test/scenarios/05-map_pruning_on_delete.py) | `map_pruning_on_delete` | rule-map entries survive session deletion |
| [06](upf_test/scenarios/06-qos_rate_change.py) | `qos_rate_change` | rate/ceil stay at 50000/100000 after an update to 20000/40000 |
| [07](upf_test/scenarios/07-qos_at_establishment.py) | `qos_at_establishment` | no enforcement and no classification until the session is modified |
| [08](upf_test/scenarios/08-qer_removal_prunes_class.py) | `qer_removal_prunes_class` | the removed QER's enforcement survives |
| [09](upf_test/scenarios/09-qos_class_cleanup.py) | `qos_class_cleanup` | shaping state survives session deletion |
| [10](upf_test/scenarios/10-static_ip_reattach.py) | `static_ip_reattach` | the UE IP is still attributed to the deleted session |
| [11](upf_test/scenarios/11-create_pdr_existing_far.py) | `create_pdr_existing_far` | rejected `MANDATORY_IE_MISSING`; accepted once a Create FAR is added |
| [12](upf_test/scenarios/12-rebuild_once.py) | `rebuild_once` | 25 datapath rebuilds for one modification carrying 4 removal IEs |
| [13](upf_test/scenarios/13-rebuild_once_update_only.py) | `rebuild_once_update_only` | 2 rebuilds for a modification with no removals at all |
| [14](upf_test/scenarios/14-qos_tc_failures.py) | `qos_rebuild_tc_failures` | 6 failed `tc` operations while applying the new rate, PFCP response still an accept |
| [16](upf_test/scenarios/16-repeated_modification.py) | `repeated_modification_stability` | 22 kernel attach refusals across 11 modifications |

Scenarios `01`–`03` are the smoke and negative cases and pass. `15`
([`qer_flag_at_establishment`](upf_test/scenarios/15-qer_flag_at_establishment.py)) also
passes, and is expected to: it asks the narrower question of whether the UPF *recorded* the
session's QER. Read with `07`, the pair locates where establishment stops short — the UPF
registered the QER and did not act on it, which is a different problem from never having
seen it.

## Quick start

```bash
cd ci-scripts/tests

python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

# Bring up the UPF, generate its config, run the preflight checks.
# The first run compiles the UPF image and takes several minutes; afterwards
# Docker's layer cache makes it quick unless src/ changed -- which is exactly
# when a rebuild is wanted, so `--build` is left on deliberately.
# sudo is only needed for the iptables FORWARD permit; without it that step is
# skipped with a warning and everything else still works.
sudo ./setup_env.sh

# Run
.venv/bin/python run_scenarios.py --list
.venv/bin/python run_scenarios.py --tag smoke
```

`setup_env.sh` prints the environment variables to export. Re-check a running
environment with `--verify`.

## Teardown

```bash
sudo ./setup_env.sh --down
```

What `--down` removes:

| | |
|---|---|
| `upf-test` container | stopped and deleted |
| `upf-test-n3` / `-n4` / `-n6` networks | deleted |
| PFCP `FORWARD` permits (udp 8805, both directions) | deleted — root only |

The image is kept because rebuilding compiles the UPF from source. Dropping it
costs several minutes on the next bring-up.

## Running

```bash
./run_scenarios.py --list                      # catalogue
./run_scenarios.py --all                       # everything
./run_scenarios.py --scenario establishment -v  # one, with debug logging
./run_scenarios.py --tag smoke --junit-xml results.xml
```

Exit codes are distinct on purpose, because CI should treat them differently:

| Code | Meaning |
|---|---|
| 0 | every selected scenario passed |
| 1 | a scenario failed — a real test result |
| 2 | the suite could not run (bad config, port conflict, unreachable UPF) |
| 130 | interrupted |

Under pytest, every discovered scenario becomes a case automatically:

```bash
.venv/bin/python -m pytest -m integration -v      # needs a live UPF
.venv/bin/python -m pytest -m "not integration"   # unit tests only
```

## Inspecting datapath state

Diagram page 2 traces each assertion down to the shell command that answers it — start
there if you want to check a verdict by hand.

```bash
# the decoders, with no UPF and no root: replayed bpftool and tc output captured
# from a live run, so a wrong struct offset or map name is caught here
.venv/bin/python -m pytest unit/library/test_bpftool.py unit/library/test_tc.py \
    unit/library/test_logs.py unit/oai -q

# the assertions themselves, against a running UPF
./run_scenarios.py --tag regression -v
./run_scenarios.py --tag datapath        # the same set, by capability rather than intent
```

Worth running the first after any change under `pfcpkit/inspect/` or `upf_test/`: a
silently wrong offset makes an *absence* assertion pass for the wrong reason, which is the
worst failure a suite can have.

### Two UPF behaviours worth knowing before writing assertions

Both were found with these inspectors and both shape how a scenario must be built:

1. **HTB classes and SDF filters are created only by `ModifyPipeline`, never by
   `CreatePipeline`.** After establishing a session with a QER there are *zero* tc
   classes and *zero* `sdf_filters_map` entries; they appear only after the first
   modification. Any QoS or SDF assertion therefore needs an establish → modify
   sequence, not establishment alone. (That the UPF applies no rate enforcement
   until a session is modified looks like a bug in its own right.)
2. **Deleted sessions leak their HTB classes.** Classes from previous sessions
   remain in `tc class show` after deletion, so a scenario must scope assertions to
   its own class ids rather than counting classes globally. Restart the UPF
   container for a clean slate.

## Configuration

Environment variables, defaulted to match `docker-compose.yaml`:

| Variable | Default | Purpose |
|---|---|---|
| `UPF_N4_ADDR` | `192.168.70.134` | where PFCP is sent |
| `CP_NODE_ID` | `192.168.70.140` | our Node ID / F-SEID address |
| `UPF_N3_ADDR` | `192.168.72.134` | uplink F-TEID address |
| `GNB_N3_ADDR` | `192.168.72.141` | downlink Outer Header Creation target |
| `UE_IPV4_BASE` | `12.1.1.2` | UE IP for generated sessions |
| `PFCP_BIND_PORT` | `8805` | local source port — override on conflict |
| `RESPONSE_TIMEOUT` | `3.0` | seconds per attempt |
| `REQUEST_RETRIES` | `2` | attempts per request |

Those are read by `pfcpkit.config.Settings` — PFCP addressing and timing, nothing
implementation-specific. How the UPF is *deployed and observed* is separate, read by
`upf_test.settings.Deployment`, because a UPF reached over an HTTP API would need
none of it:

| Variable | Default | Purpose |
|---|---|---|
| `UPF_CONTAINER` | `upf-test` | container to inspect |
| `N3_IFACE` / `N6_IFACE` | `n3` / `n6` | interfaces for QoS assertions |
| `BPFTOOL` | `/openair-upf/bin/bpftool` | path inside the container |
| `COMMAND_TIMEOUT` | `15.0` | seconds for one inspection command |

## Adding a scenario

One file per scenario, in `upf_test/scenarios/`, named `NN-topic.py` with the next number
— before `16-repeated_modification.py`, which must stay last. Subclass `OaiScenario`,
implement `act()` and `verify()`, declare `requires`, and decorate with `@register`. It is
then picked up by `--all`, selectable by name and tag, and collected by pytest — no other
file changes. Diagram page 4 has the same thing as a picture.

```python
# upf_test/scenarios/17-my_topic.py
from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class MyCase(OaiScenario):
    name = "my_case"
    description = "What this proves"
    tags = frozenset({"smoke"})                      # optional: selection labels
    requires = frozenset({Capability.LOG_WINDOW})    # what it observes
    ue_index = 23                                    # unique across every scenario

    def arrange(self) -> None:       # optional: preconditions
        self.session = self.establish(
            presets.basic_ipv4_session(self.ctx.settings, ue_ipv4=self.ue_ip())
        )

    def act(self) -> None:
        self.mark = self.logs.mark()
        self.response = self.modify(self.session, ...)

    def verify(self) -> None:
        self.report.check("modification accepted", self.response.accepted)
```

Six rules, most of them learned from a bug in this suite rather than invented. The first
three are enforced by `unit/test_scenario_conventions.py`, so you will hear about them;
the rest are on you:

- **One registered class per file**, named for the behaviour, numbered uniquely and
  contiguously. The number is the run order.
- **A unique `ue_index`**, and the UE IP always from `self.ue_ip()`. Two scenarios sharing
  an address make the first one's leftovers the second one's failure, because this UPF does
  not clear its UE-IP attribution on session deletion.
- **Declare everything you read in `requires`.** An undeclared read cannot be skipped, so
  on an adapter lacking that capability the scenario fails on state it was never going to
  reach — which reads as a UPF defect, not a missing declaration.
- **State the requirement, not the defect.** "An Update QER changes the enforced rate", not
  "reproduces Fix 5" — the first is still true after the fix and simply starts passing.
- **Resolve rule ids from the session**, via `spec.far()` / `spec.qer()` /
  `spec.pdrs_for_qer()` / `spec.uplink_pdrs()`, which raise when absent. Preset constants
  are for *declaring* rules; referencing one that no longer matches gives a misleading
  failure or, worse, a vacuous pass.
- **Assert a rule was installed before asserting it was removed**, via
  `self.require_pdrs_installed()`. Removing a rule that was never there is a no-op, and
  "it is absent afterwards" then passes while testing nothing.

Sessions created via `self.establish()` are deleted automatically, even if the
scenario fails.

Only a genuinely new PFCP IE requires touching shared code: add a field to
`pfcpkit/models.py` and a builder in `pfcpkit/pfcp/codec.py`.

## Layout

Two packages: `pfcpkit/` is the machinery and knows nothing about any one UPF; `upf_test/`
holds everything true only of this one, including all 16 scenarios. Diagram page 1 shows
how they relate and page 5 lists every module and what it exposes.

Scenario modules are named **`NN-topic.py`**, one registered class each, and the number is
the run order: discovery walks the package sorted, which is why
`16-repeated_modification.py` must stay last — it can leave the UPF degraded. Those names
are not valid Python identifiers, which is fine: they are only ever loaded through
`importlib.import_module`, and both ruff and mypy still analyse them.

`pfcpkit` never imports `upf_test`, enforced by
[`unit/test_boundary.py`](unit/test_boundary.py). `bpftool` and `tc` run **inside** the UPF
container because no BPF map is pinned and `tc` is namespace-scoped; `docker logs` runs on
the **host**. [`upf_test/harness.py`](upf_test/harness.py) is the only place that split is
made, so a different execution target is a new `CommandRunner` subclass and nothing else.

## Troubleshooting

**`could not bind 0.0.0.0:8805`** — PFCP uses 8805 for both source and
destination, so a local SMF/UPF or leftover container holds it. Check with
`ss -ulnp | grep 8805`; set `PFCP_BIND_PORT` to something free.

**Requests time out with the UPF running** — most likely the host `FORWARD`
chain. With `net.bridge.bridge-nf-call-iptables=1`, container traffic traverses
`FORWARD`, whose policy is often `DROP`, and the request never arrives. Run
`sudo ./setup_env.sh --verify`, or add the permit by hand.

**BPF map names look wrong** — the kernel truncates them to 15 characters
(`BPF_OBJ_NAME_LEN`), and that truncated form is what `bpftool map dump name`
expects. Verified on a live UPF: `session_by_ue_ip_map` → `session_by_ue_i`,
`rules_match_pdr_map` → `rules_match_pdr`, `pdrs_per_session_map` →
`pdrs_per_sessio`. `sdf_filters_map` is exactly 15 and survives intact.
`BpfMapInspector` truncates for you, so pass the full logical name.

**`MapNotFound` from an inspector** — deliberately distinct from an empty dump,
because "no map" and "no entries" mean very different things and conflating them
would let a pruning assertion pass against a UPF with no data path at all. Check
`docker exec upf-test /openair-upf/bin/bpftool map show`.

**`tc class show` returns nothing but classes clearly exist** — you are probably
calling it on the wrong interface. QoS classes live on the **N3** interface
(`$N3_IFACE`, default `n3`), not N6. Also remember classes only appear after a
*modification*, not on establishment.

**`retrieveNextHopMAC: ARP unresolved for 192.168.72.141`** — nothing is
answering at the gNB address named in the downlink FAR's Outer Header Creation.
The `gnb-sim` service exists solely to hold that address: `NextHopFinder` resolves
the next hop with active `arping` and never consults the kernel neighbour cache,
so a static `ip neigh` entry will not help — something must reply on the wire.

```bash
docker compose -f docker-compose.yaml up -d gnb-sim
./setup_env.sh --verify      # asserts the address answers ARP
```

Sessions still establish without it, so this is not fatal — but each downlink FAR
burns three arping retries, stores a zero MAC in `arp_table_map`, and adds error
lines to the logs that log-scraping assertions have to read past.

Note the ARP update runs on a **detached thread**, so success is logged a second
or two *after* the PFCP response returns. When asserting on ARP state, poll with
`pfcpkit.waiting.wait_until` rather than checking immediately.

**Session establishment rejected with cause 65/66** — a UE IP left over from a
previous run can still be in `session_by_ue_ip_map`, since the UPF does not clear
it on deletion. Restart the UPF container between runs until that
is fixed.