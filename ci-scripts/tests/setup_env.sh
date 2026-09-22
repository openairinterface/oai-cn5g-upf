#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Bring up the UPF integration test environment and verify it fail-fast.
#
# Every check here corresponds to a failure mode that otherwise presents as a
# confusing false negative -- most dangerously, one that makes an assertion pass
# for the wrong reason.
#
#   ./setup_env.sh            bring up, generate config, verify
#   ./setup_env.sh --verify   verify an already-running environment
#   ./setup_env.sh --down     tear down (use sudo to also remove the iptables rules)
#
# Run both bring-up and teardown under sudo if you want the host FORWARD chain
# managed; without it those two steps are skipped with a warning and everything
# else still works.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yaml"
readonly UPF_CONTAINER="${UPF_CONTAINER:-upf-test}"
readonly PFCP_PORT="${PFCP_PORT:-8805}"

# Interface names are pinned by `interface_name` in docker-compose.yaml, so these
# are known up front rather than discovered. They must stay in step with the
# compose file -- verify_environment checks that they really took effect.
readonly N4_IFACE="n4"
readonly N3_IFACE="n3"
readonly N6_IFACE="n6"

# Expected subnet per interface, so a mis-wired attachment is caught rather than
# silently producing a UPF bound to the wrong network.
readonly N4_SUBNET="192.168.70."
readonly N3_SUBNET="192.168.72."
readonly N6_SUBNET="192.168.73."

# The gNB stand-in on N3. Downlink FARs name this in Outer Header Creation, and
# the UPF resolves it with active arping, so it must answer on the wire.
readonly GNB_N3_ADDR="${GNB_N3_ADDR:-192.168.72.141}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[0;32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '  \033[0;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '  \033[0;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

# ---------------------------------------------------------------------------
# Host preflight
# ---------------------------------------------------------------------------
check_host() {
  log "Host preflight"

  command -v docker >/dev/null || die "docker is not on PATH"
  docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon"

  # `interface_name` under a service's network attachment needs Compose v2.30+.
  # An older version parses it and silently ignores it, which would leave the UPF
  # bound to whichever eth* Docker happened to assign.
  local version
  version=$(docker compose version --short 2>/dev/null | tr -d 'v')
  if [[ -n "$version" ]]; then
    local major minor
    major=${version%%.*}
    minor=$(cut -d. -f2 <<<"$version")
    if (( major < 2 || (major == 2 && minor < 30) )); then
      die "docker compose ${version} is too old for per-attachment interface_name
        (needs >= 2.30). Upgrade, or pin interface names another way."
    fi
    ok "docker compose ${version} supports interface_name"
  else
    warn "could not determine the docker compose version; assuming >= 2.30"
  fi

  # PFCP uses 8805 for both source and destination, so a local SMF/UPF or a
  # leftover container will occupy it and the suite cannot bind.
  #
  # Capture first, then match with a here-string. Piping into `grep -q` under
  # `set -o pipefail` is a trap: grep exits on the first match and closes the
  # pipe, the producer dies of SIGPIPE, and pipefail reports the *successful*
  # match as a failed pipeline -- so this check silently claimed the port was
  # always free.
  local listeners
  listeners=$(ss -ulnp 2>/dev/null || true)
  if grep -q ":${PFCP_PORT}\b" <<<"$listeners"; then
    warn "UDP ${PFCP_PORT} is already bound on this host:"
    grep ":${PFCP_PORT}\b" <<<"$listeners" | sed 's/^/        /'
    warn "set PFCP_BIND_PORT=<free port> if the UPF tolerates another source port"
  else
    ok "UDP ${PFCP_PORT} is free"
  fi

  command -v python3 >/dev/null || die "python3 is required to generate the config"
  python3 -c 'import yaml' 2>/dev/null \
    || die "PyYAML is required: pip install -r ${SCRIPT_DIR}/requirements-dev.txt"
  ok "python3 with PyYAML available"
}

# ---------------------------------------------------------------------------
# The host FORWARD chain
# ---------------------------------------------------------------------------
permit_forwarding() {
  log "Permitting PFCP through the host FORWARD chain"

  # With net.bridge.bridge-nf-call-iptables=1 (the default on many hosts),
  # container traffic traverses the host FORWARD chain, whose policy is often
  # DROP. The PFCP request then never arrives and the symptom is
  # indistinguishable from the UPF rejecting the session.
  if ! command -v iptables >/dev/null; then
    warn "iptables not found -- skipping; if requests time out, check FORWARD"
    return 0
  fi
  if [[ $(id -u) -ne 0 ]]; then
    warn "not root -- skipping the FORWARD permit; re-run with sudo if requests time out"
    return 0
  fi

  # awk's `exit` replaces `| head -n1`, which would SIGPIPE awk and trip pipefail.
  local bridge
  bridge=$(ip -o -4 addr show 2>/dev/null \
    | awk -v net="${N4_SUBNET}129/" '$4 ~ net {print $2; exit}' || true)
  if [[ -z "$bridge" ]]; then
    warn "N4 bridge not found -- re-run --verify once the networks exist"
    return 0
  fi

  local dir
  for dir in dport sport; do
    if ! iptables -C FORWARD -i "$bridge" -o "$bridge" \
         -p udp --${dir} "$PFCP_PORT" -j ACCEPT 2>/dev/null; then
      iptables -I FORWARD -i "$bridge" -o "$bridge" \
        -p udp --${dir} "$PFCP_PORT" -j ACCEPT
    fi
  done
  ok "UDP ${PFCP_PORT} permitted intra-bridge on ${bridge}"
  warn "these rules outlive the containers -- 'sudo ./setup_env.sh --down' removes them"
}

revoke_forwarding() {
  # The inverse of permit_forwarding. Without this the rules accumulate as cruft
  # pointing at deleted bridges: `compose down` removes the bridge, but iptables
  # happily keeps rules referencing an interface that no longer exists.
  log "Removing the PFCP FORWARD permits"

  if ! command -v iptables >/dev/null; then
    warn "iptables not found -- nothing to remove"
    return 0
  fi
  if [[ $(id -u) -ne 0 ]]; then
    # Only warn if there is actually something to clean up.
    warn "not root -- cannot remove FORWARD permits; run: sudo ./setup_env.sh --down"
    return 0
  fi

  # Match only what permit_forwarding inserted: same docker bridge in and out,
  # udp, our port, ACCEPT. Deliberately narrow so an unrelated user rule that
  # happens to mention 8805 is left alone.
  local rules removed=0 rule
  rules=$(iptables -S FORWARD 2>/dev/null \
    | grep -E "^-A FORWARD -i br-[0-9a-f]+ -o br-[0-9a-f]+ -p udp .*(--dport|--sport) ${PFCP_PORT} -j ACCEPT$" \
    || true)

  if [[ -z "$rules" ]]; then
    ok "no PFCP FORWARD permits to remove"
    return 0
  fi

  while IFS= read -r rule; do
    [[ -n "$rule" ]] || continue
    # Strip the leading "-A " so the remainder is a -D-compatible spec. Unquoted
    # on purpose: iptables needs the spec split into separate arguments.
    # shellcheck disable=SC2086
    if iptables -D ${rule#-A } 2>/dev/null; then
      removed=$((removed + 1))
    else
      warn "could not remove: ${rule}"
    fi
  done <<<"$rules"

  ok "removed ${removed} PFCP FORWARD permit(s)"
}

# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------
generate_config() {
  log "Generating conf/upf_test.yaml (n3=${N3_IFACE} n4=${N4_IFACE} n6=${N6_IFACE})"
  python3 "${SCRIPT_DIR}/conf/make_test_config.py" \
    --n3-iface "$N3_IFACE" --n4-iface "$N4_IFACE" --n6-iface "$N6_IFACE" \
    | sed 's/^/  /'
}

upf_died() {
  # Report the container's own failure rather than letting a later step fail
  # obscurely. The UPF exits non-zero on a config problem seconds after start,
  # so a bare "is it running?" check taken immediately can pass and every
  # downstream check then fails with something unrelated-looking.
  local exit_code
  exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$UPF_CONTAINER" 2>/dev/null || echo "?")
  printf '\n'
  warn "the UPF exited (code ${exit_code}). Last 20 log lines:"
  docker logs --tail 20 "$UPF_CONTAINER" 2>&1 | sed 's/^/        /' >&2
  printf '\n'
  die "the UPF did not stay up. Config problems name the offending value, e.g.
        'Failed to probe <iface> inet addr: No such device'  -> an interface_name mismatch
        'Cannot resolve a DNS name'                          -> upf.remote_n6_gw is unreachable
        Both are set by conf/make_test_config.py."
}

wait_for_container() {
  log "Waiting for ${UPF_CONTAINER} to become ready"
  local i state
  for i in $(seq 1 60); do
    state=$(docker inspect -f '{{.State.Status}}' "$UPF_CONTAINER" 2>/dev/null || echo "missing")
    case "$state" in
      exited|dead) upf_died ;;
      running)
        # The data-path banner is the only true readiness signal: the process is
        # alive well before XDP is attached and N4 is listening.
        #
        # Matched in-shell rather than piped into `grep -q`, which under
        # `set -o pipefail` turns a successful match into a failed pipeline
        # (grep closes the pipe, docker logs dies of SIGPIPE).
        local logs
        logs=$(docker logs "$UPF_CONTAINER" 2>&1 || true)
        if [[ "$logs" == *"INITIALIZATION COMPLETE - READY"* ]]; then
          ok "UPF data path is initialised and listening"
          return 0
        fi
        ;;
    esac
    sleep 1
  done

  # Timed out: distinguish "still starting" from "quietly wedged".
  if [[ "$(docker inspect -f '{{.State.Running}}' "$UPF_CONTAINER" 2>/dev/null)" == "true" ]]; then
    warn "container is running but never logged the ready banner; continuing anyway"
    docker logs --tail 15 "$UPF_CONTAINER" 2>&1 | sed 's/^/        /'
    return 0
  fi
  upf_died
}

# ---------------------------------------------------------------------------
# Post-bring-up verification
# ---------------------------------------------------------------------------
verify_interfaces() {
  # Confirms `interface_name` took effect AND each interface carries the subnet
  # it should. Without this, an older Compose (or a mis-wired attachment) would
  # leave the UPF listening on the wrong network, and every data-path assertion
  # afterwards would be meaningless.
  # Check liveness first, so a crashed UPF reports its own error rather than
  # surfacing as an unexplained "could not read interface addresses".
  local state
  state=$(docker inspect -f '{{.State.Status}}' "$UPF_CONTAINER" 2>/dev/null || echo "missing")
  if [[ "$state" == "missing" ]]; then
    die "container ${UPF_CONTAINER} does not exist -- run ./setup_env.sh first"
  fi
  if [[ "$state" != "running" ]]; then
    upf_died
  fi

  local addrs
  if ! addrs=$(docker exec "$UPF_CONTAINER" ip -o -4 addr show 2>/dev/null); then
    # The state check above can win a race against a container that is still
    # mid-exit, so re-check before blaming the exec itself.
    state=$(docker inspect -f '{{.State.Status}}' "$UPF_CONTAINER" 2>/dev/null || echo "missing")
    [[ "$state" == "running" ]] \
      || upf_died
    die "could not read interface addresses from ${UPF_CONTAINER} (is 'ip' present?)"
  fi

  local pair iface subnet actual
  for pair in "${N4_IFACE}:${N4_SUBNET}" "${N3_IFACE}:${N3_SUBNET}" "${N6_IFACE}:${N6_SUBNET}"; do
    IFS=':' read -r iface subnet <<<"$pair"
    actual=$(awk -v want="$iface" '$2 == want {print $4}' <<<"$addrs")
    if [[ -z "$actual" ]]; then
      printf '%s\n' "$addrs" | sed 's/^/        /' >&2
      die "interface '${iface}' does not exist in the container.
        docker-compose.yaml sets interface_name, so either Compose ignored it
        (needs >= 2.30) or the container predates the change -- try
        ./setup_env.sh --down && ./setup_env.sh"
    fi
    if [[ "$actual" != ${subnet}* ]]; then
      die "interface '${iface}' has ${actual}, expected ${subnet}x -- networks are mis-wired"
    fi
    ok "${iface} = ${actual}"
  done
}

verify_environment() {
  log "Verifying the UPF environment"
  verify_interfaces

  # eBPF actually loaded? A missing map would make pruning assertions pass
  # vacuously, which is the worst possible outcome for a bug-detection suite.
  local maps
  maps=$(docker exec "$UPF_CONTAINER" /openair-upf/bin/bpftool map show 2>/dev/null || true)
  if [[ -z "$maps" ]]; then
    die "bpftool listed no maps -- the eBPF datapath did not load (enable_bpf_datapath?)"
  fi
  # The kernel truncates BPF map names to 15 characters (BPF_OBJ_NAME_LEN), so
  # these are the *truncated* forms -- which is also what `bpftool map dump name`
  # must be given. Confirmed against a live UPF:
  #   session_by_ue_ip_map  -> session_by_ue_i
  #   rules_match_pdr_map   -> rules_match_pdr
  #   pdrs_per_session_map  -> pdrs_per_sessio
  local expected missing=()
  for expected in session_by_ue_i rules_match_pdr pdrs_per_sessio sdf_filters_map; do
    grep -q "\bname ${expected}\b" <<<"$maps" || missing+=("$expected")
  done
  if (( ${#missing[@]} )); then
    warn "expected map(s) not found: ${missing[*]}"
    warn "the datapath may be partially loaded -- check docker logs ${UPF_CONTAINER}"
  else
    ok "expected BPF maps are present (names truncated to 15 chars by the kernel)"
  fi

  # The UPF ARPs the downlink next hop when a session is established. If nothing
  # answers, every downlink FAR burns three arping retries and stores a zero MAC
  # in arp_table_map -- harmless for control-plane assertions, but slow and noisy.
  if docker exec "$UPF_CONTAINER" \
       arping -c 2 -w 3 -I "$N3_IFACE" "$GNB_N3_ADDR" >/dev/null 2>&1; then
    ok "gNB next hop ${GNB_N3_ADDR} answers ARP on ${N3_IFACE}"
  else
    warn "gNB next hop ${GNB_N3_ADDR} does not answer ARP on ${N3_IFACE}"
    warn "expect 'retrieveNextHopMAC: ARP unresolved' per downlink FAR"
    warn "is the gnb-sim service up?  docker compose -f docker-compose.yaml up -d gnb-sim"
  fi

  # tc reachability. Note what is NOT checked here: whether `-j` yields JSON for
  # `class show`. On iproute2 5.15 (the image's version) it does not -- `-j` is
  # silently ignored for classes while working for qdiscs. An earlier version of
  # this check ran `tc -j class show` and called success "JSON supported", which
  # passed only because no classes existed yet to print. The inspector parses both
  # formats, so all that matters here is that the commands run.
  local qdisc_json
  qdisc_json=$(docker exec "$UPF_CONTAINER" tc -j qdisc show dev "$N3_IFACE" 2>/dev/null || true)
  if [[ "$qdisc_json" == \[* ]]; then
    ok "tc qdisc show returns JSON on ${N3_IFACE}"
  else
    warn "tc -j qdisc show did not return JSON on ${N3_IFACE}; qdisc checks will fail"
  fi
  if docker exec "$UPF_CONTAINER" tc class show dev "$N3_IFACE" >/dev/null 2>&1; then
    ok "tc class show runs on ${N3_IFACE} (text format is parsed)"
  else
    warn "tc class show failed on ${N3_IFACE}; QoS assertions cannot run"
  fi

  # docker logs line counting depends on the json-file driver.
  local driver
  driver=$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' "$UPF_CONTAINER")
  if [[ "$driver" == "json-file" || "$driver" == "local" ]]; then
    ok "log driver is ${driver}"
  else
    warn "log driver is ${driver}; log-window assertions may not work"
  fi

  if docker exec "$UPF_CONTAINER" sh -c "ss -uln 2>/dev/null | grep -q ':${PFCP_PORT}'"; then
    ok "UPF is listening on UDP ${PFCP_PORT}"
  else
    warn "no listener on UDP ${PFCP_PORT} inside the container yet"
  fi

  printf '\n'
  log "Environment ready. Export these for the test runner:"
  cat <<EOF
    export UPF_CONTAINER=${UPF_CONTAINER}
    export UPF_N4_ADDR=192.168.70.134
    export UPF_N3_ADDR=192.168.72.134
    export GNB_N3_ADDR=192.168.72.141
    export CP_NODE_ID=192.168.70.140
    export N3_IFACE=${N3_IFACE}
    export N6_IFACE=${N6_IFACE}

    ./run_scenarios.py --list
    ./run_scenarios.py --tag smoke
EOF
}

# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
bring_up() {
  check_host
  generate_config

  # Starts upf and gnb-sim. test-runner is behind a compose profile, so it is
  # not included. gnb-sim first, so the address already answers ARP by the time
  # the UPF resolves a downlink next hop.
  log "Starting the gNB stand-in and the UPF"
  compose up -d --build
  wait_for_container

  permit_forwarding
  sleep 3   # let the UPF finish loading XDP before verifying
  verify_environment
}

tear_down() {
  # Revoke before `compose down`, while the bridge still exists -- it makes the
  # rules easier to recognise and keeps the ordering intuitive.
  revoke_forwarding

  log "Tearing down containers and networks"
  compose down --remove-orphans
  ok "containers and networks removed"

  printf '\n'
  log "Left in place on purpose:"
  cat <<EOF
    oai-upf:pfcp-tests        the built image -- reuse it; 'docker rmi oai-upf:pfcp-tests' to drop
    conf/upf_test.yaml        generated, gitignored; regenerated on the next run
    .venv/                    the Python environment
EOF
}

main() {
  case "${1:-up}" in
    up|"")     bring_up ;;
    --verify)  verify_environment ;;
    --down)    tear_down ;;
    -h|--help) sed -n '3,12p' "${BASH_SOURCE[0]}" ;;
    *)         die "unknown argument: $1 (try --help)" ;;
  esac
}

main "$@"
