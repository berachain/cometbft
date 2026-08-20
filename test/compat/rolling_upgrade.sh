#!/usr/bin/env bash
#
# bera-v1.x <-> bera-v0.40.x live compatibility test.
#
# Phase A (data-dir reuse): a single-validator chain is started on the
#   bera-v1.x binary, stopped, restarted on the bera-v0.40.x binary with the
#   SAME home directory (no migration), and then rolled back to bera-v1.x and
#   forward again. Every restart must replay the other version's data dir and
#   keep producing blocks; historical blocks written by the other version must
#   stay queryable.
#
# Phase B (mixed-validator rolling upgrade): a 4-validator all-BLS network
#   (aggregated commits, PBTS) is started on bera-v1.x, then validators are
#   moved one by one to bera-v0.40.x (1+3, 2+2, 3+1, 4+0), soaking at each
#   stage. In between, an already-upgraded node is restarted on its own data
#   dir mid-soak, a node of each version is stopped for a soak and must
#   block-sync the missed blocks from the mixed-version peers, and a tx is
#   sent through the fully upgraded network. Finally one validator is rolled
#   back to bera-v1.x and forward again.
#   At every stage all validators must keep signing, both versions must
#   propose blocks the other accepts, rounds must stay at 0, block hashes
#   must agree across nodes, and the moved node must still serve early blocks.
#
# Requirements: go, python3, curl. The two binaries are built on the fly:
#   bera-v0.40.x from this checkout (tags: bls12381,pebbledb), bera-v1.x from
#   the module pinned in gen-v1x/go.mod (the bera-v1.x default db_backend is
#   pebbledb, which is why the bera-v0.40.x binary needs the pebbledb tag).
#
# Usage: test/compat/rolling_upgrade.sh [workdir]
#   env: V1X_BIN, V040_BIN (skip building), SOAK_BLOCKS (default 25),
#        KEEP_WORKDIR=1 (do not delete the workdir on success)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${1:-$(mktemp -d -t bera-compat-XXXXXX)}"
SOAK_BLOCKS="${SOAK_BLOCKS:-25}"
NUM_VALS=4
BASE_PORT=27100 # node i: p2p BASE+10i, rpc BASE+10i+1
CHAIN_ID="bera-compat-upgrade"
mkdir -p "$WORK"
REPORT="$WORK/report.md"
: > "$REPORT"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$REPORT"; }
note() { printf '%s\n' "$*" >> "$REPORT"; }
die() { log "FATAL: $*"; dump_logs; exit 1; }

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  for d in "$WORK"/node*; do [ -f "$d/pid" ] && kill "$(cat "$d/pid")" 2>/dev/null || true; done
}
trap cleanup EXIT
dump_logs() {
  for d in "$WORK"/node*; do
    for l in "$d"/*.log; do [ -f "$l" ] || continue; echo "== $l (tail)"; tail -n 30 "$l" | cut -c1-220; done
  done
}

# ---- binaries ---------------------------------------------------------------
if [ -z "${V040_BIN:-}" ]; then
  V040_BIN="$WORK/cometbft-v040"
  log "building bera-v0.40.x binary from $ROOT"
  (cd "$ROOT" && go build -tags bls12381,pebbledb -o "$V040_BIN" ./cmd/cometbft)
fi
if [ -z "${V1X_BIN:-}" ]; then
  V1X_BIN="$WORK/cometbft-v1x"
  log "building bera-v1.x binary from the module pinned in gen-v1x/go.mod"
  (cd "$HERE/gen-v1x" && go build -o "$V1X_BIN" github.com/cometbft/cometbft/cmd/cometbft)
fi
log "bera-v1.x:    $("$V1X_BIN" version) ($V1X_BIN)"
log "bera-v0.40.x: $("$V040_BIN" version) ($V040_BIN)"

# ---- helpers ----------------------------------------------------------------
p2p_port() { echo $((BASE_PORT + 10 * $1)); }
rpc_port() { echo $((BASE_PORT + 10 * $1 + 1)); }
rpc() { curl -s --max-time 5 "127.0.0.1:$(rpc_port "$1")$2"; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }

height_of() { rpc "$1" /status | jget "['result']['sync_info']['latest_block_height']" 2>/dev/null || echo 0; }
version_of() { rpc "$1" /status | jget "['result']['node_info']['version']" 2>/dev/null || echo "?"; }

start_node() { # idx bin label
  local i=$1 bin=$2 label=$3 home="$WORK/node$1"
  local peers="" j
  for j in $(seq 0 $((NUM_VALS - 1))); do
    [ "$j" = "$i" ] && continue
    [ -f "$WORK/node$j/id" ] || continue
    peers+="$(cat "$WORK/node$j/id")@127.0.0.1:$(p2p_port "$j"),"
  done
  peers="${peers%,}"
  "$bin" start --home "$home" --proxy_app kvstore \
    --rpc.laddr "tcp://127.0.0.1:$(rpc_port "$i")" \
    --p2p.laddr "tcp://127.0.0.1:$(p2p_port "$i")" \
    ${peers:+--p2p.persistent_peers "$peers"} \
    >> "$home/$label.log" 2>&1 &
  echo $! > "$home/pid"
  echo "$label" > "$home/running"
}
stop_node() { # idx
  local home="$WORK/node$1" _
  if [ -f "$home/pid" ]; then
    kill "$(cat "$home/pid")" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$(cat "$home/pid")" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$(cat "$home/pid")" 2>/dev/null || true
    rm -f "$home/pid" "$home/running"
  fi
}
wait_height() { # idx target timeout_s
  local i=$1 target=$2 t=${3:-120} h=0 _
  for _ in $(seq 1 $((t * 2))); do
    h=$(height_of "$i")
    [ "${h:-0}" -ge "$target" ] 2>/dev/null && return 0
    sleep 0.5
  done
  die "node$i did not reach height $target (at $h) within ${t}s"
}
wait_all_height() { local k; for k in $(seq 0 $((NUM_VALS - 1))); do wait_height "$k" "$1" "${2:-120}"; done; }
max_height() { local m=0 k h; for k in "$@"; do h=$(height_of "$k"); [ "$h" -gt "$m" ] && m=$h; done; echo "$m"; }

check_no_errors() { # idx label
  local f="$WORK/node$1/$2.log"
  # panics and consensus/p2p codec errors that would indicate an interop problem
  if grep -E "panic|CONSENSUS FAILURE|wrong Block.Header|invalid commit|failed to verify|unknown message|failed to decode|ErrMsgFromProto|conflicting votes|Vote extension|signature is too big" "$f" | grep -v "use of closed network" | head -3 | grep -q .; then
    log "WARN: suspicious log lines in $f:"; grep -E "panic|CONSENSUS FAILURE|wrong Block.Header|invalid commit|failed to verify|unknown message|failed to decode|ErrMsgFromProto|conflicting votes|Vote extension|signature is too big" "$f" | head -5 | cut -c1-200 | tee -a "$REPORT"
    return 1
  fi
  return 0
}

# analyze heights [from,to] as seen by node $1: per-validator signing/proposing,
# max commit round, and block hash agreement across all running nodes.
analyze() { # via_idx from to stage_name
  local via=$1 from=$2 to=$3 stage=$4
  python3 - "$via" "$from" "$to" "$stage" "$WORK" "$BASE_PORT" "$NUM_VALS" "$REPORT" <<'PY'
import sys, json, urllib.request, os
via, frm, to, stage, work, base, n, report = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6]), int(sys.argv[7]), sys.argv[8]
def rpc(i, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{base+10*i+1}{path}", timeout=5) as r:
        return json.load(r)["result"]
# validator addresses and which binary each node runs
addr, running = {}, {}
for i in range(n):
    try:
        st = rpc(i, "/status")
        addr[i] = st["validator_info"]["address"]
        running[i] = open(os.path.join(work, f"node{i}", "running")).read().strip()
    except Exception as e:
        running[i] = "down"
vals = rpc(via, f"/validators?height={frm}&per_page=100")["validators"]
order = [v["address"] for v in vals]
signed = {a: 0 for a in order}; proposed = {a: 0 for a in order}; maxround = 0; agg = 0; blocks = 0
for h in range(frm, to + 1):
    b = rpc(via, f"/block?height={h}")["block"]
    lc = b["last_commit"]
    blocks += 1
    maxround = max(maxround, int(lc["round"]))
    proposed[b["header"]["proposer_address"]] += 1
    flags = [int(s["block_id_flag"]) for s in lc["signatures"]]
    if any(f in (4, 5, 6, 7) for f in flags): agg += 1
    for a, f in zip(order, flags):
        if f in (2, 4, 5): signed[a] += 1
# hash agreement at `to` across all running nodes
hashes = {}
for i in range(n):
    if running.get(i, "down") == "down": continue
    try: hashes[i] = rpc(i, f"/block?height={to}")["block_id"]["hash"]
    except Exception as e: hashes[i] = f"ERR {e}"
ok = True
lines = [f"### {stage}: heights {frm}..{to} ({blocks} blocks) via node{via}"]
for i in range(n):
    a = addr.get(i)
    if a is None:
        lines.append(f"- node{i}: down"); continue
    lines.append(f"- node{i} [{running[i]}] {a[:8]}: signed {signed.get(a,0)}/{blocks}, proposed {proposed.get(a,0)}")
    if signed.get(a, 0) < blocks - 2:  # tolerate the restart window
        ok = False; lines.append(f"  FAIL: node{i} missed {blocks - signed.get(a,0)} commits")
# each version group that is up must have proposed at least once
for label in set(running.values()) - {"down"}:
    p = sum(proposed.get(addr[i], 0) for i in range(n) if running.get(i) == label)
    lines.append(f"- proposals by {label} nodes: {p}")
    if p == 0 and blocks >= 8:
        ok = False; lines.append(f"  FAIL: no block proposed by a {label} node")
lines.append(f"- max commit round: {maxround}; blocks with aggregated commit: {agg}/{blocks}")
if maxround > 0: lines.append("  WARN: rounds > 0 seen")
if agg != blocks: ok = False; lines.append("  FAIL: non-aggregated commit seen in an all-BLS network")
if len(set(hashes.values())) != 1:
    ok = False; lines.append(f"  FAIL: block hash at {to} disagrees: {hashes}")
else:
    lines.append(f"- block hash at {to} identical on {len(hashes)} nodes: {list(hashes.values())[0][:16]}...")
lines.append("- RESULT: " + ("PASS" if ok else "FAIL"))
out = "\n".join(lines)
print(out)
with open(report, "a") as f: f.write(out + "\n\n")
sys.exit(0 if ok else 1)
PY
}

# =============================================================================
# Phase A: single-node data-dir reuse, both directions
# =============================================================================
log "=== Phase A: data-dir reuse (single validator) ==="
A="$WORK/single"
rm -rf "$A"; mkdir -p "$A"
"$V1X_BIN" init --home "$A" --key-type bls12_381 >/dev/null 2>&1
sed -i.bak 's/^timeout_commit = .*/timeout_commit = "200ms"/' "$A/config/config.toml"
ARPC=$((BASE_PORT + 90)); AP2P=$((BASE_PORT + 91))
a_start() { "$1" start --home "$A" --proxy_app kvstore --rpc.laddr "tcp://127.0.0.1:$ARPC" --p2p.laddr "tcp://127.0.0.1:$AP2P" >> "$A/$2.log" 2>&1 & echo $! > "$A/pid"; }
a_stop() { kill "$(cat "$A/pid")" 2>/dev/null || true; for _ in $(seq 1 50); do kill -0 "$(cat "$A/pid")" 2>/dev/null || break; sleep 0.2; done; }
a_height() { curl -s --max-time 3 "127.0.0.1:$ARPC/status" | jget "['result']['sync_info']['latest_block_height']" 2>/dev/null || echo 0; }
a_wait() { for _ in $(seq 1 240); do h=$(a_height); [ "${h:-0}" -ge "$1" ] && return 0; sleep 0.5; done; die "single node stuck at $(a_height), wanted $1"; }
a_tx() { curl -s --max-time 10 "127.0.0.1:$ARPC/broadcast_tx_commit?tx=\"$1\"" | jget "['result']['height']"; }
a_query() { curl -s --max-time 5 "127.0.0.1:$ARPC/abci_query?path=\"/key\"&data=\"$1\"" | jget "['result']['response']['log']"; }

H=0
for step in "v1x:$V1X_BIN:10" "v040:$V040_BIN:10" "v1x:$V1X_BIN:10" "v040:$V040_BIN:10"; do
  IFS=: read -r label bin blocks <<< "$step"
  a_start "$bin" "$label"
  a_wait $((H + 1))
  ver=$(curl -s "127.0.0.1:$ARPC/status" | jget "['result']['node_info']['version']")
  txh=$(a_tx "k-$label-$H=v")
  a_wait $((txh + blocks))
  # every height written so far (by either version) must be queryable,
  # historical commits must be aggregated, and old txs must be in the app state
  for h in $(seq 1 5 $((txh + blocks))); do
    flags=$(curl -s "127.0.0.1:$ARPC/block?height=$h" | python3 -c "import sys,json; print(sorted(set(int(s['block_id_flag']) for s in json.load(sys.stdin)['result']['block']['last_commit']['signatures'])))")
    [ "$h" -gt 1 ] && [ "$flags" != "[4]" ] && die "height $h last_commit flags $flags (expected aggregated [4]) on $label"
    curl -s "127.0.0.1:$ARPC/block_results?height=$h" | jget "['result']['height']" >/dev/null || die "block_results $h failed on $label"
  done
  [ "$(a_query "k-$label-$H")" = "exists" ] || die "tx k-$label-$H not found on $label"
  H=$(a_height)
  a_stop
  log "Phase A: $label ($ver) ran from the shared data dir to height $H (tx at $txh), clean stop"
  note ""
done
grep -q "ABCI Replay Blocks\|Replay: Done" "$A/v040.log" || die "bera-v0.40.x did not replay the bera-v1.x data dir?"
log "Phase A PASS: v1.x -> v0.40.x -> v1.x -> v0.40.x on one data dir, final height $H"
note ""

# =============================================================================
# Phase B: 4-validator rolling upgrade
# =============================================================================
log "=== Phase B: mixed-validator rolling upgrade (4 BLS validators) ==="
for i in $(seq 0 $((NUM_VALS - 1))); do
  home="$WORK/node$i"; rm -rf "$home"; mkdir -p "$home"
  "$V1X_BIN" init --home "$home" --key-type bls12_381 >/dev/null 2>&1
  "$V1X_BIN" show-node-id --home "$home" > "$home/id"
  sed -i.bak \
    -e 's/^timeout_commit = .*/timeout_commit = "300ms"/' \
    -e 's/^addr_book_strict = .*/addr_book_strict = false/' \
    -e 's/^allow_duplicate_ip = .*/allow_duplicate_ip = true/' \
    -e "s/^moniker = .*/moniker = \"node$i\"/" \
    "$home/config/config.toml"
done
# one genesis with all four validators, produced from the bera-v1.x files
python3 - "$WORK" "$NUM_VALS" "$CHAIN_ID" <<'PY'
import json, sys, os
work, n, chain = sys.argv[1], int(sys.argv[2]), sys.argv[3]
base = json.load(open(os.path.join(work, "node0", "config", "genesis.json")))
base["chain_id"] = chain
vals = []
for i in range(n):
    k = json.load(open(os.path.join(work, f"node{i}", "config", "priv_validator_key.json")))
    vals.append({"address": k["address"], "pub_key": k["pub_key"], "power": "10", "name": f"node{i}"})
base["validators"] = vals
for i in range(n):
    json.dump(base, open(os.path.join(work, f"node{i}", "config", "genesis.json"), "w"), indent=2)
print("genesis validators:", [v["address"][:8] for v in vals])
PY

for i in $(seq 0 $((NUM_VALS - 1))); do start_node "$i" "$V1X_BIN" v1x; done
wait_all_height 5 120
log "Phase B: baseline network on bera-v1.x is producing blocks"
FROM=$(max_height 0 1 2 3); wait_all_height $((FROM + SOAK_BLOCKS)); TO=$(max_height 0 1 2 3)
analyze 0 "$FROM" "$TO" "B0 baseline: 4x v1.x" || die "baseline analysis failed"

stage() { # name idx bin label
  local name=$1 i=$2 bin=$3 label=$4
  log "Phase B: $name: moving node$i to $label"
  stop_node "$i"
  start_node "$i" "$bin" "$label"
  wait_height "$i" $(( $(max_height $(seq 0 $((NUM_VALS - 1)) | grep -v "^$i$") ) + 2 )) 120
  local from; from=$(max_height 0 1 2 3)
  wait_all_height $((from + SOAK_BLOCKS)) 180
  local to; to=$(max_height 0 1 2 3)
  local via=$(( (i + 1) % NUM_VALS ))
  analyze "$via" "$from" "$to" "$name" || die "$name analysis failed"
  analyze "$i" "$from" "$to" "$name (as seen by the moved node$i)" || die "$name analysis (node$i view) failed"
  local j
  for j in $(seq 0 $((NUM_VALS - 1))); do check_no_errors "$j" "$(cat "$WORK/node$j/running")" || die "errors in node$j log"; done
  # the moved node must be able to serve blocks written before the move
  rpc "$i" "/block?height=2" | jget "['result']['block']['header']['height']" >/dev/null || die "node$i cannot serve early blocks"
  rpc "$i" "/block_results?height=2" | jget "['result']['height']" >/dev/null || die "node$i cannot serve early block_results"
}
# catch-up: keep a node down for a while, then restart it with the given
# binary; it must block-sync the missed blocks from the (mixed-version) peers
# and rejoin consensus.
catchup() { # name idx bin label
  local name=$1 i=$2 bin=$3 label=$4 others from target
  others=$(seq 0 $((NUM_VALS - 1)) | grep -v "^$i$" | tr '\n' ' ')
  log "Phase B: $name: stopping node$i for $SOAK_BLOCKS blocks, then restarting it on $label"
  stop_node "$i"
  from=$(max_height $others)
  # shellcheck disable=SC2086
  for j in $others; do wait_height "$j" $((from + SOAK_BLOCKS)) 180; done
  local stopped_at; stopped_at=$(rpc "$(echo $others | cut -d' ' -f1)" "/block?height=$from" | jget "['result']['block']['header']['height']")
  start_node "$i" "$bin" "$label"
  target=$(( $(max_height $others) + 3 ))
  wait_height "$i" "$target" 180
  # the node must have fetched the missed blocks through blocksync (from the
  # mixed-version peers) before switching to consensus
  local switch_h
  switch_h=$(grep "Time to switch to consensus mode" "$WORK/node$i/$label.log" | tail -1 | sed -n 's/.*height=\([0-9]*\).*/\1/p')
  if [ -n "$switch_h" ] && [ "$switch_h" -ge $((stopped_at + SOAK_BLOCKS - 5)) ]; then
    log "Phase B: $name: node$i block-synced $stopped_at -> $switch_h, switched to consensus, now at $target"
  else
    die "$name: node$i did not block-sync the missed blocks (stopped at $stopped_at, switch height '$switch_h')"
  fi
  local via=$(( (i + 1) % NUM_VALS ))
  wait_all_height $((target + 10)) 120
  analyze "$via" "$((target + 1))" "$((target + 10))" "$name (after catch-up)" || die "$name analysis failed"
  rpc "$i" "/block?height=$((from + 5))" | jget "['result']['block']['header']['height']" >/dev/null || die "node$i cannot serve a block it block-synced"
}

stage "B1: 1x v0.40.x + 3x v1.x" 0 "$V040_BIN" v040
stage "B2: 2x v0.40.x + 2x v1.x (votes must cross the version boundary in every block)" 1 "$V040_BIN" v040
# restart an upgraded node mid-soak (replay over mixed-version data)
log "Phase B: restarting node0 (v0.40.x) on its own data dir mid-soak"
stop_node 0; start_node 0 "$V040_BIN" v040; wait_height 0 $(( $(max_height 1 2 3) + 2 )) 120
catchup "B2b: v0.40.x node block-syncs from mixed peers" 1 "$V040_BIN" v040
catchup "B2c: v1.x node block-syncs from mixed peers" 3 "$V1X_BIN" v1x
stage "B3: 3x v0.40.x + 1x v1.x" 2 "$V040_BIN" v040
stage "B4: 4x v0.40.x" 3 "$V040_BIN" v040
# transactions through a v0.40.x node land and are visible everywhere
txh=$(rpc 0 '/broadcast_tx_commit?tx="rolling=ok"' | jget "['result']['height']")
wait_all_height "$txh" 60
for i in $(seq 0 $((NUM_VALS - 1))); do [ "$(rpc "$i" '/abci_query?path="/key"&data="rolling"' | jget "['result']['response']['log']")" = "exists" ] || die "tx not visible on node$i"; done
log "Phase B: tx committed at height $txh on the fully upgraded network, visible on all nodes"
stage "B5: rollback: node0 back to v1.x (3x v0.40.x + 1x v1.x)" 0 "$V1X_BIN" v1x
stage "B6: forward again: node0 to v0.40.x (4x v0.40.x)" 0 "$V040_BIN" v040

log "=== PASS: bera-v1.x <-> bera-v0.40.x data-dir reuse and rolling upgrade ==="
log "report: $REPORT"
if [ -z "${KEEP_WORKDIR:-}" ] && [ -z "${1:-}" ]; then
  cleanup; trap - EXIT
  cp "$REPORT" "$(dirname "$WORK")/bera-compat-report-$(date +%Y%m%d-%H%M%S).md" 2>/dev/null || true
fi
