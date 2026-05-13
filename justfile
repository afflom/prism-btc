default:
    @just --list

build:
    cargo build --workspace

build-release:
    cargo build --workspace --release

build-wasm:
    wasm-pack build crates/prism-btc-wasm --target web --out-dir ../../pkg/prism-btc-wasm --release

test:
    cargo test --workspace --exclude prism-btc-wasm

test-wasm:
    wasm-pack test crates/prism-btc-wasm --node

check:
    cargo check --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# Compile-only check on prism-btc — triggers const-validation of the BlockHash CompileUnit
check-genesis:
    cargo check -p prism-btc

verify:
    cd prism-btc-lean && lake update && lake build

verify-check:
    cd prism-btc-lean && lake check

# Complete V&V suite (architecture invariants, fail-closed mining
# contract, wire-format equivalence, ψ-pipeline determinism, Lean
# proofs, regtest end-to-end if bitcoind is reachable). See
# VERIFICATION.md.
vv:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "── §1 fmt + clippy ──────────────────────────────────────────"
    just fmt-check
    just lint
    echo "── §2 prism-btc unit + integration + V&V tests (release) ────"
    cargo test --workspace --release
    echo "── §3 conformance (CONFORMANCE.md) ──────────────────────────"
    just conformance
    echo "── §4 rustdoc (broken-intra-doc-links = deny) ───────────────"
    just doc-check
    echo "── §5 Lean proofs ──────────────────────────────────────────"
    just verify
    echo "── §6 regtest end-to-end (skipped if PRISM_RPC_URL unset) ──"
    if [ -n "${PRISM_RPC_URL:-}" ] && [ -n "${PRISM_PAYOUT:-}" ]; then
        cargo test -p prism-btc-node --release -- --ignored --nocapture
    else
        echo "    SKIPPED: set PRISM_RPC_URL, PRISM_RPC_USER, PRISM_RPC_PASS, PRISM_PAYOUT to run"
    fi
    echo "── V&V complete ─────────────────────────────────────────────"

# Conformance suite — validates that the zero-cost runtime model scales
# arbitrarily over K and α. See CONFORMANCE.md.
conformance:
    cargo test -p prism-btc --release --test conformance -- --nocapture

# Fast CI (excludes Lean and wasm-pack — run separately)
ci:
    just fmt-check
    just check
    just lint
    just test
    just check-genesis

bench:
    cargo bench -p prism-btc

doc:
    cargo doc --workspace --no-deps --open

# Lint-strict rustdoc — broken intra-doc links are denied. Wired into `vv`.
doc-check:
    RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --workspace --no-deps --release

# End-to-end regtest demo: spin up bitcoind, mine 10 blocks via prism-btc, show chain state.
# Requires: bitcoind + bitcoin-cli on PATH (e.g. installed under ~/bin/).
# Default datadir: $HOME/regtest-data; override by exporting PRISM_REGTEST_DATA.
regtest-demo:
    #!/usr/bin/env bash
    set -euo pipefail
    DATADIR="${PRISM_REGTEST_DATA:-$HOME/regtest-data}"
    mkdir -p "$DATADIR"
    cat > "$DATADIR/bitcoin.conf" <<EOF
    regtest=1
    server=1
    fallbackfee=0.00001000
    [regtest]
    rpcuser=prism
    rpcpassword=demo
    rpcbind=127.0.0.1
    rpcallowip=127.0.0.1
    rpcport=18443
    EOF
    bitcoind -datadir="$DATADIR" -daemon || true
    bitcoin-cli -datadir="$DATADIR" -rpcwait createwallet "prism" 2>/dev/null || true
    ADDR=$(bitcoin-cli -datadir="$DATADIR" getnewaddress "" "bech32")
    echo "Payout address: $ADDR"
    cargo build --release -p prism-btc-node
    ./target/release/prism-mine \
      --rpc-url http://127.0.0.1:18443 \
      --rpc-user prism --rpc-pass demo \
      --network regtest \
      --payout "$ADDR" \
      --blocks 10
    echo "--- chain state ---"
    bitcoin-cli -datadir="$DATADIR" getblockcount
    bitcoin-cli -datadir="$DATADIR" getbalances

# End-to-end regtest integration test for prism-btc-node (requires bitcoind running).
regtest-test:
    #!/usr/bin/env bash
    set -euo pipefail
    DATADIR="${PRISM_REGTEST_DATA:-$HOME/regtest-data}"
    ADDR=$(bitcoin-cli -datadir="$DATADIR" getnewaddress "" "bech32")
    PRISM_RPC_URL=http://127.0.0.1:18443 \
    PRISM_RPC_USER=prism \
    PRISM_RPC_PASS=demo \
    PRISM_PAYOUT="$ADDR" \
      cargo test -p prism-btc-node --release -- --ignored --nocapture

# Bring up a pruned testnet4 node. Initial block download is ~few hundred MB
# and takes 20–60 minutes on first run; subsequent starts are instant.
# Override datadir with PRISM_TESTNET4_DATA.
testnet4-up:
    #!/usr/bin/env bash
    set -euo pipefail
    DATADIR="${PRISM_TESTNET4_DATA:-$HOME/testnet4-data}"
    mkdir -p "$DATADIR"
    cat > "$DATADIR/bitcoin.conf" <<EOF
    chain=testnet4
    server=1
    prune=2000
    [testnet4]
    rpcuser=prism
    rpcpassword=demo
    rpcbind=127.0.0.1
    rpcallowip=127.0.0.1
    rpcport=48332
    EOF
    bitcoind -datadir="$DATADIR" -daemon
    echo "testnet4 bitcoind starting; tail $DATADIR/testnet4/debug.log for IBD progress"

testnet4-status:
    bitcoin-cli -datadir="${PRISM_TESTNET4_DATA:-$HOME/testnet4-data}" getblockchaininfo

# Run prism-mine against testnet4. The mining inference is identical
# across regtest / signet / testnet / testnet4 / mainnet: same
# `BitcoinMiningModel`, same `mining_inference` verb (k-invariant
# branch ψ_1 → ψ_7 → ψ_8 → ψ_9), same `BitcoinResolverTuple`. The
# network-dependent value is the runtime byte threshold decoded from
# `getblocktemplate.bits` and carried in `MiningTask.target`. Each
# call to `mine()` is one structural inference per `MiningTask`:
# ψ_9 deterministically κ-derives a wire-format header candidate
# from the typed input (one σ-projection, no enumeration); the host
# boundary checks σ(header) ≤ target. On `DidNotAdmit`, the bitcoind
# boundary rolls the extranonce and re-invokes.
testnet4-mine BLOCKS="1" DURATION_SEC="300":
    #!/usr/bin/env bash
    set -euo pipefail
    DATADIR="${PRISM_TESTNET4_DATA:-$HOME/testnet4-data}"
    bitcoin-cli -datadir="$DATADIR" -rpcwait createwallet "prism" 2>/dev/null || true
    ADDR=$(bitcoin-cli -datadir="$DATADIR" getnewaddress "" "bech32")
    echo "Payout: $ADDR (blocks={{BLOCKS}}, duration cap {{DURATION_SEC}}s)"
    cargo build --release -p prism-btc-node
    timeout {{DURATION_SEC}} ./target/release/prism-mine \
      --rpc-url http://127.0.0.1:48332 \
      --rpc-user prism --rpc-pass demo \
      --network testnet4 \
      --payout "$ADDR" \
      --blocks {{BLOCKS}} || echo "duration limit reached or interrupt"
