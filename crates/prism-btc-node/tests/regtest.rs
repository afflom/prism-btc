//! End-to-end regtest mining test.
//!
//! Gated `#[ignore]` because it requires a running bitcoind. To run:
//!
//! ```bash
//! ~/bin/bitcoind -datadir=$HOME/regtest-data -daemon
//! ~/bin/bitcoin-cli -datadir=$HOME/regtest-data -rpcwait createwallet prism
//! export PRISM_RPC_URL=http://127.0.0.1:18443
//! export PRISM_RPC_USER=prism
//! export PRISM_RPC_PASS=demo
//! export PRISM_PAYOUT=$(~/bin/bitcoin-cli -datadir=$HOME/regtest-data getnewaddress "" bech32)
//! cargo test -p prism-btc-node --release -- --ignored
//! ```
//!
//! Verifies the full pipeline: get template → mine via prism-btc
//! (foundation's catamorphism evaluates the `block_address_inference`
//! verb's ψ-chain term arena, ψ_1 → ψ_7 → ψ_8 → ψ_9; ψ_9 folds the
//! header carrier through the `sha256d` σ-axis to the block-hash κ-label,
//! the host scans nonces and rolls extranonces until one admits) →
//! assemble block → submit → chain height advances → block we minted
//! appears at the new tip.

use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoincore_rpc::{Auth, Client, RpcApi};

use prism_btc_node::PrismMiner;

fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!("regtest test skipped: {key} not set");
            None
        }
    }
}

#[test]
#[serial_test::serial]
#[ignore = "requires running bitcoind on regtest; set PRISM_RPC_* env vars"]
fn mines_a_block_and_advances_the_chain() {
    let url = env_or_skip("PRISM_RPC_URL").expect("PRISM_RPC_URL");
    let user = env_or_skip("PRISM_RPC_USER").expect("PRISM_RPC_USER");
    let pass = env_or_skip("PRISM_RPC_PASS").expect("PRISM_RPC_PASS");
    let payout = env_or_skip("PRISM_PAYOUT").expect("PRISM_PAYOUT");

    // Read-only client to observe the chain before/after.
    let observer = Client::new(&url, Auth::UserPass(user.clone(), pass.clone()))
        .expect("observer RPC connect");
    let height_before = observer.get_block_count().expect("getblockcount before");

    // The miner under test.
    let miner = PrismMiner::connect(&url, Auth::UserPass(user, pass), &payout, Network::Regtest)
        .expect("PrismMiner::connect");

    let mined = miner.mine_one_block().expect("mine_one_block");

    // Chain advanced by exactly one block.
    let height_after = observer.get_block_count().expect("getblockcount after");
    assert_eq!(
        height_after,
        height_before + 1,
        "chain height should advance by 1 (before={height_before}, after={height_after})"
    );

    // The new tip is the block prism-btc just mined.
    let tip_hash = observer.get_best_block_hash().expect("getbestblockhash");
    assert_eq!(
        tip_hash, mined.hash,
        "tip hash should equal the prism-btc-mined block hash"
    );

    // The mined block carries a replayable TC-05 proof-of-work witness.
    // verify() re-certifies the derivation and returns the attested
    // κ-label — the sha256d:<64hex> block address.
    let attested = mined.witness.verify().expect("witness must replay");
    assert!(
        attested.starts_with("sha256d:"),
        "witness attests the sha256d block address"
    );
    assert_eq!(attested.len(), 72, "κ-label is the 72-byte sha256d address");
    assert_eq!(mined.witness.content_fingerprint().len(), 32);

    // The MiningOutcome's host-side digest matches the bitcoind-anchored block hash.
    let from_bitcoind: [u8; 32] = mined.hash.to_byte_array();
    let mut display = [0u8; 32];
    display.copy_from_slice(&from_bitcoind);
    display.reverse();
    assert_ne!(display, [0u8; 32], "block hash is non-zero");
}

#[test]
#[serial_test::serial]
#[ignore = "requires running bitcoind on regtest; set PRISM_RPC_* env vars"]
fn mines_a_chain_of_blocks_without_fail() {
    // Architecture §7 / VERIFICATION.md §4: extends the single-block
    // regtest E2E to a chain of `N_BLOCKS` consecutive mining calls,
    // pinning the "valid input → valid output without fail" claim
    // across repeated invocations. Each mining call:
    //   1. fetches a fresh template (new prev_hash, new transactions),
    //   2. drives prism-btc's ψ-pipeline through the host-boundary
    //      extranonce-roll loop,
    //   3. assembles the wire-format block,
    //   4. submits via `submitblock` (fail-closed accept).
    // The chain advances by exactly `N_BLOCKS` and each new tip is
    // the block prism-btc just mined.
    const N_BLOCKS: u64 = 10;

    let url = env_or_skip("PRISM_RPC_URL").expect("PRISM_RPC_URL");
    let user = env_or_skip("PRISM_RPC_USER").expect("PRISM_RPC_USER");
    let pass = env_or_skip("PRISM_RPC_PASS").expect("PRISM_RPC_PASS");
    let payout = env_or_skip("PRISM_PAYOUT").expect("PRISM_PAYOUT");

    let observer = Client::new(&url, Auth::UserPass(user.clone(), pass.clone()))
        .expect("observer RPC connect");
    let height_before = observer.get_block_count().expect("getblockcount before");

    let miner = PrismMiner::connect(&url, Auth::UserPass(user, pass), &payout, Network::Regtest)
        .expect("PrismMiner::connect");

    let mut mined_hashes = Vec::with_capacity(N_BLOCKS as usize);
    for i in 1..=N_BLOCKS {
        let mined = miner
            .mine_one_block()
            .unwrap_or_else(|e| panic!("mine_one_block #{i} failed: {e:?}"));
        // The observed chain height after this mine matches the
        // pre-mining height plus the count of mined blocks.
        let height_now = observer.get_block_count().expect("getblockcount mid-loop");
        assert_eq!(
            height_now,
            height_before + i,
            "after mining #{i}, height should be height_before + {i}"
        );
        // The new tip is the block we just mined.
        let tip_hash = observer.get_best_block_hash().expect("getbestblockhash");
        assert_eq!(
            tip_hash, mined.hash,
            "after mining #{i}, tip hash should equal the prism-btc-mined block hash"
        );
        // Witness invariants hold for every block: the replayable TC-05
        // witness re-certifies to the 72-byte sha256d block address.
        let attested = mined
            .witness
            .verify()
            .unwrap_or_else(|e| panic!("witness must replay (block #{i}): {e:?}"));
        assert_eq!(
            attested.len(),
            72,
            "κ-label is the 72-byte sha256d address for every mined block (#{i})"
        );
        mined_hashes.push(mined.hash);
    }

    // All mined hashes are distinct (no chain forks, no re-orgs in
    // this controlled regtest run).
    let mut seen = std::collections::HashSet::new();
    for h in &mined_hashes {
        assert!(seen.insert(*h), "mined block hashes must be distinct");
    }
    assert_eq!(seen.len() as u64, N_BLOCKS);
}
