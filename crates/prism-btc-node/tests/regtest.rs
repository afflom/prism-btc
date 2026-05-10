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
//! Verifies the full pipeline: get template → mine via prism-btc → submit →
//! chain height advances → block we minted appears at the new tip.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::Network;
use bitcoincore_rpc::{Auth, Client, RpcApi};

use prism_btc_node::{MiningSession, PrismMiner, SessionConfig};

/// Both `MiningWitness::output_bytes()` and `BlockHash::to_byte_array()`
/// return SHA-256d in **internal** (wire / Hasher-finalize) byte order.
/// They are bit-equal when the catamorphism evaluator produced the same
/// digest bitcoind anchored.
fn witness_block_hash_internal(witness: &prism_btc::MiningWitness) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(witness.output_bytes());
    out
}

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

    // The mined block carries a non-zero, type-certified grounding witness.
    let unit_addr = mined.witness.unit_address().as_u128();
    assert_ne!(unit_addr, 0, "grounded unit_address must be non-zero");
    assert_eq!(
        mined.witness.witt_level_bits(),
        32,
        "W32 level must propagate from the const-validated CompileUnit"
    );

    // Foundation catamorphism (ADR-028, ADR-029): the Grounded's
    // output_bytes IS the block hash bitcoind accepted, in the Hasher's
    // internal byte order — bit-equal to BlockHash::to_byte_array().
    let from_witness = witness_block_hash_internal(&mined.witness);
    let from_bitcoind: [u8; 32] = mined.hash.to_byte_array();
    assert_eq!(
        from_witness, from_bitcoind,
        "Grounded::output_bytes must equal the bitcoind-anchored block hash"
    );
}

#[test]
#[serial_test::serial]
#[ignore = "requires running bitcoind on regtest; set PRISM_RPC_* env vars"]
fn session_mines_a_block_and_advances_the_chain() {
    let url = env_or_skip("PRISM_RPC_URL").expect("PRISM_RPC_URL");
    let user = env_or_skip("PRISM_RPC_USER").expect("PRISM_RPC_USER");
    let pass = env_or_skip("PRISM_RPC_PASS").expect("PRISM_RPC_PASS");
    let payout = env_or_skip("PRISM_PAYOUT").expect("PRISM_PAYOUT");

    let observer = Client::new(&url, Auth::UserPass(user.clone(), pass.clone()))
        .expect("observer RPC connect");
    let height_before = observer.get_block_count().expect("getblockcount before");

    let cfg = SessionConfig {
        threads: Some(2),
        // Tight tip poll for a fast test.
        tip_poll: std::time::Duration::from_millis(100),
        progress_every: std::time::Duration::from_secs(60),
    };
    let session = MiningSession::new(
        &url,
        Auth::UserPass(user, pass),
        &payout,
        Network::Regtest,
        cfg,
    )
    .expect("MiningSession::new");

    let cancel = Arc::new(AtomicBool::new(false));
    let mined = session.mine_until_block(cancel).expect("mine_until_block");

    let height_after = observer.get_block_count().expect("getblockcount after");
    assert_eq!(height_after, height_before + 1);
    let tip = observer.get_best_block_hash().expect("getbestblockhash");
    assert_eq!(tip, mined.hash);
    assert_eq!(mined.witness.witt_level_bits(), 32);

    // Same end-to-end pin as the single-shot path: the typed-iso
    // evaluator's output_bytes equals the bitcoind-anchored block hash
    // (both internal byte order).
    let from_witness = witness_block_hash_internal(&mined.witness);
    let from_bitcoind: [u8; 32] = mined.hash.to_byte_array();
    assert_eq!(from_witness, from_bitcoind);
}
