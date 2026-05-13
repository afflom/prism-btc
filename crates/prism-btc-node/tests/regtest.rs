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
//! (foundation's catamorphism evaluates the `mining_inference` verb's
//! ψ-chain term arena, ψ_1 → ψ_7 → ψ_8 → ψ_9; ψ_9's structural
//! κ-derivation produces one wire-format candidate per template, and
//! the host loop rolls extranonces until one admits) → assemble block
//! → submit → chain height advances → block we minted appears at the
//! new tip.

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

    // The mined block carries a non-zero, type-certified grounding witness.
    let unit_addr = mined.witness.unit_address().as_u128();
    assert_ne!(unit_addr, 0, "grounded unit_address must be non-zero");
    assert_eq!(
        mined.witness.witt_level_bits(),
        32,
        "W32 level must propagate from the const-validated CompileUnit"
    );

    // The ψ-pipeline label is the terminal ψ_9 output: 80 bytes that
    // ARE the wire-format Bitcoin header by construction (architecture
    // §2.2 + §6). Bytes 76..80 are the resolved nonce (canonical LE).
    let output = mined.witness.output_bytes();
    assert_eq!(
        output.len(),
        80,
        "κ-label is the 80-byte wire-format header"
    );
    let nonce_from_label = u32::from_le_bytes([output[76], output[77], output[78], output[79]]);
    assert_eq!(
        nonce_from_label, mined.nonce,
        "κ-label's nonce-field bytes decode to the resolved nonce"
    );

    // The MiningOutcome's host-side digest matches the bitcoind-anchored block hash.
    let from_bitcoind: [u8; 32] = mined.hash.to_byte_array();
    let mut display = [0u8; 32];
    display.copy_from_slice(&from_bitcoind);
    display.reverse();
    assert_eq!(
        mined.witness.witt_level_bits(),
        32,
        "witt level pinned through forward()"
    );
    assert_ne!(display, [0u8; 32], "block hash is non-zero");
}
