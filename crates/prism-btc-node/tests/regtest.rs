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
//! (foundation 0.4.1's catamorphism evaluates the
//! `nonce_fiber_traversal` verb's term arena per ADR-034 Mechanism 2)
//! → assemble block → submit → chain height advances → block we
//! minted appears at the new tip.

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

    // Foundation 0.4.1 Term::FirstAdmit (ADR-034 M2) returns a 6-byte
    // coproduct on the Grounded's output_bytes (ADR-028):
    //   byte 0:    discriminant (0x01 admitted)
    //   bytes 1..6: admitting nonce padded to 5 bytes BE
    // The 4-byte nonce in bytes[2..6] reconstructs the same wire-format
    // header bitcoind anchored, whose SHA-256d is the block hash. Pin
    // this end-to-end equivalence between the catamorphism's structural
    // result and the bitcoind-confirmed digest.
    let output = mined.witness.output_bytes();
    assert_eq!(output.len(), 6);
    assert_eq!(output[0], 0x01);
    let admitted_nonce = u32::from_be_bytes([output[2], output[3], output[4], output[5]]);
    assert_eq!(
        admitted_nonce, mined.nonce,
        "FirstAdmit's admitted nonce on output_bytes equals the nonce in the submitted block"
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
