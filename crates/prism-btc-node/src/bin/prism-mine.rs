//! prism-mine — drive `prism_btc::mine` against a real bitcoind.
//!
//! Each addressing inference evaluates the `block_address_inference`
//! verb (wiki ADR-024) — the ψ-pipeline's k-invariant branch
//! (ψ_1 → ψ_7 → ψ_8 → ψ_9) — over an 80-byte serialized header via
//! foundation's catamorphism. ψ_9 folds the header carrier through the
//! `sha256d` σ-axis and emits the `sha256d:<64hex>` κ-label (the block
//! hash). Foundation's `run_route` evaluates the admission relation
//! `block_hash ≤ target` via the model's `TargetCommitment`. The host
//! boundary (`prism_btc::mine`) scans the nonce space and varies the
//! template (rolling extranonce) until admission lands; this binary then
//! assembles the wire-format block from that header + the template's
//! transactions and submits via `submitblock`.

use anyhow::{bail, Context, Result};
use bitcoin::Network;
use bitcoincore_rpc::Auth;
use clap::Parser;

use prism_btc_node::PrismMiner;

#[derive(Parser, Debug)]
#[command(name = "prism-mine", about = "Mine Bitcoin blocks via prism-btc")]
struct Args {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    rpc_user: String,
    #[arg(long)]
    rpc_pass: String,
    #[arg(long, value_parser = parse_network)]
    network: Network,
    #[arg(long)]
    payout: String,

    /// Number of blocks to mine before exiting.
    #[arg(long, default_value_t = 1)]
    blocks: u32,

    /// Mainnet safety airlock — required when `--network mainnet`.
    #[arg(long)]
    i_know_what_im_doing: bool,
}

fn parse_network(s: &str) -> std::result::Result<Network, String> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unknown network: {other}")),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.network == Network::Bitcoin && !args.i_know_what_im_doing {
        bail!(
            "refusing to mine on mainnet without --i-know-what-im-doing. \
             prism-btc's ψ-pipeline is identical across networks; mainnet's \
             admission probability α ≈ 2^-77 means the host extranonge roll \
             would need ~2^77 iterations in expectation, which is computationally \
             infeasible on consumer hardware. The flag exists to prevent \
             accidental misconfiguration; the pipeline itself is fully valid for \
             mainnet input."
        );
    }

    let auth = Auth::UserPass(args.rpc_user.clone(), args.rpc_pass.clone());
    let miner = PrismMiner::connect(&args.rpc_url, auth, &args.payout, args.network)
        .context("PrismMiner::connect")?;

    println!(
        "prism-mine: connected to {} on {:?}; payout {}",
        args.rpc_url, args.network, args.payout
    );

    for i in 1..=args.blocks {
        let started = std::time::Instant::now();
        let mined = miner.mine_one_block().context("mine_one_block")?;
        let dt = started.elapsed();
        println!(
            "[{i}/{}] mined block #{} hash={} nonce={} txs={} \
             extranonce_attempts={} \u{03ba}_label={} ({:?})",
            args.blocks,
            mined.height,
            mined.hash,
            mined.nonce,
            mined.tx_count,
            mined.extranonce_attempts,
            mined.witness.kappa_label(),
            dt
        );
    }
    Ok(())
}
