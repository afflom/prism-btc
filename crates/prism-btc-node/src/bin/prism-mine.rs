//! prism-mine — drive `prism_btc::mine` against a real bitcoind.
//!
//! Each invocation evaluates the `nonce_fiber_traversal` verb (wiki
//! ADR-024) over a (template prefix, target) pair via foundation
//! 0.4.1's catamorphism (ADR-029, ADR-034 Mechanism 2). On admission,
//! `BitcoinMiningModel::forward` mints the foundation-sealed
//! `Grounded<MiningResult, MiningTag>` carrying the `(disc, nonce)`
//! coproduct on `output_bytes`; this binary then assembles the
//! wire-format block from `(prefix, nonce)` and submits via
//! `submitblock`.

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
             prism-btc CPU mining cannot find a mainnet block in any reasonable time; \
             this flag exists to prevent accidental misconfiguration."
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
            "[{i}/{}] mined block #{} hash={} nonce={} txs={} ({:?})",
            args.blocks, mined.height, mined.hash, mined.nonce, mined.tx_count, dt
        );
    }
    Ok(())
}
