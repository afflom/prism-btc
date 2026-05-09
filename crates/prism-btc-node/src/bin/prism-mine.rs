//! prism-mine — drive `prism_btc::mine` against a real bitcoind.
//!
//! Each invocation evaluates the `nonce_fiber_traversal` verb (wiki
//! ADR-024) over a (template prefix, target) pair via the implementation
//! runtime per ADR-026 G16, then mints the foundation-sealed
//! `Grounded<ConstrainedTypeInput, MiningTag>` and submits the wire-format
//! block. Two modes:
//!
//! - **single-shot** (default): one template, one verb evaluation, one
//!   submit. Useful when the output-shape constraint complexity is low
//!   enough that the first canonical-order fiber visit admits (regtest,
//!   testnet4 under the min-difficulty rule).
//! - **session** (`--session`): long-running, with extranonce rolling,
//!   tip-staleness watcher, and a parallel coset-partition runtime per
//!   ADR-026 G16. The catamorphism evaluation cost is parametric in
//!   the chosen `Hasher` impl + the runtime's parallelism; this mode
//!   expresses both as user-tunable parameters.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bitcoin::Network;
use bitcoincore_rpc::Auth;
use clap::Parser;

use prism_btc_node::{MiningSession, PrismMiner, SessionConfig};

#[derive(Parser, Debug)]
#[command(
    name = "prism-mine",
    about = "Mine Bitcoin blocks via prism-btc σ-convergence"
)]
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

    /// Use the long-running session (extranonce + tip-watch + parallel + hash-rate).
    #[arg(long)]
    session: bool,

    /// Worker thread count for the session's parallel σ-convergence.
    /// Default: `std::thread::available_parallelism()`.
    #[arg(long)]
    threads: Option<usize>,

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

    if args.session {
        run_session(&args, auth)
    } else {
        run_single_shot(&args, auth)
    }
}

fn run_single_shot(args: &Args, auth: Auth) -> Result<()> {
    let miner = PrismMiner::connect(&args.rpc_url, auth, &args.payout, args.network)
        .context("PrismMiner::connect")?;

    println!(
        "prism-mine [single-shot]: connected to {} on {:?}; payout {}",
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

fn run_session(args: &Args, auth: Auth) -> Result<()> {
    let cfg = SessionConfig {
        threads: args.threads,
        tip_poll: Duration::from_millis(500),
        progress_every: Duration::from_secs(5),
    };
    let session = MiningSession::new(&args.rpc_url, auth, &args.payout, args.network, cfg)
        .context("MiningSession::new")?;

    println!(
        "prism-mine [session]: connected to {} on {:?}; payout {}; threads={:?}",
        args.rpc_url, args.network, args.payout, args.threads
    );

    // Ctrl-C handling: shared AtomicBool the session checks on its
    // tip-watch / extranonce boundaries.
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = cancel.clone();
        ctrlc::set_handler(move || {
            eprintln!("\nprism-mine: interrupt received, finishing current iteration...");
            cancel.store(true, std::sync::atomic::Ordering::Release);
        })
        .context("install SIGINT handler")?;
    }

    for i in 1..=args.blocks {
        if cancel.load(std::sync::atomic::Ordering::Acquire) {
            bail!("user cancelled before mining block {i}");
        }
        let started = std::time::Instant::now();
        let mined = session
            .mine_until_block(cancel.clone())
            .context("mine_until_block")?;
        let dt = started.elapsed();
        println!(
            "[{i}/{}] mined block #{} hash={} nonce={} txs={} ({:?})",
            args.blocks, mined.height, mined.hash, mined.nonce, mined.tx_count, dt
        );
    }
    Ok(())
}
