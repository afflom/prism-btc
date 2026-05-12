//! Bitcoin Core RPC integration for prism-btc.
//!
//! [`PrismMiner::mine_one_block`] is the entry point: fetch a template
//! via `getblocktemplate`, then drive prism-btc's ψ-pipeline against
//! template-derived `MiningTask` variations (extranonce roll) until an
//! admitting κ-derived header lands; assemble the wire-format block
//! and submit via `submitblock` (architecture §7).
//!
//! prism-btc owns the mining inference (the typed-iso surface
//! foundation 0.4.5's catamorphism evaluates); rust-bitcoin owns the
//! transaction / script / block container; this crate is the wiring.

use anyhow::{bail, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header as BtcHeader, Version as BtcBlockVersion};
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::merkle_tree::calculate_root;
use bitcoin::pow::CompactTarget;
use bitcoin::script::{Builder as ScriptBuilder, ScriptBuf};
use bitcoin::{
    Address, Amount, Block, BlockHash as BtcBlockHash, Network, Sequence, Transaction, Witness,
};
use bitcoincore_rpc::json::{
    GetBlockTemplateCapabilities, GetBlockTemplateModes, GetBlockTemplateResult,
    GetBlockTemplateRules,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use prism_btc::{
    mine, Bits, BlockHeader, MerkleRoot, MiningFailure, MiningWitness, Target, Timestamp, Version,
};

const COINBASE_WITNESS_RESERVED: [u8; 32] = [0u8; 32];

/// One end-to-end mining attempt against a connected bitcoind.
pub struct PrismMiner {
    client: Client,
    payout_address: Address,
    network: Network,
}

impl PrismMiner {
    pub fn connect(
        rpc_url: &str,
        auth: Auth,
        payout_address: &str,
        network: Network,
    ) -> Result<Self> {
        let client = Client::new(rpc_url, auth).context("RPC client connect")?;
        let info = client
            .get_blockchain_info()
            .context("getblockchaininfo for chain-mismatch guard")?;
        if info.chain != network {
            bail!(
                "chain-mismatch guard: node is on {:?} but --network is {network:?}",
                info.chain
            );
        }
        let address = payout_address
            .parse::<Address<_>>()
            .context("parse payout address")?
            .require_network(network)
            .with_context(|| format!("payout address is not for network {network:?}"))?;
        Ok(Self {
            client,
            payout_address: address,
            network,
        })
    }

    /// Fetch a block template, drive the ψ-pipeline against template-
    /// derived `MiningTask` variations until an admitting κ-label
    /// lands, submit via `submitblock`, return the summary.
    ///
    /// The host boundary owns the template-variation loop
    /// (architecture §7): it rolls the coinbase extranonce, which
    /// changes the coinbase txid, which changes the `MerkleRoot`,
    /// which changes the `TemplatePrefix`, which yields a new
    /// `MiningTask` whose ψ-pipeline κ-derived header may admit.
    /// prism-btc owns the per-task ψ-pipeline inference.
    ///
    /// This call blocks until an admitting variation is found,
    /// `submitblock` rejects, or the u64 extranonce space wraps
    /// (~10¹⁹ variations — typically reached only on adversarial
    /// targets; for any real network the chain advances first).
    pub fn mine_one_block(&self) -> Result<MinedBlock> {
        let rules: &[GetBlockTemplateRules] = match self.network {
            Network::Signet => &[
                GetBlockTemplateRules::SegWit,
                GetBlockTemplateRules::Signet,
                GetBlockTemplateRules::Csv,
                GetBlockTemplateRules::Taproot,
            ],
            _ => &[
                GetBlockTemplateRules::SegWit,
                GetBlockTemplateRules::Csv,
                GetBlockTemplateRules::Taproot,
            ],
        };

        let template = self
            .client
            .get_block_template(
                GetBlockTemplateModes::Template,
                rules,
                &[] as &[GetBlockTemplateCapabilities],
            )
            .context("getblocktemplate RPC")?;

        let mut extranonce: u64 = 0;
        loop {
            let job = MiningJob::from_template_with_extranonce(
                &template,
                &self.payout_address,
                extranonce,
            )?;

            // One ψ-pipeline inference per template variation. The
            // resolver chain is deterministic; finding admission
            // means finding the MiningTask variation whose κ-derived
            // nonce satisfies the target.
            match mine(&job.header, job.target) {
                Ok(outcome) => {
                    let block = job.assemble(outcome.nonce);
                    self.client
                        .submit_block(&block)
                        .context("submitblock rejected")?;
                    return Ok(MinedBlock {
                        hash: block.block_hash(),
                        height: template.height,
                        nonce: outcome.nonce,
                        witness: outcome.witness,
                        tx_count: block.txdata.len(),
                    });
                }
                Err(MiningFailure::DidNotAdmit) => {
                    extranonce = extranonce.wrapping_add(1);
                    if extranonce == 0 {
                        anyhow::bail!(
                            "u64 extranonce space exhausted for this template without admission"
                        );
                    }
                }
                Err(MiningFailure::PipelineFailure) => {
                    anyhow::bail!("foundation pipeline rejected the input");
                }
            }
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

/// Summary returned to the caller of [`PrismMiner::mine_one_block`].
pub struct MinedBlock {
    pub hash: BtcBlockHash,
    pub height: u64,
    pub nonce: u32,
    pub witness: MiningWitness,
    pub tx_count: usize,
}

/// All the per-template state a mining attempt needs.
pub(crate) struct MiningJob {
    pub(crate) header: BlockHeader,
    pub(crate) target: Target,
    coinbase: Transaction,
    other_txs: Vec<Transaction>,
    btc_version: BtcBlockVersion,
    btc_prev_hash: BtcBlockHash,
    btc_merkle: bitcoin::TxMerkleNode,
    btc_time: u32,
    btc_bits: CompactTarget,
}

impl MiningJob {
    pub(crate) fn from_template_with_extranonce(
        tpl: &GetBlockTemplateResult,
        payout: &Address,
        extranonce: u64,
    ) -> Result<Self> {
        let other_txs: Vec<Transaction> = tpl
            .transactions
            .iter()
            .map(|t| t.transaction().context("decode template tx"))
            .collect::<Result<_>>()?;

        let coinbase = build_coinbase_tx(tpl, payout, extranonce)?;

        let mut leaves = Vec::with_capacity(other_txs.len() + 1);
        leaves.push(coinbase.compute_txid().to_raw_hash());
        for tx in &other_txs {
            leaves.push(tx.compute_txid().to_raw_hash());
        }
        let merkle_root_raw = calculate_root(leaves.into_iter())
            .context("merkle root computation (empty leaf set unexpected)")?;
        let btc_merkle = bitcoin::TxMerkleNode::from_raw_hash(merkle_root_raw);

        if tpl.bits.len() != 4 {
            bail!(
                "getblocktemplate.bits has unexpected length {}",
                tpl.bits.len()
            );
        }
        let bits_u32 = u32::from_be_bytes([tpl.bits[0], tpl.bits[1], tpl.bits[2], tpl.bits[3]]);
        let btc_bits = CompactTarget::from_consensus(bits_u32);

        let time_u32: u32 = tpl.current_time.try_into().with_context(|| {
            format!(
                "template current_time {} exceeds u32::MAX",
                tpl.current_time
            )
        })?;

        let version_i32: i32 = tpl
            .version
            .try_into()
            .with_context(|| format!("template version {} exceeds i32::MAX", tpl.version))?;

        let prev_bytes: [u8; 32] = tpl.previous_block_hash.to_byte_array();
        let merkle_bytes: [u8; 32] = merkle_root_raw.to_byte_array();

        let header = BlockHeader {
            version: Version(tpl.version),
            prev_hash: prev_bytes,
            merkle_root: MerkleRoot::from_bytes(merkle_bytes),
            timestamp: Timestamp(time_u32),
            bits: Bits(bits_u32),
        };
        let target = Target::new(bits_u32);

        Ok(Self {
            header,
            target,
            coinbase,
            other_txs,
            btc_version: BtcBlockVersion::from_consensus(version_i32),
            btc_prev_hash: tpl.previous_block_hash,
            btc_merkle,
            btc_time: time_u32,
            btc_bits,
        })
    }

    /// Splice the winning nonce back into a full rust-bitcoin Block.
    pub(crate) fn assemble(self, nonce: u32) -> Block {
        let header = BtcHeader {
            version: self.btc_version,
            prev_blockhash: self.btc_prev_hash,
            merkle_root: self.btc_merkle,
            time: self.btc_time,
            bits: self.btc_bits,
            nonce,
        };
        let mut txdata = Vec::with_capacity(self.other_txs.len() + 1);
        txdata.push(self.coinbase);
        txdata.extend(self.other_txs);
        Block { header, txdata }
    }
}

/// Build a BIP141-compliant coinbase transaction.
fn build_coinbase_tx(
    tpl: &GetBlockTemplateResult,
    payout: &Address,
    extranonce: u64,
) -> Result<Transaction> {
    let height_i64: i64 = tpl
        .height
        .try_into()
        .with_context(|| format!("template height {} exceeds i64::MAX", tpl.height))?;

    let script_sig = ScriptBuilder::new()
        .push_int(height_i64)
        .push_slice(extranonce.to_le_bytes())
        .push_slice(b"prism-btc")
        .into_script();

    let mut input = TxIn {
        previous_output: OutPoint::null(),
        script_sig,
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    input.witness.push(COINBASE_WITNESS_RESERVED);

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(tpl.coinbase_value.to_sat()),
        script_pubkey: payout.script_pubkey(),
    }];

    let commitment_script: &ScriptBuf = &tpl.default_witness_commitment;
    if !commitment_script.as_bytes().is_empty() {
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: commitment_script.clone(),
        });
    }

    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: outputs,
    })
}
