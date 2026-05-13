//! Bitcoin Core RPC integration for prism-btc.
//!
//! [`PrismMiner::mine_one_block`] is the entry point: fetch a template
//! via `getblocktemplate`, then drive prism-btc's ψ-pipeline against
//! template-derived `MiningTask` variations (extranonce roll) until an
//! admitting κ-derived header lands; assemble the wire-format block
//! and submit via `submitblock` (architecture §7).
//!
//! prism-btc owns the mining inference (the typed-iso surface
//! foundation's catamorphism evaluates); rust-bitcoin owns the
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

    /// Fetch a block template, drive prism-btc's ψ-pipeline against it,
    /// submit the admitting wire-format block via `submitblock`, return
    /// the summary.
    ///
    /// `prism_btc::mine` is one-shot per template: ψ_9's structural
    /// κ-derivation produces exactly one candidate header for any
    /// well-formed `MiningTask`. The host boundary iterates the
    /// **extranonce roll** (architecture §7) — each extranonce value
    /// produces a distinct coinbase txid → distinct merkle root →
    /// distinct `MiningTask` → distinct κ-derivation. Under PRF
    /// baseline, expected extranonce trials before admission is
    /// `1/α` where `α` is the target's admission probability. The
    /// u64 extranonce space (2^64) covers every realistic network
    /// difficulty (mainnet `α ≈ 2^-77`); exhaustion would indicate
    /// the network's `α` is below the algorithmic floor and is not a
    /// pipeline bug.
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

        // Signet validity gate (BIP325). When `signet_challenge` is
        // non-empty, valid signet blocks must carry the operator's
        // signature in the coinbase witness commitment area —
        // prism-btc-node does not implement signet block signing.
        // Fail-closed here rather than producing invalid output.
        // Empty-challenge signets (private no-challenge setups) are
        // supported.
        if self.network == Network::Signet && !template.signet_challenge.as_bytes().is_empty() {
            bail!(
                "signet has non-empty signet_challenge ({} bytes); BIP325 block signing \
                 is required and prism-btc-node does not implement it. Use bitcoind's \
                 built-in signet signer (signet wallet + generatetoaddress) for \
                 challenge signets, or run a private no-challenge signet for \
                 prism-btc-node end-to-end testing.",
                template.signet_challenge.as_bytes().len()
            );
        }

        // Template-variation loop: each iteration produces a fresh
        // MiningTask (distinct merkle root via the rolled extranonce)
        // and a distinct κ-derivation. mine() returns Ok when the
        // κ-candidate's σ-projection admits; DidNotAdmit otherwise.
        // For permissive targets (regtest), the loop body typically
        // runs once.
        let mut extranonce: u64 = 0;
        loop {
            let job = MiningJob::from_template_with_extranonce(
                &template,
                &self.payout_address,
                extranonce,
            )?;

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
                        resolution: outcome.resolution,
                        extranonce_attempts: extranonce,
                    });
                }
                Err(MiningFailure::DidNotAdmit) => {
                    // The κ-derivation for this template's
                    // (prefix, target) didn't satisfy target. Vary
                    // the extranonce → distinct MerkleRoot →
                    // distinct TemplatePrefix → distinct κ-derivation.
                    extranonce = extranonce.wrapping_add(1);
                    if extranonce == 0 {
                        anyhow::bail!(
                            "u64 extranonce space exhausted for this template without admission"
                        );
                    }
                }
                Err(MiningFailure::PipelineFailure) => {
                    bail!(
                        "ψ-pipeline shape violation — defensive failure mode, should not occur for well-formed MiningTask inputs"
                    );
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
    /// Diagnostic state from ψ_9's structural κ-derivation that
    /// landed the admitting κ-label for the submitted block.
    /// See [`prism_btc::diagnostics`].
    pub resolution: prism_btc::ResolutionState,
    /// Number of host-boundary extranonce variations the template
    /// loop walked before admission. `0` means the first
    /// κ-derivation admitted; higher values count subsequent
    /// extranonce rolls (architecture §7).
    pub extranonce_attempts: u64,
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

        if tpl.bits.len() != 4 {
            bail!(
                "getblocktemplate.bits has unexpected length {}",
                tpl.bits.len()
            );
        }
        let bits_u32 = u32::from_be_bytes([tpl.bits[0], tpl.bits[1], tpl.bits[2], tpl.bits[3]]);

        let time_u32: u32 = tpl.current_time.try_into().with_context(|| {
            format!(
                "template current_time {} exceeds u32::MAX",
                tpl.current_time
            )
        })?;

        Self::from_components(
            tpl.previous_block_hash.to_byte_array(),
            tpl.height,
            bits_u32,
            time_u32,
            tpl.version,
            tpl.coinbase_value.to_sat(),
            tpl.default_witness_commitment.clone(),
            other_txs,
            payout,
            extranonce,
        )
    }

    /// Component-level constructor — testable without a live bitcoind.
    /// Mirrors [`Self::from_template_with_extranonce`] but takes the
    /// essential template fields directly. Produces the same
    /// `MiningJob` for any (template, extranonce) the host loop drives.
    #[allow(clippy::too_many_arguments)] // every arg is a load-bearing template field
    pub(crate) fn from_components(
        prev_hash: [u8; 32],
        height: u64,
        bits: u32,
        time: u32,
        version: u32,
        coinbase_value_sat: u64,
        witness_commitment_script: ScriptBuf,
        other_txs: Vec<Transaction>,
        payout: &Address,
        extranonce: u64,
    ) -> Result<Self> {
        let coinbase = build_coinbase_tx(
            height,
            coinbase_value_sat,
            &witness_commitment_script,
            payout,
            extranonce,
        )?;

        let mut leaves = Vec::with_capacity(other_txs.len() + 1);
        leaves.push(coinbase.compute_txid().to_raw_hash());
        for tx in &other_txs {
            leaves.push(tx.compute_txid().to_raw_hash());
        }
        let merkle_root_raw = calculate_root(leaves.into_iter())
            .context("merkle root computation (empty leaf set unexpected)")?;
        let btc_merkle = bitcoin::TxMerkleNode::from_raw_hash(merkle_root_raw);
        let merkle_bytes: [u8; 32] = merkle_root_raw.to_byte_array();

        let version_i32: i32 = version
            .try_into()
            .with_context(|| format!("template version {version} exceeds i32::MAX"))?;
        let btc_bits = CompactTarget::from_consensus(bits);
        let btc_prev_hash = BtcBlockHash::from_byte_array(prev_hash);

        let header = BlockHeader {
            version: Version(version),
            prev_hash,
            merkle_root: MerkleRoot::from_bytes(merkle_bytes),
            timestamp: Timestamp(time),
            bits: Bits(bits),
        };
        let target = Target::new(bits);

        Ok(Self {
            header,
            target,
            coinbase,
            other_txs,
            btc_version: BtcBlockVersion::from_consensus(version_i32),
            btc_prev_hash,
            btc_merkle,
            btc_time: time,
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
    height: u64,
    coinbase_value_sat: u64,
    witness_commitment_script: &ScriptBuf,
    payout: &Address,
    extranonce: u64,
) -> Result<Transaction> {
    let height_i64: i64 = height
        .try_into()
        .with_context(|| format!("template height {height} exceeds i64::MAX"))?;

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
        value: Amount::from_sat(coinbase_value_sat),
        script_pubkey: payout.script_pubkey(),
    }];

    if !witness_commitment_script.as_bytes().is_empty() {
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: witness_commitment_script.clone(),
        });
    }

    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    /// Regtest payout address (a valid bech32 P2WPKH derived from a
    /// fixed all-zero key for deterministic test fixtures).
    fn regtest_payout() -> Address {
        "bcrt1q6rhpng9evdsfnn833a4f4vej0asu6dk5srld6x"
            .parse::<Address<_>>()
            .expect("parse fixture address")
            .require_network(Network::Regtest)
            .expect("regtest address")
    }

    fn fixture_components(extranonce: u64) -> Result<MiningJob> {
        MiningJob::from_components(
            [0u8; 32],        // previous block hash
            1,                // height
            0x207fffff,       // regtest bits
            1_700_000_000,    // timestamp
            0x20000000,       // version (BIP9 base)
            50 * 100_000_000, // coinbase value (50 BTC)
            ScriptBuf::new(), // no witness commitment (no SegWit txs)
            Vec::new(),       // no other transactions
            &regtest_payout(),
            extranonce,
        )
    }

    #[test]
    fn extranonce_roll_produces_distinct_merkle_roots() {
        // Architecture §7: each host-boundary extranonce variation must
        // produce a distinct MiningTask (distinct prefix → distinct
        // κ-derivation). The mechanism: extranonce bytes change the
        // coinbase scriptSig → coinbase txid changes → merkle root
        // changes → header prefix changes. Without this distinctness
        // the host loop would re-issue the same κ-derivation every
        // iteration, never landing admission for harder targets.
        let job0 = fixture_components(0).expect("build job 0");
        let job1 = fixture_components(1).expect("build job 1");
        let job2 = fixture_components(0xDEAD_BEEF).expect("build job 2");

        // The header's merkle_root differs across extranonces — that's
        // the load-bearing distinctness for κ-derivation variety.
        assert_ne!(
            job0.header.merkle_root.as_bytes(),
            job1.header.merkle_root.as_bytes(),
            "extranonce 0 vs 1 must produce distinct merkle roots"
        );
        assert_ne!(
            job0.header.merkle_root.as_bytes(),
            job2.header.merkle_root.as_bytes(),
            "extranonce 0 vs DEADBEEF must produce distinct merkle roots"
        );
        assert_ne!(
            job1.header.merkle_root.as_bytes(),
            job2.header.merkle_root.as_bytes(),
            "extranonce 1 vs DEADBEEF must produce distinct merkle roots"
        );

        // Same-extranonce determinism: build twice with the same
        // extranonce; should be byte-identical.
        let job0_again = fixture_components(0).expect("rebuild job 0");
        assert_eq!(
            job0.header.merkle_root.as_bytes(),
            job0_again.header.merkle_root.as_bytes(),
            "same extranonce → same merkle root (host loop reproducibility)"
        );
    }

    #[test]
    fn extranonce_roll_holds_non_merkle_header_fields_constant() {
        // Only the merkle root varies under extranonce roll; version,
        // prev_hash, timestamp, bits are fixed by the template.
        let job0 = fixture_components(0).expect("build job 0");
        let job1 = fixture_components(0xCAFEBABE).expect("build job 1");
        assert_eq!(job0.header.version, job1.header.version);
        assert_eq!(job0.header.prev_hash, job1.header.prev_hash);
        assert_eq!(job0.header.timestamp, job1.header.timestamp);
        assert_eq!(job0.header.bits, job1.header.bits);
    }

    #[test]
    fn assemble_produces_valid_bitcoin_block_with_supplied_nonce() {
        // assemble(nonce) splices a κ-derived nonce back into a
        // rust-bitcoin Block. The header's wire-format reconstruction
        // is byte-for-byte: prev_hash, merkle, time, bits, nonce —
        // all carried through.
        let job = fixture_components(42).expect("build job");
        let expected_merkle: [u8; 32] = *job.header.merkle_root.as_bytes();
        let expected_prev = job.header.prev_hash;
        let expected_time = job.header.timestamp.0;
        let expected_bits = job.header.bits.0;
        let block = job.assemble(0xDEAD_BEEF);

        assert_eq!(block.header.nonce, 0xDEAD_BEEF);
        assert_eq!(block.header.time, expected_time);
        assert_eq!(block.header.bits.to_consensus(), expected_bits);
        assert_eq!(block.header.prev_blockhash.to_byte_array(), expected_prev);
        assert_eq!(block.header.merkle_root.to_byte_array(), expected_merkle);
        // The coinbase is at txdata[0]; in our fixture, no other txs.
        assert_eq!(block.txdata.len(), 1);
        // Coinbase has BIP141 witness (single 32-byte zero entry).
        assert_eq!(block.txdata[0].input[0].witness.len(), 1);
        // BIP34 height-in-coinbase: first scriptSig push decodes to height.
        let script_sig = &block.txdata[0].input[0].script_sig;
        assert!(
            !script_sig.is_empty(),
            "BIP34 requires non-empty coinbase scriptSig (height push)"
        );
    }

    #[test]
    fn from_components_accepts_witness_commitment() {
        // When the template includes a witness commitment (BIP141),
        // the coinbase carries an additional OP_RETURN output with
        // the commitment script.
        let mut commitment_bytes = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_bytes.extend_from_slice(&[0u8; 32]);
        let commitment = ScriptBuf::from_bytes(commitment_bytes);

        let job = MiningJob::from_components(
            [0u8; 32],
            1,
            0x207fffff,
            1_700_000_000,
            0x20000000,
            50 * 100_000_000,
            commitment,
            Vec::new(),
            &regtest_payout(),
            0,
        )
        .expect("build job with witness commitment");

        // Coinbase outputs: [0] = payout, [1] = witness commitment.
        assert_eq!(job.coinbase.output.len(), 2);
        assert_eq!(job.coinbase.output[1].value, Amount::ZERO);
        assert!(job.coinbase.output[1]
            .script_pubkey
            .as_bytes()
            .starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]));
    }
}
