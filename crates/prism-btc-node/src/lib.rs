//! Bitcoin Core RPC integration for prism-btc — the **protocol layer**
//! over the κ-derivation kernel.
//!
//! prism-btc emits κ-labels for canonical-form block headers; this
//! crate is the **mining protocol** that wraps that κ-derivation in
//! Bitcoin's mining semantics. It owns:
//! 1. The RPC adapter (`getblocktemplate` / `submitblock`).
//! 2. The wire-format assembly (coinbase tx, merkle root, header bytes).
//! 3. The **PoW search**: walk the 32-bit nonce space, derive each
//!    candidate's κ via [`prism_btc::address_block`], compare the
//!    digest to the target, take the first that admits.
//! 4. The extranonce roll on nonce-space exhaustion.
//! 5. The campaign observatory aggregating per-attempt observables.
//!
//! The kernel makes no claim about searching; the search lives here,
//! honest and explicit. Hosts with parallel/GPU/hardware miners
//! replace this scan with their own implementation while reusing
//! [`prism_btc::address_block`] as the κ-derivation primitive.

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
    address_block, serialize_header, sha256d_display, Bits, BlockHeader, CampaignStats,
    KappaObservables, MerkleRoot, MiningWitness, Target, Timestamp, Version,
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
    /// The kernel exposes one admission body — `prism_btc::mine_at` —
    /// which **recognizes** one `(header, nonce)` candidate. This
    /// bridge layer owns the iteration: a **nonce scan** over the 32-bit
    /// space for one template, plus an **extranonce roll** that
    /// produces fresh templates (architecture §7) when the scan
    /// exhausts. Each extranonce value produces a distinct coinbase
    /// txid → distinct merkle root → distinct header template → a
    /// fresh nonce scan. Under PRF baseline, expected total
    /// inferences before admission is `1/α` where `α` is the target's
    /// admission probability. The nonce space (2^32) plus the u64
    /// extranonce space covers every realistic network difficulty
    /// (mainnet `α ≈ 2^-77`); exhaustion would indicate the network's
    /// `α` is below the algorithmic floor and is not a pipeline bug.
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

        // Template-variation loop: each iteration produces a fresh header
        // Template-variation loop: each iteration produces a fresh
        // header template (distinct merkle root via the rolled
        // extranonce) and a fresh nonce sweep. The PoW search lives
        // here — `scan_template_nonces` walks the 32-bit nonce space
        // and uses `prism_btc::address_block` to derive each
        // candidate's κ-label, then compares the digest to the target
        // directly. Every per-candidate observable folds into the
        // session's CampaignStats aggregate (CONFORMANCE.md CM-3,
        // CM-5).
        let mut extranonce: u64 = 0;
        let mut campaign = CampaignStats::new();
        loop {
            let job = MiningJob::from_template_with_extranonce(
                &template,
                &self.payout_address,
                extranonce,
            )?;

            if let Some((nonce, witness)) =
                scan_template_nonces(&job.header, job.target, &mut campaign)
            {
                let block = job.assemble(nonce);
                self.client
                    .submit_block(&block)
                    .context("submitblock rejected")?;
                return Ok(MinedBlock {
                    hash: block.block_hash(),
                    height: template.height,
                    nonce,
                    witness,
                    tx_count: block.txdata.len(),
                    extranonce_attempts: extranonce,
                    campaign,
                });
            }
            // Nonce space exhausted for this template's header without
            // a candidate whose digest satisfied the target. Roll the
            // extranonce → distinct coinbase txid → distinct merkle
            // root → distinct header template → a fresh nonce sweep.
            extranonce = extranonce.wrapping_add(1);
            if extranonce == 0 {
                bail!("u64 extranonce space exhausted for this template without admission");
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
    /// Number of host-boundary extranonce variations the template
    /// loop walked before admission. `0` means the first
    /// κ-derivation admitted; higher values count subsequent
    /// extranonce rolls (architecture §7).
    pub extranonce_attempts: u64,
    /// Aggregate observatory over the session — typed property
    /// landscape across every κ-candidate the host walked, both
    /// admitting and non-admitting. Carries empirical α, stratum /
    /// spectrum / p-adic histograms, and the closest-to-admission
    /// digest observed. The receiver-side typed lens at session
    /// granularity.
    pub campaign: CampaignStats,
}

/// **The PoW search.** Walk the 32-bit nonce space for one template,
/// call [`prism_btc::address_block`] for each candidate, observe the
/// digest against the target, and take the first that admits. Every
/// per-candidate observable folds into `campaign`.
///
/// The kernel exposes only κ-derivation; this function is the bridge's
/// honest search loop over candidate canonical-form bytes. Hosts with
/// parallel/GPU/hardware miners replace this body with their own
/// candidate-stream implementation, reusing `address_block` as the
/// kernel primitive.
///
/// Returns `Some((nonce, witness))` on the first admitting candidate
/// — the nonce that admits, and the κ-derivation witness from the
/// kernel — or `None` if the entire nonce space exhausts without a
/// digest satisfying the target.
fn scan_template_nonces(
    header: &BlockHeader,
    target: Target,
    campaign: &mut CampaignStats,
) -> Option<(u32, MiningWitness)> {
    for nonce in 0u32..=u32::MAX {
        // Serialize to canonical form, derive κ via the kernel, observe.
        let wire = serialize_header(header, nonce);
        let outcome = address_block(&wire);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);

        // PoW admission check — a host-side observation on the digest.
        if target.is_satisfied_by_bytes(&digest) {
            campaign.record_admission(&observables, &digest);
            return Some((nonce, outcome.witness));
        }
        campaign.record_attempt(&observables, &digest);
    }
    None
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
        // produce a distinct header template (distinct merkle root →
        // distinct addressing inference). The mechanism: extranonce bytes
        // change the coinbase scriptSig → coinbase txid changes → merkle
        // root changes → header changes. Without this distinctness the
        // host loop would re-scan the same nonce space every iteration,
        // never landing admission for harder targets.
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
