use alloy_consensus::BlockBody;
use alloy_primitives::{Sealed, B256};
use alloy_rlp::Decodable;
use anyhow::{anyhow, Result};
use kona_derive::{
    errors::{PipelineError, PipelineErrorKind},
    traits::{BlobProvider, Pipeline, SignalReceiver},
    types::Signal,
};
use kona_driver::{Driver, DriverError, DriverPipeline, DriverResult, Executor, TipCursor};
use kona_executor::TrieDBProvider;
use kona_genesis::RollupConfig;
use kona_preimage::{CommsClient, PreimageKey};
use kona_proof::{
    errors::OracleProviderError, executor::KonaExecutor, l1::OracleL1ChainProvider,
    l2::OracleL2ChainProvider, sync::new_pipeline_cursor, BootInfo, FlushableCache, HintType,
};
use kona_protocol::L2BlockInfo;
use kona_rpc::OpAttributesWithParent;
use op_alloy_consensus::{OpBlock, OpTxEnvelope, OpTxType};
use std::{fmt::Debug, sync::Arc};
use tracing::{error, info, warn};

use crate::{precompiles::zkvm_handle_register, witness::WitnessData, BlobStore};

cfg_if::cfg_if! {
    if #[cfg(feature = "celestia")] {
        use hana_oracle::{
            pipeline::OraclePipeline as CelestiaOraclePipeline, provider::OracleCelestiaProvider,
        };
    } else {
        use kona_proof::l1::OraclePipeline;
    }
}

/// Runs the OP Succinct client using the given witness data.
pub async fn run_witness_client(witness: WitnessData) -> Result<BootInfo> {
    println!("cycle-tracker-report-start: oracle-verify");
    // Check the preimages in the witness are valid.
    witness.preimage_store.check_preimages().expect("Failed to validate preimages");
    println!("cycle-tracker-report-end: oracle-verify");

    // Create an Arc of the preimage store.
    let oracle = Arc::new(witness.preimage_store);

    // Create a BlobStore from the blobs in the witness and verifies them for correctness.
    println!("cycle-tracker-report-start: blob-verification");
    let beacon = BlobStore::from(witness.blob_data);
    println!("cycle-tracker-report-end: blob-verification");

    // Run the client.
    run_opsuccinct_client(oracle, beacon).await
}

// Sourced from https://github.com/op-rs/kona/tree/main/bin/client/src/single.rs
/// Runs the OP Succinct client using the given oracle and blob provider.
pub async fn run_opsuccinct_client<O, B>(oracle: Arc<O>, beacon: B) -> Result<BootInfo>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
{
    ////////////////////////////////////////////////////////////////
    //                          PROLOGUE                          //
    ////////////////////////////////////////////////////////////////

    let boot = match BootInfo::load(oracle.as_ref()).await {
        Ok(boot) => boot,
        Err(e) => {
            return Err(anyhow!("Failed to load boot info: {:?}", e));
        }
    };

    let boot_clone = boot.clone();

    let rollup_config = Arc::new(boot.rollup_config);
    let safe_head_hash = fetch_safe_head_hash(oracle.as_ref(), boot.agreed_l2_output_root).await?;

    let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, oracle.clone());
    let mut l2_provider =
        OracleL2ChainProvider::new(safe_head_hash, rollup_config.clone(), oracle.clone());

    // Fetch the safe head's block header.
    let safe_head = l2_provider
        .header_by_hash(safe_head_hash)
        .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

    // If the claimed L2 block number is less than the safe head of the L2 chain, the claim is
    // invalid.
    if boot.claimed_l2_block_number < safe_head.number {
        return Err(anyhow!(
            "Claimed L2 block number {claimed} is less than the safe head {safe}",
            claimed = boot.claimed_l2_block_number,
            safe = safe_head.number
        ));
    }

    // In the case where the agreed upon L2 output root is the same as the claimed L2 output root,
    // trace extension is detected and we can skip the derivation and execution steps.
    if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
        info!(
            target: "client",
            "Trace extension detected. State transition is already agreed upon.",
        );
        return Ok(boot_clone);
    }
    ////////////////////////////////////////////////////////////////
    //                   DERIVATION & EXECUTION                   //
    ////////////////////////////////////////////////////////////////

    // Create a new derivation driver with the given boot information and oracle.
    let cursor =
        new_pipeline_cursor(rollup_config.as_ref(), safe_head, &mut l1_provider, &mut l2_provider)
            .await?;
    l2_provider.set_cursor(cursor.clone());

    let pipeline = {
        #[cfg(feature = "celestia")]
        {
            CelestiaOraclePipeline::new(
                rollup_config.clone(),
                cursor.clone(),
                oracle.clone(),
                beacon,
                l1_provider.clone(),
                l2_provider.clone(),
                OracleCelestiaProvider::new(oracle.clone()),
            )
            .await?
        }
        #[cfg(not(feature = "celestia"))]
        {
            OraclePipeline::new(
                rollup_config.clone(),
                cursor.clone(),
                oracle.clone(),
                beacon,
                l1_provider.clone(),
                l2_provider.clone(),
            )
            .await?
        }
    };
    let executor = KonaExecutor::new(
        &rollup_config,
        l2_provider.clone(),
        l2_provider,
        Some(zkvm_handle_register),
        None,
    );
    let mut driver = Driver::new(cursor, executor, pipeline);
    // Run the derivation pipeline until we are able to produce the output root of the claimed
    // L2 block.

    // Use custom advance to target with cycle tracking.
    #[cfg(target_os = "zkvm")]
    println!("cycle-tracker-report-start: block-execution-and-derivation");
    let (safe_head, output_root) =
        advance_to_target(&mut driver, rollup_config.as_ref(), Some(boot.claimed_l2_block_number))
            .await?;
    #[cfg(target_os = "zkvm")]
    println!("cycle-tracker-report-end: block-execution-and-derivation");

    ////////////////////////////////////////////////////////////////
    //                          EPILOGUE                          //
    ////////////////////////////////////////////////////////////////

    if output_root != boot.claimed_l2_output_root {
        return Err(anyhow!(
            "Failed to validate L2 block #{number} with claimed output root {claimed_output_root}. Got {output_root} instead",
            number = safe_head.block_info.number,
            output_root = output_root,
            claimed_output_root = boot.claimed_l2_output_root,
        ));
    }

    info!(
        target: "client",
        "Successfully validated L2 block #{number} with output root {output_root}",
        number = safe_head.block_info.number,
        output_root = output_root
    );

    #[cfg(target_os = "zkvm")]
    {
        std::mem::forget(driver);
        std::mem::forget(l1_provider);
        std::mem::forget(oracle);
        std::mem::forget(rollup_config);
    }

    Ok(boot_clone)
}

/// Fetches the safe head hash of the L2 chain based on the agreed upon L2 output root in the
/// [BootInfo].
async fn fetch_safe_head_hash<O>(
    caching_oracle: &O,
    agreed_l2_output_root: B256,
) -> Result<B256, OracleProviderError>
where
    O: CommsClient,
{
    let mut output_preimage = [0u8; 128];
    HintType::StartingL2Output
        .with_data(&[agreed_l2_output_root.as_ref()])
        .send(caching_oracle)
        .await?;
    caching_oracle
        .get_exact(PreimageKey::new_keccak256(*agreed_l2_output_root), output_preimage.as_mut())
        .await?;

    output_preimage[96..128].try_into().map_err(OracleProviderError::SliceConversion)
}

// Sourced from kona/crates/driver/src/core.rs with modifications to use the L2 provider's caching
// system. After each block execution, we update the L2 provider's caches (header_by_number,
// block_by_number, system_config_by_number, l2_block_info_by_number) with the new block data. This
// ensures subsequent lookups for this block number can be served directly from cache rather than
// requiring oracle queries.
/// Advances the derivation pipeline to the target block number.
///
/// ## Takes
/// - `cfg`: The rollup configuration.
/// - `target`: The target block number.
///
/// ## Returns
/// - `Ok((number, output_root))` - A tuple containing the number of the produced block and the
///   output root.
/// - `Err(e)` - An error if the block could not be produced.
pub async fn advance_to_target<E, DP, P>(
    driver: &mut Driver<E, DP, P>,
    cfg: &RollupConfig,
    mut target: Option<u64>,
) -> DriverResult<(L2BlockInfo, B256), E::Error>
where
    E: Executor + Send + Sync + Debug,
    DP: DriverPipeline<P> + Send + Sync + Debug,
    P: Pipeline + SignalReceiver + Send + Sync + Debug,
{
    loop {
        // Check if we have reached the target block number.
        let pipeline_cursor = driver.cursor.read();
        let tip_cursor = pipeline_cursor.tip();
        if let Some(tb) = target {
            if tip_cursor.l2_safe_head.block_info.number >= tb {
                info!(target: "client", "Derivation complete, reached L2 safe head.");
                return Ok((tip_cursor.l2_safe_head, tip_cursor.l2_safe_head_output_root));
            }
        }

        #[cfg(target_os = "zkvm")]
        println!("cycle-tracker-report-start: payload-derivation");
        let OpAttributesWithParent { mut attributes, .. } = match driver
            .pipeline
            .produce_payload(tip_cursor.l2_safe_head)
            .await
        {
            Ok(attrs) => attrs,
            Err(PipelineErrorKind::Critical(PipelineError::EndOfSource)) => {
                warn!(target: "client", "Exhausted data source; Halting derivation and using current safe head.");

                // Adjust the target block number to the current safe head, as no more blocks
                // can be produced.
                if target.is_some() {
                    target = Some(tip_cursor.l2_safe_head.block_info.number);
                };

                // If we are in interop mode, this error must be handled by the caller.
                // Otherwise, we continue the loop to halt derivation on the next iteration.
                if cfg.is_interop_active(driver.cursor.read().l2_safe_head().block_info.number) {
                    return Err(PipelineError::EndOfSource.crit().into());
                } else {
                    continue;
                }
            }
            Err(e) => {
                error!(target: "client", "Failed to produce payload: {:?}", e);
                return Err(DriverError::Pipeline(e));
            }
        };
        #[cfg(target_os = "zkvm")]
        println!("cycle-tracker-report-end: payload-derivation");

        driver.executor.update_safe_head(tip_cursor.l2_safe_head_header.clone());

        #[cfg(target_os = "zkvm")]
        println!("cycle-tracker-report-start: block-execution");
        let execution_result = match driver.executor.execute_payload(attributes.clone()).await {
            Ok(header) => header,
            Err(e) => {
                error!(target: "client", "Failed to execute L2 block: {}", e);

                if cfg.is_holocene_active(attributes.payload_attributes.timestamp) {
                    // Retry with a deposit-only block.
                    warn!(target: "client", "Flushing current channel and retrying deposit only block");

                    // Flush the current batch and channel - if a block was replaced with a
                    // deposit-only block due to execution failure, the
                    // batch and channel it is contained in is forwards
                    // invalidated.
                    driver.pipeline.signal(Signal::FlushChannel).await?;

                    // Strip out all transactions that are not deposits.
                    attributes.transactions = attributes.transactions.map(|txs| {
                        txs.into_iter()
                            .filter(|tx| (!tx.is_empty() && tx[0] == OpTxType::Deposit as u8))
                            .collect::<Vec<_>>()
                    });

                    // Retry the execution.
                    driver.executor.update_safe_head(tip_cursor.l2_safe_head_header.clone());
                    match driver.executor.execute_payload(attributes.clone()).await {
                        Ok(header) => header,
                        Err(e) => {
                            error!(
                                target: "client",
                                "Critical - Failed to execute deposit-only block: {e}",
                            );
                            return Err(DriverError::Executor(e));
                        }
                    }
                } else {
                    // Pre-Holocene, discard the block if execution fails.
                    continue;
                }
            }
        };
        #[cfg(target_os = "zkvm")]
        println!("cycle-tracker-report-end: block-execution");

        // Construct the block.
        let block = OpBlock {
            header: execution_result.block_header.inner().clone(),
            body: BlockBody {
                transactions: attributes
                    .transactions
                    .unwrap_or_default()
                    .into_iter()
                    .map(|tx| OpTxEnvelope::decode(&mut tx.as_ref()).map_err(DriverError::Rlp))
                    .collect::<DriverResult<Vec<OpTxEnvelope>, E::Error>>()?,
                ommers: Vec::new(),
                withdrawals: None,
            },
        };

        // Get the pipeline origin and update the tip cursor.
        let origin = driver.pipeline.origin().ok_or(PipelineError::MissingOrigin.crit())?;
        let l2_info =
            L2BlockInfo::from_block_and_genesis(&block, &driver.pipeline.rollup_config().genesis)?;
        let tip_cursor = TipCursor::new(
            l2_info,
            execution_result.block_header,
            driver.executor.compute_output_root().map_err(DriverError::Executor)?,
        );

        // Advance the derivation pipeline cursor
        drop(pipeline_cursor);
        driver.cursor.write().advance(origin, tip_cursor);

        // Add forget calls to save cycles
        #[cfg(target_os = "zkvm")]
        std::mem::forget(block);
    }
}
