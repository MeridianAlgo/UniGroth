//! # Memory-Efficient Streaming Prover
#![allow(missing_docs)]
//!
//! Processes witness assignments in fixed-size chunks to bound peak memory,
//! enabling proving for circuits with >2^20 constraints on memory-constrained
//! devices.
//!
//! Instead of materializing the full witness vector, the streaming prover:
//! 1. Splits the witness into chunks of configurable size
//! 2. Computes partial MSM contributions per chunk
//! 3. Accumulates results incrementally
//!
//! References: Bottleneck-free Groth16 (2024), Bellman streaming prover

use ark_ec::CurveGroup;
use ark_ff::PrimeField;

/// Configuration for the streaming prover.
#[derive(Clone, Debug)]
pub struct StreamingConfig {
    /// Number of witness elements to process per chunk.
    /// Smaller = less memory, larger = better throughput.
    /// Default: 2^16 = 65536
    pub chunk_size: usize,
    /// Whether to use parallel MSM within each chunk
    pub parallel_chunks: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1 << 16,
            parallel_chunks: true,
        }
    }
}

impl StreamingConfig {
    /// Create config for a given memory budget (in bytes) and scalar size.
    pub fn from_memory_budget(budget_bytes: usize, scalar_bytes: usize) -> Self {
        let chunk_size = (budget_bytes / scalar_bytes).max(1024);
        Self {
            chunk_size,
            parallel_chunks: true,
        }
    }
}

/// Result of a streaming MSM computation.
pub struct StreamingMSMResult<G: CurveGroup> {
    /// The accumulated MSM result
    pub result: G,
    /// Number of chunks processed
    pub chunks_processed: usize,
    /// Peak memory usage estimate (bytes)
    pub peak_memory_estimate: usize,
}

/// Compute a multi-scalar multiplication in streaming fashion.
///
/// Splits bases and scalars into chunks, computes partial MSMs,
/// and accumulates the results. Peak memory is bounded by
/// chunk_size * (sizeof(base) + sizeof(scalar)).
pub fn streaming_msm<G: CurveGroup>(
    bases: &[G::Affine],
    scalars: &[G::ScalarField],
    config: &StreamingConfig,
) -> StreamingMSMResult<G> {
    assert_eq!(bases.len(), scalars.len());

    let n = bases.len();
    let chunk_size = config.chunk_size.min(n).max(1);
    let num_chunks = (n + chunk_size - 1) / chunk_size;
    let scalar_bytes = std::mem::size_of::<G::ScalarField>();
    let base_bytes = std::mem::size_of::<G::Affine>();
    let peak_memory = chunk_size * (scalar_bytes + base_bytes);

    let mut accumulator = G::zero();
    let mut chunks_processed = 0;

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = (start + chunk_size).min(n);

        let bases_chunk = &bases[start..end];
        let scalars_chunk = &scalars[start..end];

        let partial = G::msm(bases_chunk, scalars_chunk).unwrap_or(G::zero());
        accumulator += partial;
        chunks_processed += 1;
    }

    StreamingMSMResult {
        result: accumulator,
        chunks_processed,
        peak_memory_estimate: peak_memory,
    }
}

/// Streaming witness processor that yields chunk results via callback.
///
/// For circuits too large to fit in memory, this processes the witness
/// in segments and calls `on_chunk` with each partial result.
pub fn streaming_witness_process<F, G, CB>(
    bases: &[G::Affine],
    witness: &[F],
    config: &StreamingConfig,
    mut on_chunk: CB,
) -> G
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
    CB: FnMut(usize, &G),
{
    let n = bases.len().min(witness.len());
    let chunk_size = config.chunk_size.min(n).max(1);
    let num_chunks = (n + chunk_size - 1) / chunk_size;

    let mut accumulator = G::zero();

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = (start + chunk_size).min(n);

        let partial = G::msm(&bases[start..end], &witness[start..end])
            .unwrap_or(G::zero());
        accumulator += partial;
        on_chunk(chunk_idx, &accumulator);
    }

    accumulator
}

/// Estimate peak memory for a given circuit size and streaming config.
pub fn estimate_peak_memory(
    num_constraints: usize,
    config: &StreamingConfig,
) -> StreamingMemoryEstimate {
    let scalar_bytes = 32; // typical for BN254/BLS12-381
    let g1_bytes = 64;
    let g2_bytes = 128;

    let chunk = config.chunk_size.min(num_constraints);

    let non_streaming = num_constraints * (scalar_bytes * 3 + g1_bytes * 3 + g2_bytes);
    let streaming = chunk * (scalar_bytes + g1_bytes) + g1_bytes * 3;

    StreamingMemoryEstimate {
        non_streaming_bytes: non_streaming,
        streaming_bytes: streaming,
        reduction_factor: if streaming > 0 {
            non_streaming as f64 / streaming as f64
        } else {
            0.0
        },
        num_chunks: (num_constraints + chunk - 1) / chunk,
    }
}

/// Memory estimate for streaming vs non-streaming prover.
#[derive(Clone, Debug)]
pub struct StreamingMemoryEstimate {
    /// Memory needed without streaming
    pub non_streaming_bytes: usize,
    /// Memory needed with streaming
    pub streaming_bytes: usize,
    /// Memory reduction factor
    pub reduction_factor: f64,
    /// Number of chunks needed
    pub num_chunks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective as G1};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_streaming_msm_correctness() {
        let mut rng = test_rng();
        let n = 256;

        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<_> = (0..n)
            .map(|_| G1::rand(&mut rng).into_affine())
            .collect();

        let direct = G1::msm(&bases, &scalars).unwrap();

        let config = StreamingConfig {
            chunk_size: 64,
            parallel_chunks: false,
        };
        let streamed = streaming_msm::<G1>(&bases, &scalars, &config);

        assert_eq!(direct, streamed.result);
        assert_eq!(streamed.chunks_processed, 4);
    }

    #[test]
    fn test_streaming_single_chunk() {
        let mut rng = test_rng();
        let n = 32;

        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<_> = (0..n)
            .map(|_| G1::rand(&mut rng).into_affine())
            .collect();

        let config = StreamingConfig {
            chunk_size: 1024,
            parallel_chunks: false,
        };
        let result = streaming_msm::<G1>(&bases, &scalars, &config);

        assert_eq!(result.chunks_processed, 1);
    }

    #[test]
    fn test_memory_estimate() {
        let config = StreamingConfig {
            chunk_size: 1 << 16,
            parallel_chunks: true,
        };
        let est = estimate_peak_memory(1 << 20, &config);

        assert!(est.reduction_factor > 1.0);
        assert_eq!(est.num_chunks, 16);
    }

    #[test]
    fn test_streaming_witness_callback() {
        let mut rng = test_rng();
        let n = 128;

        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<_> = (0..n)
            .map(|_| G1::rand(&mut rng).into_affine())
            .collect();

        let config = StreamingConfig {
            chunk_size: 32,
            parallel_chunks: false,
        };

        let mut callback_count = 0;
        let result = streaming_witness_process::<Fr, G1, _>(
            &bases,
            &scalars,
            &config,
            |_idx, _acc| {
                callback_count += 1;
            },
        );

        assert_eq!(callback_count, 4);
        let direct = G1::msm(&bases, &scalars).unwrap();
        assert_eq!(direct, result);
    }

    #[test]
    fn test_from_memory_budget() {
        let config = StreamingConfig::from_memory_budget(1024 * 1024, 32);
        assert_eq!(config.chunk_size, 1024 * 1024 / 32);
    }
}
