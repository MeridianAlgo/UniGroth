use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_std::{cfg_iter, cfg_iter_mut, vec};

use crate::Vec;
use ark_relations::gr1cs::{
    ConstraintSystemRef, Matrix, Result as R1CSResult, SynthesisError, R1CS_PREDICATE_LABEL,
};
use core::ops::Deref;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
/// Computes the inner product of `terms` with `assignment`.
///
/// This implementation is optimized for both parallel and sequential execution:
/// - In parallel mode, it uses Rayon's parallel iterator for efficient
///   multi-threading
/// - In sequential mode, it processes elements in chunks for better
///   vectorization
///
/// # Performance characteristics
/// - Time complexity: O(n) where n is the number of terms
/// - Space complexity: O(1) in sequential mode, O(log n) in parallel mode due
///   to work splitting
///
/// # Arguments
/// * `terms` - Slice of tuples containing coefficients and their indices
/// * `assignment` - Slice of values to be multiplied with coefficients
pub fn evaluate_constraint<F: PrimeField>(terms: &[(F, usize)], assignment: &[F]) -> F {
    #[cfg(feature = "parallel")]
    if terms.len() < 1000 {
        serial_evaluate_constraint(terms, assignment)
    } else {
        terms
            .par_iter()
            .map(|(coeff, index)| {
                let val = assignment[*index];
                if coeff.is_one() {
                    val
                } else {
                    val * coeff
                }
            })
            .sum()
    }
    #[cfg(not(feature = "parallel"))]
    serial_evaluate_constraint(terms, assignment)
}

fn serial_evaluate_constraint<F: PrimeField>(terms: &[(F, usize)], assignment: &[F]) -> F {
    let mut sum = F::zero();
    // Process elements in chunks for better CPU vectorization
    for chunk in terms.chunks(4) {
        let chunk_sum = chunk
            .iter()
            .map(|(coeff, index)| {
                let val = assignment[*index];
                if coeff.is_one() {
                    val
                } else {
                    val * coeff
                }
            })
            .sum::<F>();
        sum += chunk_sum;
    }
    sum
}

/// Standard 7-FFT h polynomial computation (libsnark-compatible).
///
/// Used for large circuits (> 2^16 constraints) where Dynark's 2n polynomial
/// expansion causes L2 cache thrashing. Unlike `compute_witness_4fft`, this
/// path explicitly computes c_evals and divides pointwise by Z_H on the 2n coset.
///
/// **Key identity**: Z_H(g*zeta^i) = g^n*(-1)^i - 1 -- only two distinct values
/// on the 2n coset (one per parity), so just two field inversions cover all n
/// divisions. Total: 7 FFTs + 2 field inversions.
fn witness_h_standard<F: PrimeField, D: EvaluationDomain<F>>(
    domain: &D,
    mut a: Vec<F>,
    mut b: Vec<F>,
    mut c: Vec<F>,
) -> R1CSResult<Vec<F>> {
    let domain_size = domain.size();
    let double_size = 2 * domain_size;
    let zero = F::zero();

    // 3 iFFTs on n-domain: eval form -> coefficient form
    #[cfg(feature = "parallel")]
    rayon::join(
        || {
            rayon::join(
                || domain.ifft_in_place(&mut a),
                || domain.ifft_in_place(&mut b),
            )
        },
        || domain.ifft_in_place(&mut c),
    );
    #[cfg(not(feature = "parallel"))]
    {
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);
        domain.ifft_in_place(&mut c);
    }

    let coset_2n = D::new(double_size)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?
        .get_coset(F::GENERATOR)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

    a.resize(double_size, zero);
    b.resize(double_size, zero);
    c.resize(double_size, zero);

    // 3 coset FFTs on 2n-domain: coefficient form -> coset evals
    #[cfg(feature = "parallel")]
    rayon::join(
        || {
            rayon::join(
                || coset_2n.fft_in_place(&mut a),
                || coset_2n.fft_in_place(&mut b),
            )
        },
        || coset_2n.fft_in_place(&mut c),
    );
    #[cfg(not(feature = "parallel"))]
    {
        coset_2n.fft_in_place(&mut a);
        coset_2n.fft_in_place(&mut b);
        coset_2n.fft_in_place(&mut c);
    }

    // Z_H(g*zeta^i) = g^n*(-1)^i - 1: constant per parity on 2n-coset.
    // Two precomputed inverses replace n individual field inversions.
    let g_n = F::GENERATOR.pow([domain_size as u64]);
    let z_even_inv = (g_n - F::one())
        .inverse()
        .ok_or(SynthesisError::AssignmentMissing)?;
    let z_odd_inv = (-g_n - F::one())
        .inverse()
        .ok_or(SynthesisError::AssignmentMissing)?;

    let mut h: Vec<F> = cfg_iter!(a)
        .zip(cfg_iter!(b))
        .zip(cfg_iter!(c))
        .enumerate()
        .map(|(i, ((a_i, b_i), c_i))| {
            let z_inv = if i % 2 == 0 { z_even_inv } else { z_odd_inv };
            (*a_i * b_i - c_i) * z_inv
        })
        .collect();

    // 1 icoset FFT: coset evals -> coefficient form
    coset_2n.ifft_in_place(&mut h);
    h.truncate(domain_size - 1);
    Ok(h)
}

/// Computes instance and witness reductions from R1CS to
/// Quadratic Arithmetic Programs (QAPs).
pub trait R1CSToQAP {
    /// Computes a QAP instance corresponding to the R1CS instance defined by
    /// `cs`.
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError>;

    #[inline]
    /// Computes a QAP witness corresponding to the R1CS witness defined by
    /// `cs`.
    fn witness_map<F: PrimeField, D: EvaluationDomain<F>>(
        prover: ConstraintSystemRef<F>,
    ) -> Result<Vec<F>, SynthesisError> {
        let matrices = &prover.to_matrices().unwrap()[R1CS_PREDICATE_LABEL];
        let num_inputs = prover.num_instance_variables();
        let num_constraints = prover.num_constraints();

        let cs = prover.borrow().unwrap();
        let prover = cs.deref();

        let full_assignment = [
            prover.instance_assignment().unwrap(),
            prover.witness_assignment().unwrap(),
        ]
        .concat();

        Self::witness_map_from_matrices::<F, D>(
            matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }

    /// Computes a QAP witness corresponding to the R1CS witness defined by
    /// `cs`.
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>>;

    /// Computes the exponents that the generator uses to calculate base
    /// elements which the prover later uses to compute `h(x)t(x)/delta`.
    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError>;
}

/// Computes the R1CS-to-QAP reduction defined in [`libsnark`](https://github.com/scipr-lab/libsnark/blob/2af440246fa2c3d0b1b0a425fb6abd8cc8b9c54d/libsnark/reductions/r1cs_to_qap/r1cs_to_qap.tcc).
pub struct LibsnarkReduction;

impl R1CSToQAP for LibsnarkReduction {
    #[inline]
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> R1CSResult<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize)> {
        let matrices = &cs.to_matrices().unwrap()[R1CS_PREDICATE_LABEL];
        let domain_size = cs.num_constraints() + cs.num_instance_variables();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(*t);

        // Evaluate all Lagrange polynomials
        let coefficients_time = start_timer!(|| "Evaluate Lagrange coefficients");
        let u = domain.evaluate_all_lagrange_coefficients(*t);
        end_timer!(coefficients_time);

        let qap_num_variables = (cs.num_instance_variables() - 1) + cs.num_witness_variables();

        let mut a = vec![F::zero(); qap_num_variables + 1];
        let mut b = vec![F::zero(); qap_num_variables + 1];
        let mut c = vec![F::zero(); qap_num_variables + 1];

        {
            let start = 0;
            let end = cs.num_instance_variables();
            let num_constraints = cs.num_constraints();
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

        for (i, u_i) in u.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices[0][i] {
                a[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[1][i] {
                b[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[2][i] {
                c[index] += &(*u_i * coeff);
            }
        }

        Ok((a, b, c, zt, qap_num_variables, domain_size))
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>> {
        use crate::optimizations::{FftStrategy, ProverProfile};

        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();
        let zero = F::zero();

        let strategy = ProverProfile::select_fft_strategy(num_constraints);

        match strategy {
            FftStrategy::Standard6Fft => {
                // Standard 7-FFT libsnark path with explicit c_evals.
                // For large circuits (> 2^16) where Dynark 2n expansion causes cache pressure.
                let mut a = vec![zero; domain_size];
                let mut b = vec![zero; domain_size];
                let mut c = vec![zero; domain_size];

                cfg_iter_mut!(a[..num_constraints])
                    .zip(&mut b[..num_constraints])
                    .zip(&mut c[..num_constraints])
                    .zip(&matrices[0])
                    .zip(&matrices[1])
                    .zip(&matrices[2])
                    .for_each(|(((((a, b), c), at_i), bt_i), ct_i)| {
                        *a = evaluate_constraint(at_i, full_assignment);
                        *b = evaluate_constraint(bt_i, full_assignment);
                        *c = evaluate_constraint(ct_i, full_assignment);
                    });

                {
                    let start = num_constraints;
                    let end = start + num_inputs;
                    a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
                }

                witness_h_standard::<F, D>(&domain, a, b, c)
            },

            // Dynark 4/5-FFT: polynomial-multiplication, no c_evals.
            // Derives h from upper coefficients of a*b, saving 2 FFTs vs standard.
            FftStrategy::Dynark5Fft | FftStrategy::Dynark4FftCoset => {
                let mut a = vec![zero; domain_size];
                let mut b = vec![zero; domain_size];

                cfg_iter_mut!(a[..num_constraints])
                    .zip(&mut b[..num_constraints])
                    .zip(&matrices[0])
                    .zip(&matrices[1])
                    .for_each(|(((a, b), at_i), bt_i)| {
                        *a = evaluate_constraint(at_i, full_assignment);
                        *b = evaluate_constraint(bt_i, full_assignment);
                    });

                {
                    let start = num_constraints;
                    let end = start + num_inputs;
                    a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
                }

                let result = crate::optimizations::compute_witness_4fft(&domain, a, b);
                let mut h = result.h_poly;
                h.truncate(domain_size - 1);
                Ok(h)
            },
        }
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        let mut scalars = Vec::with_capacity(max_power);
        let base = zt * delta_inverse;
        let mut acc = base;
        for _ in 0..max_power {
            scalars.push(acc);
            acc *= t;
        }
        Ok(scalars)
    }
}
