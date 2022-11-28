//! Threshold Signatures implementation for any type which implements
//! `SignatureScheme`.
use crate::primitives::poly::{Eval, IndexedValue, Poly, PolyError};
use crate::sig::{PartialSignature, SignatureScheme, ThresholdScheme};
use thiserror::Error;

/// A private share which is part of the threshold signing key
pub type Share<S> = IndexedValue<S>;

/// Errors associated with threshold signing, verification and aggregation.
#[derive(Debug, Error)]
pub enum ThresholdError<I: SignatureScheme> {
    /// PolyError is raised when the public key could not be recovered
    #[error("could not recover public key: {0}")]
    PolyError(PolyError),

    /// BincodeError is raised when there is an error in (de)serialization
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),

    /// SignatureError is raised when there is an error in threshold signing
    #[error("signing error {0}")]
    SignatureError(I::Error),

    /// NotEnoughPartialSignatures is raised if the signatures provided for aggregation
    /// were fewer than the threshold
    #[error("not enough partial signatures: {0}/{1}")]
    NotEnoughPartialSignatures(usize, usize),
}

impl<I: SignatureScheme> ThresholdScheme for I {
    type Error = ThresholdError<I>;

    fn partial_sign(
        share: &Share<Self::Private>,
        msg: &[u8],
    ) -> Result<PartialSignature<Self::Signature>, <Self as ThresholdScheme>::Error> {
        let sig = Self::sign(&share.value, msg).map_err(ThresholdError::SignatureError)?;
        Ok(PartialSignature {
            index: share.index,
            value: sig,
        })
    }

    fn partial_verify(
        vss_pk: &Poly<Self::Public>,
        msg: &[u8],
        partial_sig: &PartialSignature<Self::Signature>,
    ) -> Result<(), <Self as ThresholdScheme>::Error> {
        let public_i = vss_pk.eval(partial_sig.index);
        Self::verify(&public_i.value, msg, &partial_sig.value)
            .map_err(ThresholdError::SignatureError)
    }

    fn aggregate(
        threshold: usize,
        partials: &[PartialSignature<Self::Signature>],
    ) -> Result<Self::Signature, <Self as ThresholdScheme>::Error> {
        if threshold > partials.len() {
            return Err(ThresholdError::NotEnoughPartialSignatures(
                partials.len(),
                threshold,
            ));
        }

        let partials = partials
            .iter()
            .map(|partial| Eval {
                index: partial.index,
                value: partial.value.clone(),
            })
            .collect();

        let recovered_sig = Poly::<Self::Signature>::recover_c0(threshold, partials)
            .map_err(ThresholdError::PolyError)?;
        Ok(recovered_sig)
    }
}

use crate::{
    curve::bls12381::PairingCurve as PCurve,
    sig::bls::{G1Scheme, G2Scheme},
};

pub mod test_utils {
    use crate::curve::group::Element;
    use crate::primitives::poly::{Idx, Poly};
    use crate::sig::{PartialSignature, Share, SignatureScheme, ThresholdScheme};

    const MSG: [u8; 4] = [1, 2, 3, 4];

    pub fn create_vss_pk_and_shares<T: ThresholdScheme>(
        n: usize,
        t: usize,
    ) -> (Vec<Share<T::Private>>, Poly<T::Public>) {
        let private = Poly::<T::Private>::new(t - 1);
        let shares = (1..(n + 1))
            .map(|i| private.eval(i as Idx))
            .map(|e| Share {
                index: e.index,
                value: e.value,
            })
            .collect();
        (shares, private.commit())
    }

    pub fn check_shares<T: ThresholdScheme + SignatureScheme>(
        num_of_shares_to_check: usize,
        shares: &Vec<Share<T::Private>>,
        vss_public: &Poly<T::Public>,
    ) -> bool {
        shares.iter().take(num_of_shares_to_check).all(|share| {
            let mut commit = T::Public::one();
            commit.mul(&share.value);
            let pub_eval = vss_public.eval(share.index);
            pub_eval.value == commit
        })
    }

    pub fn compute_partial_sigs<T: ThresholdScheme + SignatureScheme>(
        t: usize,
        shares: &Vec<Share<T::Private>>,
    ) -> Vec<PartialSignature<T::Signature>> {
        shares
            .iter()
            .take(t)
            .map(|s| T::partial_sign(s, &MSG).unwrap())
            .collect()
    }

    pub fn process_partial_sigs<T: ThresholdScheme + SignatureScheme>(
        partials: &Vec<PartialSignature<T::Signature>>,
        vss_public: &Poly<T::Public>,
        to_verify: bool,
    ) -> bool {
        if to_verify {
            assert_eq!(
                false,
                partials
                    .iter()
                    .any(|p| T::partial_verify(&vss_public, &MSG, &p).is_err())
            );
        }
        let final_sig = T::aggregate(partials.len(), &partials).unwrap();
        T::verify(vss_public.public_key(), &MSG, &final_sig).is_ok()
    }

    pub fn test_threshold_scheme<T: ThresholdScheme + SignatureScheme>(n: usize, t: usize) {
        // Checks are done on n shares, even though in practice t will be used.
        let (shares, public) = create_vss_pk_and_shares::<T>(n, t);
        assert_eq!(true, check_shares::<T>(n, &shares, &public));
        let sigs = compute_partial_sigs::<T>(n, &shares);
        assert_eq!(true, process_partial_sigs::<T>(&sigs, &public, true));
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;

    // TODO: add more tests.

    #[test]
    fn threshold_e2e_g1() {
        type S = G1Scheme<PCurve>;
        test_threshold_scheme::<S>(256, 128);
    }

    #[test]
    fn threshold_e2e_g2() {
        type S = G2Scheme<PCurve>;
        test_threshold_scheme::<S>(256, 128);
    }
}
