//! Threshold Signatures implementation for any type which implements
//! [`SignatureScheme`](../trait.SignatureScheme.html)
use crate::primitives::poly::{Eval, Idx, Poly, PolyError};
use crate::sig::{Partial, SignatureScheme, ThresholdScheme};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// A private share which is part of the threshold signing key
pub struct Share<S> {
    /// The share's index in the polynomial
    pub index: Idx,
    /// The scalar corresponding to the share's secret
    pub private: S,
}

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
        private: &Share<Self::Private>,
        msg: &[u8],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        let sig = Self::sign(&private.private, msg).map_err(ThresholdError::SignatureError)?;
        let partial = Eval {
            index: private.index,
            value: sig,
        };
        let ret = bincode::serialize(&partial)?;
        Ok(ret)
    }

    fn partial_verify(
        public: &Poly<Self::Public>,
        msg: &[u8],
        partial: &[u8],
    ) -> Result<(), <Self as ThresholdScheme>::Error> {
        let partial: Eval<Vec<u8>> = bincode::deserialize(partial)?;
        let public_i = public.eval(partial.index);
        Self::verify(&public_i.value, msg, &partial.value).map_err(ThresholdError::SignatureError)
    }

    fn aggregate(
        threshold: usize,
        partials: &[Partial],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        if threshold > partials.len() {
            return Err(ThresholdError::NotEnoughPartialSignatures(
                partials.len(),
                threshold,
            ));
        }

        let valid_partials: Vec<Eval<Self::Signature>> = partials
            .iter()
            .map(|partial| {
                let eval: Eval<Vec<u8>> = bincode::deserialize(&partial)?;
                let sig = bincode::deserialize(&eval.value)?;
                Ok(Eval {
                    index: eval.index,
                    value: sig,
                })
            })
            .collect::<Result<_, <Self as ThresholdScheme>::Error>>()?;

        let recovered_sig = Poly::<Self::Signature>::recover_c0(threshold, valid_partials)
            .map_err(ThresholdError::PolyError)?;
        Ok(bincode::serialize(&recovered_sig).expect("could not serialize"))
    }
}

use crate::{
    curve::bls12381::PairingCurve as PCurve,
    sig::bls::{G1Scheme, G2Scheme},
};

pub mod test_utils {
    use crate::curve::group::Element;
    use crate::primitives::poly::{Idx, Poly};
    use crate::sig::{Partial, Share, SignatureScheme, ThresholdScheme};

    const MSG: [u8; 4] = [1, 2, 3, 4];

    /// extract to dkg lib, and add
    /// - ecies key gen and encryptions
    /// - nizkpok of ecies key, and of first coefficient
    /// - nizkpok in case of frauds
    ///
    pub fn create_vss_pk_and_shares<T: ThresholdScheme>(
        n: usize,
        t: usize,
    ) -> (Vec<Share<T::Private>>, Poly<T::Public>) {
        let private = Poly::<T::Private>::new(t - 1);
        let shares = (1..(n + 1))
            .map(|i| private.eval(i as Idx))
            .map(|e| Share {
                index: e.index,
                private: e.value,
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
            commit.mul(&share.private);
            let pub_eval = vss_public.eval(share.index);
            pub_eval.value == commit
        })
    }

    pub fn compute_partial_sigs<T: ThresholdScheme + SignatureScheme>(
        t: usize,
        shares: &Vec<Share<T::Private>>,
    ) -> Vec<Partial> {
        shares
            .iter()
            .take(t)
            .map(|s| T::partial_sign(s, &MSG).unwrap())
            .collect()
    }

    pub fn process_partial_sigs<T: ThresholdScheme + SignatureScheme>(
        partials: &Vec<Partial>,
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

    #[test]
    fn threshold_g1_128() {
        type S = G1Scheme<PCurve>;
        test_threshold_scheme::<S>(256, 128);
    }

    #[test]
    fn threshold_g2() {
        type S = G2Scheme<PCurve>;
        test_threshold_scheme::<S>(256, 128);
    }
}
