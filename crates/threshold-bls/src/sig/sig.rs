//! Traits for working with signatures and threshold signatures.
pub use super::tbls::Share; // import and re-export it for easier access
use crate::primitives::poly::IndexedValue;
use crate::{
    curve::group::{Element, Point, Scalar},
    primitives::poly::Poly,
};
use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};

/// The `Scheme` trait contains the basic information of the groups over
/// which the signing operations takes places and a way to create a valid key
/// pair.
///
/// The Scheme trait is necessary to implement for "simple" signature scheme as
/// well for threshold based signature scheme.
pub trait Scheme: Debug {
    /// `Private` represents the field over which private keys are represented.
    type Private: Scalar<RHS = Self::Private>;
    /// `Public` represents the group over which the public keys are
    /// represented.
    type Public: Point<RHS = Self::Private> + Serialize + DeserializeOwned;
    /// `Signature` represents the group over which the signatures are represented (not relevant to
    /// all signature schemes).
    type Signature: Point<RHS = Self::Private> + Serialize + DeserializeOwned;

    /// Returns a new fresh keypair usable by the scheme.
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let private = Self::Private::rand(rng);
        let mut public = Self::Public::one();
        public.mul(&private);
        (private, public)
    }
}

/// SignatureScheme is the trait that defines the operations of a signature
/// scheme, namely `sign` and `verify`. Below is an example of using the
/// signature scheme based on BLS, using the BLS12-381 curves.
///
/// ```
///  # {
///  use rand::prelude::*;
///  use threshold_bls::{sig::{SignatureScheme, Scheme, G2Scheme}, curve::group::{Element, Point}};
///  use threshold_bls::curve::bls12381::PairingCurve as PC;
///
///  let msg = vec![1,9,6,9];
///  let (private,public) = G2Scheme::<PC>::keypair(&mut thread_rng());
///  let signature = G2Scheme::<PC>::sign(&private,&msg).unwrap();
///  match G2Scheme::<PC>::verify(&public, &msg, &signature) {
///     Ok(_) => println!("signature is correct!"),
///     Err(e) => println!("signature is invalid: {}",e),
///  };
/// # }
/// ```
/// Note signature scheme handles the format of the signature itself.
pub trait SignatureScheme: Scheme {
    /// Error produced when signing a message
    type Error: Error;

    /// Signs the message with the provided private key and returns a serialized signature
    fn sign(private: &Self::Private, msg: &[u8]) -> Result<Self::Signature, Self::Error>;

    /// Verifies that the signature on the provided message was produced by the public key
    /// TODO: return a bool
    fn verify(public: &Self::Public, msg: &[u8], sig: &Self::Signature) -> Result<(), Self::Error>;
}

pub type PartialSignature<S> = IndexedValue<S>;

/// ThresholdScheme is a threshold-based `t-n` signature scheme. The security of
/// such a scheme means at least `t` participants are required produce a "partial
/// signature" to then produce a regular signature.
pub trait ThresholdScheme: Scheme {
    /// Error produced when partially signing, aggregating or verifying
    type Error: Error;

    /// Partially signs a message with a share of the private key
    fn partial_sign(
        private: &Share<Self::Private>,
        msg: &[u8],
    ) -> Result<PartialSignature<Self::Signature>, Self::Error>;

    /// Verifies a partial signature on a message against the public polynomial
    /// TODO: return a bool
    fn partial_verify(
        public: &Poly<Self::Public>,
        msg: &[u8],
        partial: &PartialSignature<Self::Signature>,
    ) -> Result<(), Self::Error>;

    /// Aggregates all partials signature together. Note that this method does
    /// not verify if the partial signatures are correct or not; it only
    /// aggregates them.
    fn aggregate(
        threshold: usize,
        partials: &[PartialSignature<Self::Signature>],
    ) -> Result<Self::Signature, Self::Error>;
}
