//! # Threshold BLS Signatures
//!
//! This crate provides implementations for BLS signatures on G1 and G2, with additional support
//! for blind and threshold signing modes.
//!
//! ## Normal BLS Signatures
//!
//! ```rust
//! // import the instantiated scheme and the traits for signing and generating keys
//! use threshold_bls::{
//!     schemes::bls12_381::G1Scheme as SigScheme,
//!     sig::{Scheme, SignatureScheme}
//! };
//!
//! let (private, public) = SigScheme::keypair(&mut rand::thread_rng());
//! let msg = b"hello";
//! let sig = SigScheme::sign(&private, &msg[..]).unwrap();
//! SigScheme::verify(&public, &msg[..], &sig).expect("signature should be verified");
//! ```
//!
//! ## Threshold Signatures
//!
//! First a threshold keypair must be generated. This is done utilizing [polynomials](poly).
//! Each share then proceeds to sign the message, to generate a partial signature. Once enough
//! partial signatures are produced, they can be combined to a threshold signature, which can be
//! verified against the threshold public key. Each partial signature can also be individually partially
//! verified against the public polynomial.
//!
//! ```rust
//! use threshold_bls::{
//!     primitives::poly::{Poly, Idx},
//!     schemes::bls12_381::G1Scheme as SigScheme,
//!     sig::{Scheme, SignatureScheme, ThresholdScheme, Share}
//! };
//!
//! let (n, t) = (5, 3);
//! // create the private key polynomial
//! let private_poly = Poly::<<SigScheme as Scheme>::Private>::new(t - 1);
//!
//! // Evaluate it at `n` points to generate the shares
//! let shares = (0..n)
//!     .map(|i| {
//!         let eval = private_poly.eval(i as Idx);
//!         Share {
//!             index: eval.index,
//!             private: eval.value,
//!         }
//!     })
//!     .collect::<Vec<_>>();
//!
//! // Get the public polynomial
//! let public_poly = private_poly.commit();
//! let threshold_public_key = public_poly.public_key();
//!
//! // Generate the partial signatures
//! let msg = b"hello";
//!
//! let partials = shares
//!     .iter()
//!     .map(|s| SigScheme::partial_sign(s, &msg[..]).unwrap())
//!     .collect::<Vec<_>>();
//!
//! // each partial sig can be partially verified against the public polynomial
//! partials.iter().for_each(|partial| {
//!     SigScheme::partial_verify(&public_poly, &msg[..], &partial).unwrap();
//! });
//!
//! // generate the threshold sig
//! let threshold_sig = SigScheme::aggregate(t, &partials).unwrap();
//!
//! SigScheme::verify(
//!     &threshold_public_key,
//!     &msg[..],
//!     &threshold_sig
//! ).unwrap();
//! ```
//!
//!
//!
//! # Misc. Notes
//!
//! ### Supporting a new curve
//!
//! Curves are implemented in the [`curve`] module. In order to support a new curve,
//! the trait [`PairingCurve`] must be implemented for it. This in turn requires that
//! you define the pairing-friendly curve's `Scalar` and `G_T` fields, its
//! G1 and G2 groups and implement the `Scalar`, `Element` and `Point` traits for them.
//! For reference, use the [existing implementation of BLS12-377](bls12_377) which wraps the implementation
//! from [Zexe](https://github.com/scipr-lab/zexe/).
//!
//! ### Switching Groups
//!
//! `G1Scheme` can be drop-in replaced with `G2Scheme` (and vice-versa) depending on which group you
//! want keys and signatures to be in.
//!
//! Before:
//!
//! ```rust
//! use threshold_bls::sig::G1Scheme as SigScheme;
//! ```
//!
//! After:
//!
//! ```rust
//! use threshold_bls::sig::G2Scheme as SigScheme;
//! ```
//!
//! ## Features
//!
//! Curently there are two curves available, `BLS12 381` and `BLS 377`. By default they are both
//! enabled both, but you can select which one you want to use using the features
//! `bls12_381` and `bls_377`.
//!
//! You can use them like this when adding the dependency to your `Cargo.toml` file.
//!
//! Only BLS12-381:
//!
//! ```toml
//! threshold-bls = { version = "0.1", default-features = false, features = ["bls12_381"] }
//! ```
//!
//! Only BLS12-377:
//!
//! ```toml
//! threshold-bls = { version = "0.1", default-features = false, features = ["bls12_377"] }
//! ```
//!
//! Both:
//!
//! ```toml
//! threshold-bls = { version = "0.1" }
//! ```
//!
//! [poly]: ./poly/index.html
//! [bls12_377]: ./curve/zexe/index.html
//!
//! [`curve`]: ./curve/index.html
//! [`SignatureSchemeExt`]: ./sig/trait.SignatureSchemeExt.html

/// Curve implementations for the traits defined in the [`group`](group/index.html) module.
pub mod curve;

pub mod primitives;

/// BLS Signature implementations. Supports blind and threshold signatures.
pub mod sig;

pub mod dkg;

/// Pre-instantiated signature schemes for each curve
pub mod schemes {
    use crate::sig::{G1Scheme, G2Scheme};

    pub mod bls12_381 {
        use crate::curve::bls12381::PairingCurve;

        pub use crate::curve::bls12381::{G1Curve, G2Curve};

        /// Public Keys on G1, Signatures on G2
        pub type G1Scheme = super::G1Scheme<PairingCurve>;
        /// Public Keys on G2, Signatures on G1
        pub type G2Scheme = super::G2Scheme<PairingCurve>;
    }
}
