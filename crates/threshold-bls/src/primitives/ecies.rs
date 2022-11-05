//! # ECIES
//!
//! Implements an Elliptic Curve Integrated Encryption Scheme using SHA256 as the Key Derivation
//! Function.
//!
//! # Examples
//!
//! ```rust
//! use threshold_bls::{
//!     primitives::ecies::{encrypt, decrypt},
//!     curve::bls12381::G2Curve,
//!     curve::group::Group,
//!     curve::group::Element,
//!     };
//!
//! let message = b"hello";
//! let rng = &mut rand::thread_rng();
//! let secret_key = <G2Curve as Group>::Scalar::rand(rng);
//! let mut public_key = <G2Curve as Group>::Point::one();
//! public_key.mul(&secret_key);
//!
//! // encrypt the message with the receiver's public key
//! let ciphertext = encrypt::<G2Curve, _>(&public_key, &message[..], rng);
//!
//! // the receiver can then decrypt the ciphertext with their secret key
//! let cleartext = decrypt(&secret_key, &ciphertext).unwrap();
//!
//! assert_eq!(&message[..], &cleartext[..]);
//! ```

use crate::curve::group::{Group, Element};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// crypto imports
use chacha20poly1305::{
    aead::{Aead, Error as AError, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

// re-export for usage by dkg primitives
pub use chacha20poly1305::aead::Error as EciesError;

/// The nonce length
const NONCE_LEN: usize = 12;

/// The ephemeral key length
const KEY_LEN: usize = 32;

/// A domain separator
const DOMAIN: &str = "ecies:";

/// An ECIES encrypted cipher. Contains the ciphertext's bytes as well as the
/// ephemeral public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesCipher<C: Group> {
    /// The ciphertext which was encrypted
    aead: Vec<u8>,
    /// The ephemeral public key corresponding to the scalar which was used to
    /// encrypt the plaintext
    ephemeral: C::Point,
}

/// Encrypts the message with a public key (curve point) and returns a ciphertext
pub fn encrypt<C: Group, R: CryptoRng + RngCore>(
    pk: &C::Point,
    msg: &[u8],
    rng: &mut R,
) -> EciesCipher<C> {
    let eph_secret = C::Scalar::rand(rng);
    let mut ephemeral = C::Point::one();
    ephemeral.mul(&eph_secret);

    // dh = eph(yG) = eph * public
    let mut dh = pk.clone();
    dh.mul(&eph_secret);

    // derive an ephemeral key from the public key
    let ephemeral_key = derive::<C>(&dh);

    // since ECIES uses different key per messages, the nonce can be fixed.
    let nonce_obj = Nonce::from_slice(&[0u8; NONCE_LEN]);

    // instantiate the AEAD scheme
    let aead = ChaCha20Poly1305::new_from_slice(&ephemeral_key).unwrap();
    let aead = aead
        .encrypt(&nonce_obj, &msg[..])
        .expect("aead should not fail");

    EciesCipher {
        aead,
        ephemeral,
    }
}

/// Decrypts the message with a secret key (curve scalar) and returns the cleartext
pub fn decrypt<C: Group>(private: &C::Scalar, cipher: &EciesCipher<C>) -> Result<Vec<u8>, AError> {
    // dh = private * (eph * G) = private * ephPublic
    let mut dh = cipher.ephemeral.clone();
    dh.mul(&private);

    let ephemeral_key = derive::<C>(&dh);

    let aead = ChaCha20Poly1305::new_from_slice(&ephemeral_key).unwrap();

    let nonce_obj = Nonce::from_slice(&[0u8; NONCE_LEN]);

    aead.decrypt(&nonce_obj, &cipher.aead[..])
}

/// Derives an ephemeral key from the provided public key
fn derive<C: Group>(dh: &C::Point) -> [u8; KEY_LEN] {
    let serialized = bincode::serialize(dh).expect("could not serialize element");

    let h = Hkdf::<Sha256>::new(None, &serialized);
    let mut ephemeral_key = [0u8; KEY_LEN];
    h.expand(DOMAIN.as_bytes(), &mut ephemeral_key)
        .expect("hkdf should not fail");

    debug_assert!(ephemeral_key.len() == KEY_LEN);

    ephemeral_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::{G1Curve, Scalar, G1};
    use rand::thread_rng;

    fn kp() -> (Scalar, G1) {
        let secret = Scalar::rand(&mut thread_rng());
        let mut public = G1::one();
        public.mul(&secret);
        (secret, public)
    }

    #[test]
    fn test_decryption() {
        let (s1, _) = kp();
        let (s2, p2) = kp();
        let data = vec![1, 2, 3, 4];

        // decryption with the right key OK
        let mut cipher = encrypt::<G1Curve, _>(&p2, &data, &mut thread_rng());
        let deciphered = decrypt::<G1Curve>(&s2, &cipher).unwrap();
        assert_eq!(data, deciphered);

        // decrypting with wrong private key should fail
        decrypt::<G1Curve>(&s1, &cipher).unwrap_err();

        // having an invalid ciphertext should fail
        cipher.aead = vec![0; 32];
        decrypt::<G1Curve>(&s2, &cipher).unwrap_err();
    }
}
