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

use crate::curve::group::{Element, Group};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// crypto imports
use chacha20poly1305::{
    aead::{Aead, Error as AError, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

// re-export for usage by dkg primitives
pub use chacha20poly1305::aead::Error as EciesError;

const NONCE_LENGTH: usize = 12;
const EPHEMERAL_KEY_LENGTH: usize = 32;

/// A domain separator
const DOMAIN: &str = "ecies:";

/// An ECIES encrypted cipher. Contains the ciphertext's bytes and the ephemeral public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesCipher<C: Group> {
    aead: Vec<u8>,
    ephemeral: C::Point,
}

// A key that allows decrypting a specific EciesCipher along with a proof of correctness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesDelegatedKey<C: Group> {
    // The encryption's key that can be used to decrypt the message.
    key: C::Point,
    // Proof that it is indeed the right element.
    // TODO: verify it's a secure ZK in the groups we work with.
    proof: (C::Point, C::Point, C::Scalar),
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
    let nonce_obj = Nonce::from_slice(&[0u8; NONCE_LENGTH]);
    // instantiate the AEAD scheme
    let aead = ChaCha20Poly1305::new_from_slice(&ephemeral_key).unwrap();
    let aead = aead
        .encrypt(&nonce_obj, &msg[..])
        .expect("aead should not fail");
    EciesCipher { aead, ephemeral }
}

/// Decrypts the message with a secret key (curve scalar) and returns the cleartext
pub fn decrypt<C: Group>(sk: &C::Scalar, cipher: &EciesCipher<C>) -> Result<Vec<u8>, AError> {
    // dh = private * (eph * G) = private * ephPublic
    let mut dh = cipher.ephemeral.clone();
    dh.mul(&sk);
    let ephemeral_key = derive::<C>(&dh);

    let aead = ChaCha20Poly1305::new_from_slice(&ephemeral_key).unwrap();
    let nonce_obj = Nonce::from_slice(&[0u8; NONCE_LENGTH]);
    aead.decrypt(&nonce_obj, &cipher.aead[..])
}

/// Generate an ephemeral key & NIZPoK for the given encryption.
pub fn create_delegated_key<C: Group, R: CryptoRng + RngCore>(
    sk: &C::Scalar,
    cipher: &EciesCipher<C>,
    rng: &mut R,
) -> EciesDelegatedKey<C> {
    // the full ephemeral key.
    let mut key = cipher.ephemeral.clone();
    key.mul(&sk);

    // NIZKPoK for the DDH tuple [G, Ephemeral=eG, PK=sk G, Key=sk eG].
    // Prover selects a random r and sends A=rG, B=reG.
    // Prover computes challenge c and sends z=r+c sk.
    // Verifier checks that zG=A+cPK and zeG=B+cKey.
    let r = C::Scalar::rand(rng);
    let mut a = C::Point::one();
    a.mul(&r);
    let mut b = cipher.ephemeral.clone();
    b.mul(&r);

    // TODO: Derive from a RO for a unique metadata.
    let challenge = C::Scalar::one();
    let mut z = challenge;
    z.mul(sk);
    z.add(&r);

    EciesDelegatedKey {
        key,
        proof: (a, b, z),
    }
}

pub fn decrypt_with_delegated_key<C: Group>(
    delegated_key: &EciesDelegatedKey<C>,
    cipher: &EciesCipher<C>,
    pk: &C::Point,
) -> Result<Vec<u8>, AError> {
    // Verify the NIZK proof.
    // TODO: Derive from a RO for a unique metadata.
    let challenge = C::Scalar::one();
    if !is_valid_relation::<C>(
        &delegated_key.proof.0, // A
        pk,
        &C::Point::one(),
        &delegated_key.proof.2, // z
        &challenge,
    ) || !is_valid_relation::<C>(
        &delegated_key.proof.1, // B
        &delegated_key.key,
        &cipher.ephemeral,
        &delegated_key.proof.2, // z
        &challenge,
    ) {
        return Err(AError);
    }

    let ephemeral_key = derive::<C>(&delegated_key.key);
    let aead = ChaCha20Poly1305::new_from_slice(&ephemeral_key).unwrap();
    let nonce_obj = Nonce::from_slice(&[0u8; NONCE_LENGTH]);
    aead.decrypt(&nonce_obj, &cipher.aead[..])
}

/// Checks if e1 + e2*c = z e3
fn is_valid_relation<C: Group>(
    e1: &C::Point,
    e2: &C::Point,
    e3: &C::Point,
    z: &C::Scalar,
    c: &C::Scalar,
) -> bool {
    let mut expected_e = e2.clone();
    expected_e.mul(c);
    expected_e.add(&e1);
    let mut e = e3.clone();
    e.mul(&z);
    e == expected_e
}

/// Derives an ephemeral key from the provided public key.
fn derive<C: Group>(dh: &C::Point) -> [u8; EPHEMERAL_KEY_LENGTH] {
    let serialized = bincode::serialize(dh).expect("could not serialize element");
    let h = Hkdf::<Sha256>::new(None, &serialized);
    let mut ephemeral_key = [0u8; EPHEMERAL_KEY_LENGTH];
    h.expand(DOMAIN.as_bytes(), &mut ephemeral_key)
        .expect("hkdf should not fail");
    debug_assert!(ephemeral_key.len() == EPHEMERAL_KEY_LENGTH);
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

    #[test]
    fn test_delegated_key() {
        let (sk, pk) = kp();
        let data = vec![1, 2, 3, 4];

        // decryption with the right key OK
        let cipher = encrypt::<G1Curve, _>(&pk, &data, &mut thread_rng());
        let mut delegated_key = create_delegated_key(&sk, &cipher, &mut thread_rng());
        let plaintext = decrypt_with_delegated_key(&delegated_key, &cipher, &pk).unwrap();
        assert_eq!(data, plaintext);

        delegated_key.proof.0.add(&delegated_key.proof.1);
        let plaintext = decrypt_with_delegated_key(&delegated_key, &cipher, &pk);
        assert!(plaintext.is_err());
    }
}
