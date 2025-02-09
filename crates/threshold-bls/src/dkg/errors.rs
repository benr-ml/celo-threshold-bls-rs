use crate::primitives::{ecies::EciesError, poly, poly::Idx};
use thiserror::Error;

#[derive(Debug, Error)]
/// Errors which may occur during the DKG
pub enum DkgError {
    /// PublicKeyNotFound is raised when the private key given to the DKG init
    /// function does not yield a public key that is included in the group.
    #[error("public key not found in list of participants")]
    PublicKeyNotFound,

    /// InvalidThreshold is raised when creating a group and specifying an
    /// invalid threshold. Either the threshold is too low, inferior to
    /// what `minimum_threshold()` returns or is too large (i.e. larger than the
    /// number of nodes).
    #[error("threshold {0} is not in range [{1},{2}]")]
    InvalidThreshold(usize, usize, usize),

    /// InvalidNumberOfMessages is raised when the DKG has not received t messages.
    #[error("expecting {0} messages")]
    InvalidNumberOfMessages(usize),

    /// Rejected is raised when the participant is rejected from the final
    /// output
    #[error("this participant is rejected from the qualified set")]
    Rejected,

    /// BincodeError is raised when de(serialization) by bincode fails
    #[error("de(serialization failed: {0})")]
    BincodeError(#[from] bincode::Error),

    /// NotDealer is raised when one attempts to call a method of a
    /// dealer during a resharing when it is not a member of the current group.
    #[error("this participant is not a dealer")]
    NotDealer,

    /// NotShareHolder is raised when one attemps to call a method of a share
    /// holder during a resharing when it is a not a share holder in the new
    /// group.
    #[error("this participant is not a share holder")]
    NotShareHolder,

    #[error("invalid recovery during resharing: {0}")]
    InvalidRecovery(#[from] poly::PolyError),

    /// InvalidCipherText returns the error raised when decrypting the encrypted
    /// share.
    #[error("[dealer: {0}] Invalid ciphertext")]
    InvalidCiphertext(Idx, EciesError),
    /// InvalidShare is raised when the share does not corresponds to the public
    /// polynomial associated.
    #[error("[dealer: {0}] Share does not match associated public polynomial")]
    InvalidShare(Idx),
    /// InvalidPublicPolynomial is raised when the public polynomial does not
    /// have the correct degree. Each public polynomial in the scheme must have
    /// a degree equals to `threshold - 1` set for the DKG protocol.
    /// The two fields are (1) the degree of the polynomial and (2) the
    /// second is the degree it should be,i.e. `threshold - 1`.
    #[error("[dealer: {0}] polynomial does not have the correct degree, got: {1}, expected {2}")]
    InvalidPublicPolynomial(Idx, usize, usize),
}
