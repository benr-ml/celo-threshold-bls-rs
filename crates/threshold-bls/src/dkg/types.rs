use crate::curve::group::Group;
use crate::primitives::ecies::{EciesCipher, EciesDelegatedKey};
use crate::primitives::poly::{Idx, PublicPoly};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Node is a participant in the DKG protocol. In a DKG protocol, each
/// participant must be identified both by an index and a public key. At the end
/// of the protocol, if sucessful, the index is used to verify the validity of
/// the share this node holds.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Node<C: Group>(pub Idx, pub C::Point);

impl<C: Group> Node<C> {
    /// index must be positive.
    pub fn new(index: Idx, public: C::Point) -> Self {
        assert!(index > 0);
        Self(index, public)
    }
    /// Returns the node's index
    pub fn id(&self) -> Idx {
        self.0
    }
    /// Returns the node's public key
    pub fn key(&self) -> &C::Point {
        &self.1
    }
}

pub(crate) type Nodes<C> = Vec<Node<C>>;

// TODO: test serialization of everything.

/// DkgFirstMessage holds all encrypted shares a dealer creates during the first
/// phase of the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DkgFirstMessage<C: Group> {
    pub dealer: Idx,
    /// The encrypted shares created by the dealer.
    pub encrypted_shares: Vec<EncryptedShare<C>>,
    /// The commitment of the secret polynomial created by the dealer.
    // TODO: add a proof of possession/knowledge.
    pub vss_pk: PublicPoly<C>,
}

/// EncryptedShare holds the ECIES encryption of a share destined to the
/// `receiver`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct EncryptedShare<C: Group> {
    pub receiver: Idx,
    // TODO: Replace with a Enc(hkdf(g^{sk_i sk_j}), share) instead of sending a random group
    // element, or extend ECIES to work like that.
    pub encryption: EciesCipher<C>,
}

/// A `DkgSecondMessage` is sent during the second phase of the protocol. It includes complaints
/// created by receiver of invalid encrypted shares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DkgSecondMessage<C: Group> {
    pub claimer: Idx,
    // List of complaints against other dealers. Empty if there are non.
    pub complaints: Vec<Complaint<C>>,
}

/// A complaint/fraud claim against a dealer that created invalid encrypted share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub enum Complaint<C: Group> {
    /// The identity of the dealer.
    NoShare(Idx),
    /// The identity of the dealer and the delegated key.
    // An alternative to using ECIES & ZKPoK for complaints is to use different ECIES public key
    // for each sender, and in case of a complaint, simply reveal the relevant secret key.
    // This saves the ZKPoK with the price of publishing one ECIES public key & PoP for each party,
    // resulting in larger communication in the happy path.
    InvalidEncryptedShare(Idx, EciesDelegatedKey<C>),
}
