//! Implements the Distributed Key Generation protocol from
//! [Pedersen](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf).
//! The protocol runs at minimum in two phases and at most in three phases.
use crate::{
    curve::group::{Element, Group},
    dkg::{
        errors::DkgError,
        types::{Node, Nodes, Complaint, DkgFirstMessage, DkgSecondMessage, EncryptedShare},
    },
    primitives::{
        ecies::{self, create_delegated_key, EciesDelegatedKey},
        poly::{self, Idx, Poly, PrivatePoly, PublicPoly},
    },
    sig::Share,
};

use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
struct DkgDealer<C: Group> {
    id: Idx,
    ecies_sk: C::Scalar,
    ecies_pk: C::Point,
    nodes: Nodes<C>,
    threshold: usize,
    vss_sk: Poly<C::Scalar>,
    vss_pk: Poly<C::Point>,
}

/// DkgOutput is the final output of the DKG protocol in case it runs
/// successfully.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DkgOutput<C: Group> {
    /// The list of nodes that successfully ran the protocol until the end.
    pub nodes: Vec<Node<C>>,
    /// The aggregated public key.
    pub vss_pk: PublicPoly<C>,
    /// The private share which corresponds to the participant's index.
    pub share: Share<C::Scalar>,
}

/// Mapping from node id to the share I received from that leader.
pub type SharesMap<C> = HashMap<Idx, <C as Group>::Scalar>;

impl<C: Group> DkgDealer<C> {
    /// Creates a new DKG instance from the provided private key, group and RNG.
    pub fn new<R: CryptoRng + RngCore>(
        ecies_sk: C::Scalar,
        nodes: Vec<Node<C>>,
        threshold: usize,
        rng: &mut R,
    ) -> Result<DkgDealer<C>, DkgError> {
        let mut ecies_pk = C::Point::one();
        ecies_pk.mul(&ecies_sk);

        // Check if the public key is in nodes
        let index = nodes
            .iter()
            .find(|n| &n.1 == &ecies_pk)
            .ok_or_else(|| DkgError::PublicKeyNotFound)?;

        // Generate a secret polynomial and commit to it
        let vss_sk = PrivatePoly::<C>::new_from(threshold - 1, rng);
        let vss_pk = vss_sk.commit::<C::Point>();

        Ok(DkgDealer {
            id: index.0,
            ecies_sk,
            ecies_pk,
            nodes,
            threshold,
            vss_sk,
            vss_pk,
        })
    }

    pub fn create_first_message<R: CryptoRng + RngCore>(self, rng: &mut R) -> DkgFirstMessage<C> {
        let encrypted_shares = self
            .nodes
            .iter()
            .map(|n| {
                let share = self.vss_sk.eval(n.id() as Idx);
                let buff = bincode::serialize(&share.value).unwrap();
                let encryption = ecies::encrypt::<C, R>(n.key(), &buff, rng);
                EncryptedShare {
                    receiver: n.id(),
                    encryption,
                }
            })
            .collect::<Vec<_>>();

        DkgFirstMessage {
            dealer: self.id,
            encrypted_shares,
            vss_pk: self.vss_pk.clone(),
        }
    }

    pub fn create_second_message(
        self,
        messages: &[DkgFirstMessage<C>],
    ) -> Result<(SharesMap<C>, DkgSecondMessage<C>), DkgError> {
        // Since we assume that at most t-1 of the parties are malicious, we only need the messages
        // of t parties to guarantee unbiasable and unpredictable beacon.
        if messages.len() != self.threshold {
            return Err(DkgError::InvalidNumberOfMessages(self.threshold));
        }

        let my_id = self.id;
        let mut shares = HashMap::new(); // Will include valid shares.
        let mut next_message = DkgSecondMessage {
            claimer: my_id,
            complaints: Vec::new(),
        };

        for message in messages {
            // Ignore if the threshold is different (and other honest parties will ignore as well).
            if message.vss_pk.degree() != self.threshold - 1 {
                continue;
            }
            // TODO: check that dealer is in the list of nodes.
            // Get the relevant encrypted share (or skip message).
            let encrypted_share = message
                .encrypted_shares
                .iter()
                .find(|n| n.receiver == my_id);
            // No share for me.
            if encrypted_share.is_none() {
                next_message
                    .complaints
                    .push(Complaint::NoShare(message.dealer));
                continue;
            }
            // Decrypt it.
            let share = decrypt_and_check_share(
                &self.ecies_sk,
                my_id,
                message.dealer,
                &message.vss_pk,
                encrypted_share.unwrap(),
            );
            match share {
                Ok(sh) => {
                    shares.insert(message.dealer, sh);
                }
                Err(_) => {
                    next_message
                        .complaints
                        .push(Complaint::InvalidEncryptedShare(
                            message.dealer,
                            create_delegated_key(
                                &self.ecies_sk,
                                &encrypted_share.unwrap().encryption,
                                &mut thread_rng(),
                            ),
                        ));
                }
            }
        }

        Ok((shares, next_message))
    }

    pub fn process_responses(
        self,
        first_messages: &[DkgFirstMessage<C>],
        second_messages: &[DkgSecondMessage<C>],
        shares: SharesMap<C>,
    ) -> Result<SharesMap<C>, DkgError> {
        // We need at least 2f+1 = 2t-1 honest nodes to check their shares to make sure we have
        // enough shares.
        if first_messages.len() != self.threshold || second_messages.len() < self.threshold * 2 - 1
        {
            return Err(DkgError::InvalidNumberOfMessages(self.threshold));
        }
        let id_to_pk: HashMap<Idx, &C::Point> = self.nodes.iter().map(|n| (n.0, &n.1)).collect();
        let id_to_m1: HashMap<Idx, &DkgFirstMessage<C>> =
            first_messages.iter().map(|m| (m.dealer, m)).collect();

        let mut shares = shares;
        'outer: for m2 in second_messages {
            'inner: for complaint in &m2.complaints[..] {
                let leader;
                match complaint {
                    Complaint::NoShare(l) => leader = *l,
                    Complaint::InvalidEncryptedShare(l, _) => leader = *l,
                }
                // Ignore dealers that are already not relevant, or invalid complaints.
                if !shares.contains_key(&leader) {
                    continue 'inner;
                }
                // We assume that the caller makes sure to include messages from the same set of
                // nodes, thus unwrap here is safe.
                let claimer_pk = id_to_pk.get(&m2.claimer).unwrap();
                let relevant_m1 = id_to_m1.get(&leader);
                // If the claim refers to a non existing message, it's an invalid complaint.
                let mut valid_complaint = relevant_m1.is_some();
                if valid_complaint {
                    let encrypted_share = relevant_m1
                        .unwrap()
                        .encrypted_shares
                        .iter()
                        .find(|s| s.receiver == m2.claimer);
                    valid_complaint = match complaint {
                        Complaint::NoShare(_) => {
                            // Check if there is a share.
                            encrypted_share.is_none()
                        }
                        Complaint::InvalidEncryptedShare(leader, delegated_key) => {
                            if encrypted_share.is_none() {
                                false // Strange case indeed, but still an invalid claim.
                            } else {
                                check_delegated_key_and_share(
                                    &delegated_key,
                                    &claimer_pk,
                                    m2.claimer,
                                    *leader,
                                    &relevant_m1.unwrap().vss_pk,
                                    encrypted_share.unwrap(),
                                )
                                .is_err()
                            }
                        }
                    }
                }
                if valid_complaint {
                    // Ignore the dealer from now on, and continue processing complaints from the
                    // current claimer.
                    shares.remove(&leader);
                    continue 'inner;
                } else {
                    // Ignore the claimer from now on, including its other complaints (not critical
                    // for security, it just saves some work).
                    shares.remove(&m2.claimer);
                    continue 'outer;
                }
            }
        }
        Ok(shares)
    }

    pub fn aggregate(
        self,
        first_messages: &[DkgFirstMessage<C>],
        shares: SharesMap<C>,
    ) -> DkgOutput<C> {
        let id_to_m1: HashMap<Idx, &DkgFirstMessage<C>> =
            first_messages.iter().map(|m| (m.dealer, m)).collect();
        let mut nodes = Vec::new();
        let mut vss_pk = PublicPoly::<C>::zero();
        let mut sk = C::Scalar::new();
        for (from_leader, share) in shares {
            nodes.push(
                self.nodes
                    .iter()
                    .find(|n| n.0 == from_leader)
                    .unwrap() // Safe since the caller already
                    .clone(),
            );
            vss_pk.add(&id_to_m1.get(&from_leader).unwrap().vss_pk);
            sk.add(&share);
        }

        DkgOutput {
            nodes,
            vss_pk,
            share: Share {
                index: self.id,
                private: sk,
            },
        }
    }
}

// Helper functions for working with ECIES encryptions.

fn deserialize_and_check_share<C: Group>(
    buff: Vec<u8>,
    my_idx: Idx,
    dealer_idx: Idx,
    vss_pk: &PublicPoly<C>,
) -> Result<C::Scalar, DkgError> {
    let share: C::Scalar = bincode::deserialize(&buff)?;
    if !poly::is_valid_share::<C>(my_idx, &share, vss_pk) {
        return Err(DkgError::InvalidShare(dealer_idx).into());
    }
    Ok(share)
}

fn decrypt_and_check_share<C: Group>(
    sk: &C::Scalar,
    idx: Idx,
    dealer_idx: Idx,
    vss_pk: &PublicPoly<C>,
    encrypted_share: &EncryptedShare<C>,
) -> Result<C::Scalar, DkgError> {
    let buff = ecies::decrypt::<C>(sk, &encrypted_share.encryption)
        .map_err(|err| DkgError::InvalidCiphertext(dealer_idx, err))?;
    deserialize_and_check_share::<C>(buff, idx, dealer_idx, vss_pk)
}

fn check_delegated_key_and_share<C: Group>(
    delegated_key: &EciesDelegatedKey<C>,
    ecies_pk: &C::Point,
    idx: Idx,
    dealer_idx: Idx,
    vss_pk: &PublicPoly<C>,
    encrypted_share: &EncryptedShare<C>,
) -> Result<C::Scalar, DkgError> {
    let buff =
        ecies::decrypt_with_delegated_key(&delegated_key, &encrypted_share.encryption, ecies_pk)
            .map_err(|err| DkgError::InvalidCiphertext(dealer_idx, err))?;
    deserialize_and_check_share::<C>(buff, idx, dealer_idx, vss_pk)
}
