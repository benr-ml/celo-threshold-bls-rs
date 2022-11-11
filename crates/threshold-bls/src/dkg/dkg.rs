//! Implements the Distributed Key Generation protocol from
//! [Pedersen](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf).
//! The protocol runs at minimum in two phases and at most in three phases.
use crate::{
    curve::group::{Element, Group},
    dkg::{
        errors::DkgError,
        types::{Complaint, DkgFirstMessage, DkgSecondMessage, EncryptedShare, Node, Nodes},
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
/// It can be used later with G1Scheme/G2Scheme's partial_sign, partial_verify and aggregate.
/// See tests for examples.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DkgOutput<C: Group> {
    /// The list of nodes that successfully ran the protocol until the end.
    pub nodes: Nodes<C>,
    /// The aggregated public key.
    pub vss_pk: PublicPoly<C>,
    /// The private share which corresponds to the participant's index.
    pub share: Share<C::Scalar>,
}

/// Mapping from node id to the share I received from that leader.
pub type SharesMap<C> = HashMap<Idx, <C as Group>::Scalar>;

/// A dealer in the DKG ceremony.
///
/// Can be instantiated with G1Curve or G2Curve.
impl<C: Group> DkgDealer<C> {
    // TODO add an API that generates an ecies sk, and returns the pk & proof of knowledge. To
    // be used when registering as a validator. Also the code that verifies such a message.

    /// Creates a new DkgLeader instance from the provided secret key, set of nodes and RNG.
    pub fn new<R: CryptoRng + RngCore>(
        ecies_sk: C::Scalar,
        nodes: Nodes<C>,
        threshold: usize,
        rng: &mut R,
    ) -> Result<DkgDealer<C>, DkgError> {
        let mut ecies_pk = C::Point::one();
        ecies_pk.mul(&ecies_sk);

        // Check if the public key is in one of the nodes.
        let index = nodes
            .iter()
            .find(|n| &n.1 == &ecies_pk)
            .ok_or_else(|| DkgError::PublicKeyNotFound)?;

        // Generate a secret polynomial and commit to it.
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

    /// Creates the first message to be sent from the leader to the other nodes.
    pub fn create_first_message<R: CryptoRng + RngCore>(&self, rng: &mut R) -> DkgFirstMessage<C> {
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
            .collect();

        DkgFirstMessage {
            dealer: self.id,
            encrypted_shares,
            vss_pk: self.vss_pk.clone(),
        }
    }

    /// Processes the first messages of exactly nodes and creates the second message to be sent
    /// to everyone. It contains the list of complaints on invalid shares. In addition, it returns
    /// a set of valid shares (so far).
    /// Since we assume that at most t-1 of the nodes are malicious, we only need messages from
    /// t nodes to guarantee an unbiasable and unpredictable beacon. (The result is secure with
    /// rushing adversaries as proven in https://eprint.iacr.org/2021/005.pdf.)
    pub fn create_second_message<R: CryptoRng + RngCore>(
        &self,
        messages: &[DkgFirstMessage<C>],
        rng: &mut R,
    ) -> Result<(SharesMap<C>, DkgSecondMessage<C>), DkgError> {
        if messages.len() != self.threshold {
            return Err(DkgError::InvalidNumberOfMessages(self.threshold));
        }

        let my_id = self.id;
        let mut shares = HashMap::new(); // Will include only valid shares.
        let mut next_message = DkgSecondMessage {
            claimer: my_id,
            complaints: Vec::new(),
        };

        for message in messages {
            // Ignore if the threshold is different (and other honest parties will ignore as well).
            if message.vss_pk.degree() != self.threshold - 1 {
                continue;
            }
            // TODO: check that current dealer is in the list of nodes.
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
                                rng,
                            ),
                        ));
                }
            }
        }

        Ok((shares, next_message))
    }

    /// Processes all the second messages, checks all complaints, and updates the local set of
    /// valid shares accordingly.
    /// minimal_threshold is the minimal number of second round messages we expect. Its value is
    /// application dependent but in most cases it should be at least 2t-1 to guarantee that at
    /// least t honest nodes have valid shares.
    pub fn process_responses(
        &self,
        first_messages: &[DkgFirstMessage<C>],
        second_messages: &[DkgSecondMessage<C>],
        shares: SharesMap<C>,
        minimal_threshold: usize,
    ) -> Result<SharesMap<C>, DkgError> {
        if first_messages.len() != self.threshold || second_messages.len() < minimal_threshold {
            return Err(DkgError::InvalidNumberOfMessages(self.threshold));
        }
        // Two hash maps for fast access in the main loop below.
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
                // TODO: check that current claimer is in nodes (and thus in id_to_pk).
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
                    // for security, just saves some work).
                    shares.remove(&m2.claimer);
                    continue 'outer;
                }
            }
        }

        Ok(shares)
    }

    /// Aggregates the valid shares (as returned from process_responses) and the public key.
    pub fn aggregate(
        &self,
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
                    .unwrap() // Safe since the caller already checked that previously.
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
                value: sk,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::G2Curve;
    use crate::schemes::bls12_381::G2Scheme;
    use crate::sig::{SignatureScheme, ThresholdScheme};

    const MSG: [u8; 4] = [1, 2, 3, 4];

    fn gen_keys<C: Group>(n: usize) -> Vec<(Idx, C::Scalar, C::Point)> {
        (1..n + 1)
            .into_iter()
            .map(|id| {
                let private = C::Scalar::rand(&mut thread_rng());
                let mut public = C::Point::one();
                public.mul(&private);
                (id as Idx, private, public)
            })
            .collect()
    }

    fn setup_node<C: Group>(id: usize, keys: &Vec<(Idx, C::Scalar, C::Point)>) -> DkgDealer<C> {
        let nodes = keys
            .iter()
            .map(|(id, _sk, pk)| Node::<C> {
                0: id.clone(),
                1: pk.clone(),
            })
            .collect();
        DkgDealer::<C>::new(
            keys.get(id - 1).unwrap().1.clone(),
            nodes,
            2,
            &mut thread_rng(),
        )
        .unwrap()
    }

    // TODO: add more tests.

    #[test]
    fn test_e2e_happy_flow() {
        type G = G2Curve;

        let keys = gen_keys::<G>(4);
        let d1 = setup_node::<G>(1, &keys);
        let d2 = setup_node::<G>(2, &keys);
        let _d3 = setup_node::<G>(3, &keys);
        let d4 = setup_node::<G>(4, &keys);

        let r1m1 = d1.create_first_message(&mut thread_rng());
        let r1m2 = d2.create_first_message(&mut thread_rng());
        // skip 3
        let _r1m4 = d4.create_first_message(&mut thread_rng());
        let r1_all = vec![r1m1, r1m2];

        let (shares1, r2m1) = d1
            .create_second_message(&r1_all[..], &mut thread_rng())
            .unwrap();
        let (shares2, r2m2) = d2
            .create_second_message(&r1_all[..], &mut thread_rng())
            .unwrap();
        // Note that d4's message is not included but it should still be able to receive shares.
        let (shares4, r2m4) = d4
            .create_second_message(&r1_all[..], &mut thread_rng())
            .unwrap();
        let r2_all = vec![r2m1, r2m2, r2m4];

        let shares1 = d1.process_responses(&r1_all, &r2_all, shares1, 3).unwrap();
        let shares2 = d2.process_responses(&r1_all, &r2_all, shares2, 3).unwrap();
        let shares4 = d4.process_responses(&r1_all, &r2_all, shares4, 3).unwrap();

        let o1 = d1.aggregate(&r1_all, shares1);
        let _o2 = d2.aggregate(&r1_all, shares2);
        let o4 = d4.aggregate(&r1_all, shares4);

        type S = G2Scheme;
        let sig1 = S::partial_sign(&o1.share, &MSG).unwrap();
        let sig4 = S::partial_sign(&o4.share, &MSG).unwrap();

        S::partial_verify(&o1.vss_pk, &MSG, &sig1).unwrap();
        S::partial_verify(&o4.vss_pk, &MSG, &sig4).unwrap();

        let sigs = vec![sig1, sig4];
        let sig = S::aggregate(d1.threshold, &sigs).unwrap();
        S::verify(&o1.vss_pk.get(0), &MSG, &sig).unwrap();
    }
}
