//! Instantiations of BLS12-381 elements.

use crate::curve::group::{self, Element, PairingCurve as PC, Point, Scalar as Sc};
use ff::{Field, PrimeField};
use groupy::CurveProjective;
use paired::bls12_381::{Bls12, Fq12, Fr, FrRepr, G1 as PG1, G2 as PG2};
use paired::Engine;
use rand_core::{CryptoRng, RngCore};

pub type Scalar = Fr;
pub type G1 = PG1;
pub type G2 = PG2;
pub type GT = Fq12;

impl Sc for Scalar {
    fn set_int(&mut self, i: u64) {
        *self = Fr::from_repr(FrRepr::from(i)).unwrap();
    }

    fn inverse(&self) -> Option<Self> {
        ff::Field::inverse(self)
    }

    fn negate(&mut self) {
        ff::Field::negate(self);
    }

    fn sub(&mut self, other: &Self) {
        self.sub_assign(other);
    }
}

impl Element for Scalar {
    type RHS = Fr;

    fn new() -> Self {
        ff::Field::zero()
    }
    fn one() -> Self {
        ff::Field::one()
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &Fr) {
        self.mul_assign(mul)
    }
    fn rand<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Fr::random(rng)
    }
}

/// G1 points can be multiplied by Fr elements
impl Element for G1 {
    type RHS = Scalar;

    fn new() -> Self {
        groupy::CurveProjective::zero()
    }
    fn one() -> Self {
        groupy::CurveProjective::one()
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.mul_assign(FrRepr::from(*mul))
    }
    fn rand<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        G1::random(rng)
    }
}

/// G2 points can be multiplied by Fr elements
impl Element for G2 {
    type RHS = Scalar;

    fn new() -> Self {
        groupy::CurveProjective::zero()
    }
    fn one() -> Self {
        groupy::CurveProjective::one()
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.mul_assign(FrRepr::from(*mul))
    }
    fn rand<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        G2::random(rng)
    }
}

impl Element for GT {
    type RHS = GT;

    fn new() -> Self {
        ff::Field::zero()
    }
    fn one() -> Self {
        ff::Field::one()
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &GT) {
        self.mul_assign(mul)
    }
    fn rand<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        ff::Field::random(rng)
    }
}

impl Point for G1 {
    fn map(&mut self, data: &[u8]) {
        *self = G1::hash(data);
    }
}

impl Point for G2 {
    fn map(&mut self, data: &[u8]) {
        *self = G2::hash(data);
    }
}

#[derive(Clone, Debug)]
pub struct PairingCurve;

impl PC for PairingCurve {
    type Scalar = Scalar;
    type G1 = G1;
    type G2 = G2;
    type GT = Fq12;

    fn pair(a: &Self::G1, b: &Self::G2) -> Self::GT {
        Bls12::pairing(a.into_affine(), b.into_affine())
    }
}

pub type G1Curve = group::PairingCurveG1<PairingCurve>;
pub type G2Curve = group::PairingCurveG2<PairingCurve>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    use serde::{de::DeserializeOwned, Serialize};
    use static_assertions::assert_impl_all;

    assert_impl_all!(G1: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(G2: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(GT: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(Scalar: Serialize, DeserializeOwned, Clone);

    // test if the element trait is usable
    fn add_two<T: Element<RHS = T>>(e1: &mut T, e2: &T) {
        e1.add(e2);
        e1.mul(e2);
    }

    #[test]
    fn basic_group() {
        let s = Scalar::rand(&mut thread_rng());
        let mut e1 = s;
        let e2 = s;
        let mut s2 = s;
        s2.add(&s);
        s2.mul(&s);
        add_two(&mut e1, &e2);
        // p1 = s2 * G = (s+s)G
        let mut p1 = G1::new();
        p1.mul(&s2);
        // p2 = sG + sG = s2 * G
        let mut p2 = G1::new();
        p2.mul(&s);
        p2.add(&p2.clone());
        assert_eq!(p1, p2);

        let mut ii = Scalar::new();
        ii.set_int(4);
    }
}
