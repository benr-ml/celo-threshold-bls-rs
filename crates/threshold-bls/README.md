## Group functionality

[`src/curve/group.rs`](src/curve/group.rs) contains the definitions of generic trait to work
with scalars of prime fields and points on elliptic curves. The following
`Element` trait allows to get a generic implementation of a polynomial with lagrange interpolation for both scalars and points.
```rust
pub trait Element<RHS = Self>: Clone + fmt::Display + fmt::Debug + Eq {
    /// new MUST return the zero element of the group.
    fn new() -> Self;
    fn one() -> Self;
    fn add(&mut self, s2: &Self);
    fn mul(&mut self, mul: &RHS);
    fn pick<R: RngCore>(&mut self, rng: &mut R);
    fn zero() -> Self {
        Self::new()
    }
}
```

There is an implementation of these traits using the curve BLS12-381 in
[`src/curve/bls12381.rs`](src/curve/bls12381.rs).

## Polynomial functionality

[`src/primitives/poly.rs`](src/primitives/poly.rs) contains the implementation of a polynomial
suitable to be used for secret sharing schemes and the dkg protocol. It can
evaluates shares and interpolate private and public shares to their
corresponding polynomial.

The following (from the [tests](src/primitives/poly.rs#L264)) shows how to interploate
a set of private shares:

```rust
use crate::bls12381::Scalar as Sc;
fn interpolation() {
    let degree = 4;
    let threshold = degree + 1;
    let poly = Poly::<Sc, Sc>::new(degree);
    let shares = (0..threshold)
        .map(|i| poly.eval(i as u64))
        .collect::<Vec<Share<Sc>>>();
    let recovered = Poly::<Sc, Sc>::recover(threshold as usize, shares);
    let expected = poly.c[0];
    let computed = recovered.c[0];
    assert_eq!(expected, computed);
}
```
