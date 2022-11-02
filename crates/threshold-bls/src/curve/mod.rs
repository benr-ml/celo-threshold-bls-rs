/// Wrappers around the BLS12-381 curve from the [paired](http://docs.rs/paired) crate
pub mod bls12381;
use thiserror::Error;

/// Error which unifies all curve specific errors from different libraries
#[derive(Debug, Error)]
pub enum CurveError {
    #[error("Bellman Error: {0}")]
    BLS12_381(bls12381::BellmanError),
}
