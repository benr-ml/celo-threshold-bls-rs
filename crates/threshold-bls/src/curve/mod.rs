use thiserror::Error;

pub mod bls12381;
pub mod group;

/// Error which unifies all curve specific errors from different libraries
#[derive(Debug, Error)]
pub enum CurveError {
    #[error("Bellman Error: {0}")]
    BLS12_381(bls12381::BellmanError),
}
