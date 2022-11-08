use criterion::{criterion_group, criterion_main, Criterion};
use curve::bls12381::PairingCurve;
use std::time::Duration;
use threshold_bls::curve;
use threshold_bls::primitives::poly::{Idx, Poly};
use threshold_bls::sig::test_utils::*;
use threshold_bls::sig::{G2Scheme, Share, SignatureScheme, ThresholdScheme};

pub fn tbls_benchmark(c: &mut Criterion) {
    const SIZES: [usize; 6] = [64, 128, 256, 440, 512, 1024];
    type S = G2Scheme<PairingCurve>;
    for n in SIZES {
        let t = n / 2;
        c.bench_function(format!("create vss {} {}", n, t).as_str(), |b| {
            b.iter(|| create_vss_pk_and_shares::<S>(n, t))
        });
        let (shares, public) = create_vss_pk_and_shares::<S>(n, t);
        // We check t shares since in the DKG we will wait for only t messages.
        c.bench_function(format!("check shares {} {}", n, t).as_str(), |b| {
            b.iter(|| check_shares::<S>(t, &shares, &public))
        });
        // In practice each party will only compute 1 partial sig, but we still benchmark how much
        // much it will take sequentially for t partial sigs.
        c.bench_function(format!("compute partial sigs {} {}", n, t).as_str(), |b| {
            b.iter(|| compute_partial_sigs::<S>(t, &shares))
        });
        let sigs = compute_partial_sigs::<S>(t, &shares);
        // In practice nodes will always verify the aggregated sig and only if there is an issue,
        // check each of the partial signatures individually.
        c.bench_function(
            format!(
                "verify the aggregation of partial sigs w/o individual verification {} {}",
                n, t
            )
            .as_str(),
            |b| b.iter(|| process_partial_sigs::<S>(&sigs, &public, false)),
        );
        c.bench_function(
            format!(
                "verify the aggregation of partial sigs with individual verification {} {}",
                n, t
            )
            .as_str(),
            |b| b.iter(|| process_partial_sigs::<S>(&sigs, &public, true)),
        );
    }
}

criterion_group! {
  name = benches;
  config = Criterion::default().measurement_time(Duration::from_secs(10));
  targets = tbls_benchmark
}

criterion_main!(benches);
