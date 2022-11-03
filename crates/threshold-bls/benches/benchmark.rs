use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use threshold_bls::curve;
use threshold_bls::primitives::poly::{Idx, Poly};
use threshold_bls::sig::test_utils::*;
use threshold_bls::sig::{G2Scheme, Share, SignatureScheme, ThresholdScheme};
use curve::bls12381::PairingCurve;

pub fn criterion_benchmark(c: &mut Criterion) {
    const sizes: [usize; 6] = [64, 128, 256, 440, 512, 1024];
    type S = G2Scheme<PairingCurve>;
    for n in sizes {
        let t = n / 2;
        c.bench_function(format!("create vss {} {}", n, t).as_str(), |b| {
            b.iter(|| create_vss_pk_and_shares::<S>(n, t))
        });
        let (shares, public) = create_vss_pk_and_shares::<S>(n, t);
        c.bench_function(format!("check shares {} {}", n, t).as_str(), |b| {
            b.iter(|| check_shares::<S>(t, &shares, &public))
        });
        c.bench_function(format!("compute partial sigs {} {}", n, t).as_str(), |b| {
            b.iter(|| compute_partial_sigs::<S>(t, &shares))
        });
        let sigs = compute_partial_sigs::<S>(t, &shares);
        c.bench_function(format!("process sigs w/o verf {} {}", n, t).as_str(), |b| {
            b.iter(|| process_partial_sigs::<S>(&sigs, &public, false))
        });
        c.bench_function(format!("process sigs with verf {} {}", n, t).as_str(), |b| {
            b.iter(|| process_partial_sigs::<S>(&sigs, &public, true))
        });
    }

}

criterion_group! {
  name = benches;
  config = Criterion::default().measurement_time(Duration::from_secs(10));
  targets = criterion_benchmark
}
criterion_main!(benches);
