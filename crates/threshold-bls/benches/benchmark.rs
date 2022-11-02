use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use threshold_bls::sig::test_threshold_g1;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut t: usize = 128;
    while t < 129 {
        c.bench_function(format!("tbls {}", t).as_str(), |b| {
            b.iter(|| test_threshold_g1(t))
        });
        t *= 2;
    }
}

criterion_group! {
  name = benches;
  config = Criterion::default().measurement_time(Duration::from_secs(10));
  targets = criterion_benchmark
}
criterion_main!(benches);
