use criterion::{criterion_group, criterion_main, Criterion};

fn ntt_benchmark(_c: &mut Criterion) {
    // TODO: Add NTT benchmarks
}

criterion_group!(benches, ntt_benchmark);
criterion_main!(benches);
