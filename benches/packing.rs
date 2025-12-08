use criterion::{criterion_group, criterion_main, Criterion};

fn packing_benchmark(_c: &mut Criterion) {
    // TODO: Add packing benchmarks
}

criterion_group!(benches, packing_benchmark);
criterion_main!(benches);
