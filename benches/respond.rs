use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspire_pir::math::GaussianSampler;
use inspire_pir::params::InspireParams;
use inspire_pir::pir::{query, respond, respond_sequential, setup};

fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        p: 65536,
        sigma: 3.2,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: inspire_pir::params::SecurityLevel::Bits128,
    }
}

fn respond_benchmark(c: &mut Criterion) {
    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let num_entries = params.ring_dim;

    let mut group = c.benchmark_group("respond");

    for num_columns in [1, 2, 4, 8] {
        let entry_size = num_columns * 32;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (_state, client_query) =
            query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("{}_columns", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| respond(&crs, &encoded_db, &client_query).unwrap());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sequential", format!("{}_columns", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| respond_sequential(&crs, &encoded_db, &client_query).unwrap());
            },
        );
    }

    group.finish();
}

criterion_group!(benches, respond_benchmark);
criterion_main!(benches);
