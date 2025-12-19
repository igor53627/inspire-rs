use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspire_pir::math::GaussianSampler;
use inspire_pir::params::InspireParams;
use inspire_pir::pir::{extract_with_variant, query, respond, respond_sequential, respond_with_variant, setup};
use inspire_pir::params::InspireVariant;

fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        p: 65536,
        sigma: 6.4,
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

fn one_packing_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let mut sampler = GaussianSampler::new(params.sigma);
    let num_entries = d;

    let mut group = c.benchmark_group("one_packing");

    // Use small column values (< p/d = 256) to avoid overflow issues
    for num_columns in [1, 2, 4, 8, 16] {
        let entry_size = num_columns * 2; // 2 bytes per column, value < 256
        let database: Vec<u8> = (0..num_entries)
            .flat_map(|i| {
                (0..num_columns).flat_map(move |col| {
                    let low = ((i + col) % 256) as u8;
                    let high = 0u8; // Keep high byte 0 for column_value < 256
                    vec![low, high]
                })
            })
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (state, client_query) =
            query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        // Benchmark NoPacking respond
        group.bench_with_input(
            BenchmarkId::new("respond_nopack", format!("{}_cols", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| respond(&crs, &encoded_db, &client_query).unwrap());
            },
        );

        // Benchmark OnePacking respond
        group.bench_with_input(
            BenchmarkId::new("respond_onepack", format!("{}_cols", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| {
                    respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::OnePacking)
                        .unwrap()
                });
            },
        );

        // Pre-compute responses for extraction benchmarks
        let response_nopack = respond(&crs, &encoded_db, &client_query).unwrap();
        let response_onepack =
            respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::OnePacking)
                .unwrap();

        // Benchmark NoPacking extract
        group.bench_with_input(
            BenchmarkId::new("extract_nopack", format!("{}_cols", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| {
                    extract_with_variant(
                        &crs,
                        &state,
                        &response_nopack,
                        entry_size,
                        InspireVariant::NoPacking,
                    )
                    .unwrap()
                });
            },
        );

        // Benchmark OnePacking extract
        group.bench_with_input(
            BenchmarkId::new("extract_onepack", format!("{}_cols", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| {
                    extract_with_variant(
                        &crs,
                        &state,
                        &response_onepack,
                        entry_size,
                        InspireVariant::OnePacking,
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

fn response_size_comparison(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let mut sampler = GaussianSampler::new(params.sigma);
    let num_entries = d;

    let mut group = c.benchmark_group("response_size");

    // Test with different column counts to show size advantage
    for num_columns in [4, 8, 16] {
        let entry_size = num_columns * 2;
        let database: Vec<u8> = (0..num_entries)
            .flat_map(|i| {
                (0..num_columns).flat_map(move |col| {
                    let low = ((i + col) % 256) as u8;
                    let high = 0u8;
                    vec![low, high]
                })
            })
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (_state, client_query) =
            query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        let response_nopack = respond(&crs, &encoded_db, &client_query).unwrap();
        let response_onepack =
            respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::OnePacking)
                .unwrap();

        // Measure serialized sizes
        let nopack_bytes = response_nopack.to_binary().unwrap();
        let onepack_bytes = response_onepack.to_binary().unwrap();

        println!(
            "{} columns: NoPacking={} bytes, OnePacking={} bytes, ratio={:.2}x",
            num_columns,
            nopack_bytes.len(),
            onepack_bytes.len(),
            nopack_bytes.len() as f64 / onepack_bytes.len() as f64
        );

        // Benchmark serialization
        group.bench_with_input(
            BenchmarkId::new("serialize_nopack", format!("{}_cols", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| response_nopack.to_binary().unwrap());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("serialize_onepack", format!("{}_cols", num_columns)),
            &num_columns,
            |b, _| {
                b.iter(|| response_onepack.to_binary().unwrap());
            },
        );
    }

    group.finish();
}

criterion_group!(benches, respond_benchmark, one_packing_benchmark, response_size_comparison);
criterion_main!(benches);
