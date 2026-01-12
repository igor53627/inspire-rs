use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use inspire_pir::math::GaussianSampler;
use inspire_pir::params::{InspireParams, InspireVariant};
use inspire_pir::pir::{
    extract_inspiring, extract_with_variant, query, query_seeded, respond, respond_inspiring,
    respond_one_packing, respond_seeded_inspiring, respond_seeded_packed, setup, PackingMode,
};

fn bench_query_size_and_latency(c: &mut Criterion) {
    // Production-like parameters; adjust if you want faster benches.
    let params = InspireParams::secure_128_d2048();
    let entry_size = 32;
    let num_entries = params.ring_dim;

    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler)
        .expect("setup should succeed");

    let target_index = 42u64;
    let (state_full, full_query) =
        query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler)
            .expect("query should succeed");
    let (state_seeded, seeded_query) =
        query_seeded(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler)
            .expect("seeded query should succeed");

    let mut full_query_tree = full_query.clone();
    full_query_tree.packing_mode = PackingMode::Tree;
    full_query_tree.inspiring_packing_keys = None;

    let mut seeded_query_tree = seeded_query.clone();
    seeded_query_tree.packing_mode = PackingMode::Tree;
    seeded_query_tree.inspiring_packing_keys = None;

    fn sizes<T: serde::Serialize>(value: &T) -> (usize, usize) {
        let bin = bincode::serialize(value).unwrap().len();
        let json = serde_json::to_vec(value).unwrap().len();
        (bin, json)
    }

    println!("\n=== Request/Response Sizes (bincode + JSON) ===");

    // InsPIRe^0 (NoPacking): full query, unpacked response
    let mut query0 = full_query.clone();
    query0.packing_mode = PackingMode::Tree;
    query0.inspiring_packing_keys = None;
    let response0 = respond(&crs, &encoded_db, &query0).expect("respond");
    let (req0_bin, req0_json) = sizes(&query0);
    let (resp0_bin, resp0_json) = sizes(&response0);
    println!(
        "\nInsPIRe^0 (NoPacking)\n  request:  {} B ({:.1} KB) | {} B ({:.1} KB)\n  response: {} B ({:.1} KB) | {} B ({:.1} KB)",
        req0_bin,
        req0_bin as f64 / 1024.0,
        req0_json,
        req0_json as f64 / 1024.0,
        resp0_bin,
        resp0_bin as f64 / 1024.0,
        resp0_json,
        resp0_json as f64 / 1024.0
    );

    // InsPIRe^1 (OnePacking): full query, packed response (InspiRING)
    let mut query1 = full_query.clone();
    query1.packing_mode = PackingMode::Inspiring;
    let response1 = respond_inspiring(&crs, &encoded_db, &query1).expect("respond_inspiring");
    let (req1_bin, req1_json) = sizes(&query1);
    let (resp1_bin, resp1_json) = sizes(&response1);
    println!(
        "\nInsPIRe^1 (OnePacking)\n  request:  {} B ({:.1} KB) | {} B ({:.1} KB)\n  response: {} B ({:.1} KB) | {} B ({:.1} KB)",
        req1_bin,
        req1_bin as f64 / 1024.0,
        req1_json,
        req1_json as f64 / 1024.0,
        resp1_bin,
        resp1_bin as f64 / 1024.0,
        resp1_json,
        resp1_json as f64 / 1024.0
    );

    // InsPIRe^2 (TwoPacking): seeded query, packed response (InspiRING)
    let mut query2 = seeded_query.clone();
    query2.packing_mode = PackingMode::Inspiring;
    let response2 =
        respond_seeded_inspiring(&crs, &encoded_db, &query2).expect("respond_seeded_inspiring");
    let (req2_bin, req2_json) = sizes(&query2);
    let (resp2_bin, resp2_json) = sizes(&response2);
    println!(
        "\nInsPIRe^2 (TwoPacking)\n  request:  {} B ({:.1} KB) | {} B ({:.1} KB)\n  response: {} B ({:.1} KB) | {} B ({:.1} KB)",
        req2_bin,
        req2_bin as f64 / 1024.0,
        req2_json,
        req2_json as f64 / 1024.0,
        resp2_bin,
        resp2_bin as f64 / 1024.0,
        resp2_json,
        resp2_json as f64 / 1024.0
    );

    if std::env::var("INSPIRE_BENCH_SIZES_ONLY").is_ok() {
        return;
    }

    let mut group = c.benchmark_group("pir_latency");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("query_full_inspiring", |b| {
        b.iter_batched(
            || GaussianSampler::new(params.sigma),
            |mut sampler| {
                let (_state, query) = query(
                    &crs,
                    target_index,
                    &encoded_db.config,
                    &rlwe_sk,
                    &mut sampler,
                )
                .expect("query");
                black_box(query);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("query_seeded_inspiring", |b| {
        b.iter_batched(
            || GaussianSampler::new(params.sigma),
            |mut sampler| {
                let (_state, query) = query_seeded(
                    &crs,
                    target_index,
                    &encoded_db.config,
                    &rlwe_sk,
                    &mut sampler,
                )
                .expect("seeded query");
                black_box(query);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("respond_inspiring_full", |b| {
        b.iter(|| {
            let response = respond_inspiring(&crs, &encoded_db, &full_query)
                .expect("respond_inspiring");
            black_box(response);
        });
    });

    group.bench_function("respond_tree_full", |b| {
        b.iter(|| {
            let response = respond_one_packing(&crs, &encoded_db, &full_query_tree)
                .expect("respond_one_packing");
            black_box(response);
        });
    });

    group.bench_function("respond_inspiring_seeded", |b| {
        b.iter(|| {
            let response = respond_seeded_inspiring(&crs, &encoded_db, &seeded_query)
                .expect("respond_seeded_inspiring");
            black_box(response);
        });
    });

    group.bench_function("respond_tree_seeded", |b| {
        b.iter(|| {
            let response = respond_seeded_packed(&crs, &encoded_db, &seeded_query_tree)
                .expect("respond_seeded_packed");
            black_box(response);
        });
    });

    let inspiring_response = respond_inspiring(&crs, &encoded_db, &full_query)
        .expect("respond_inspiring");
    let tree_response = respond_one_packing(&crs, &encoded_db, &full_query_tree)
        .expect("respond_one_packing");

    group.bench_function("extract_inspiring", |b| {
        b.iter(|| {
            let entry = extract_inspiring(&crs, &state_full, &inspiring_response, entry_size)
                .expect("extract_inspiring");
            black_box(entry);
        });
    });

    group.bench_function("extract_tree", |b| {
        b.iter(|| {
            let entry = extract_with_variant(
                &crs,
                &state_full,
                &tree_response,
                entry_size,
                InspireVariant::OnePacking,
            )
            .expect("extract_with_variant");
            black_box(entry);
        });
    });

    group.finish();

    // Prevent unused warnings for seeded state
    black_box(state_seeded);
}

criterion_group!(benches, bench_query_size_and_latency);
criterion_main!(benches);
