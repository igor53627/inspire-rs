use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspire_pir::inspiring::{
    pack_lwes, precompute_inspiring, pack_inspiring, YConstants, GeneratorPowers,
};
use inspire_pir::ks::generate_automorphism_ks_matrix;
use inspire_pir::math::{GaussianSampler, NttContext, Poly};
use inspire_pir::params::InspireParams;
use inspire_pir::pir::setup;
use inspire_pir::rgsw::GadgetVector;

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

fn production_params() -> InspireParams {
    InspireParams::secure_128_d2048()
}

fn pack_lwes_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = d;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, _encoded_db, _rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let mut group = c.benchmark_group("pack_lwes");

    for num_lwes in [1, 2, 4, 8, 16, 32] {
        let lwe_cts: Vec<_> = (0..num_lwes)
            .map(|i| {
                let msg = (i as u64) % 256;
                let mut msg_coeffs = vec![0u64; d];
                msg_coeffs[0] = msg;
                let msg_poly = Poly::from_coeffs(msg_coeffs, q);
                let rlwe_ct = inspire_pir::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
                rlwe_ct.sample_extract_coeff0()
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("tree_pack", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| pack_lwes(&lwe_cts, &crs.galois_keys, &params));
            },
        );
    }

    group.finish();
}

fn inspiring2_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let database: Vec<u8> = (0..(d * entry_size)).map(|i| (i % 256) as u8).collect();
    let (crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
    let g = 3;
    let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g, &gadget, &mut sampler, &ctx);

    let mut group = c.benchmark_group("inspiring2");

    for num_lwes in [4, 8, 16, 32] {
        let lwe_cts: Vec<_> = (0..num_lwes)
            .map(|i| {
                let msg = (i as u64) % 256;
                let mut msg_coeffs = vec![0u64; d];
                msg_coeffs[0] = msg;
                let msg_poly = Poly::from_coeffs(msg_coeffs, q);
                let rlwe_ct = inspire_pir::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
                rlwe_ct.sample_extract_coeff0()
            })
            .collect();

        let crs_a_vectors: Vec<Vec<u64>> = lwe_cts.iter().map(|lwe| lwe.a.clone()).collect();

        group.bench_with_input(
            BenchmarkId::new("precompute", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| precompute_inspiring(&crs_a_vectors, &k_g, &params));
            },
        );

        let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);

        group.bench_with_input(
            BenchmarkId::new("pack_online", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| pack_inspiring(&lwe_cts, &precomp, &k_g, &params));
            },
        );
    }

    group.finish();
}

fn comparison_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let database: Vec<u8> = (0..(d * entry_size)).map(|i| (i % 256) as u8).collect();
    let (crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
    let g = 3;
    let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g, &gadget, &mut sampler, &ctx);

    let num_lwes = 16;
    let lwe_cts: Vec<_> = (0..num_lwes)
        .map(|i| {
            let msg = (i as u64) % 256;
            let mut msg_coeffs = vec![0u64; d];
            msg_coeffs[0] = msg;
            let msg_poly = Poly::from_coeffs(msg_coeffs, q);
            let rlwe_ct = inspire_pir::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
            rlwe_ct.sample_extract_coeff0()
        })
        .collect();

    let crs_a_vectors: Vec<Vec<u64>> = lwe_cts.iter().map(|lwe| lwe.a.clone()).collect();
    let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);

    let mut group = c.benchmark_group("comparison_16_lwes");

    group.bench_function("tree_packing", |b| {
        b.iter(|| pack_lwes(&lwe_cts, &crs.galois_keys, &params));
    });

    group.bench_function("inspiring2_online", |b| {
        b.iter(|| pack_inspiring(&lwe_cts, &precomp, &k_g, &params));
    });

    group.bench_function("inspiring2_full", |b| {
        b.iter(|| {
            let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);
            pack_inspiring(&lwe_cts, &precomp, &k_g, &params)
        });
    });

    group.finish();
}

fn production_comparison_benchmark(c: &mut Criterion) {
    let params = production_params();
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let database: Vec<u8> = (0..(d * entry_size)).map(|i| (i % 256) as u8).collect();
    let (crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
    let g = 3;
    let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g, &gadget, &mut sampler, &ctx);

    let num_lwes = 16;
    let lwe_cts: Vec<_> = (0..num_lwes)
        .map(|i| {
            let msg = (i as u64) % 256;
            let mut msg_coeffs = vec![0u64; d];
            msg_coeffs[0] = msg;
            let msg_poly = Poly::from_coeffs(msg_coeffs, q);
            let rlwe_ct = inspire_pir::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
            rlwe_ct.sample_extract_coeff0()
        })
        .collect();

    let crs_a_vectors: Vec<Vec<u64>> = lwe_cts.iter().map(|lwe| lwe.a.clone()).collect();
    let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);

    let mut group = c.benchmark_group("production_d2048_16_lwes");
    group.sample_size(20);

    group.bench_function("tree_packing", |b| {
        b.iter(|| pack_lwes(&lwe_cts, &crs.galois_keys, &params));
    });

    group.bench_function("inspiring2_online", |b| {
        b.iter(|| pack_inspiring(&lwe_cts, &precomp, &k_g, &params));
    });

    group.finish();
}

fn key_material_benchmark(c: &mut Criterion) {
    let params = production_params();
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let database: Vec<u8> = (0..(d * entry_size)).map(|i| (i % 256) as u8).collect();
    let (_crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

    let mut group = c.benchmark_group("key_generation");
    group.sample_size(10);

    group.bench_function("single_ks_matrix", |b| {
        b.iter(|| {
            generate_automorphism_ks_matrix(&rlwe_sk, 3, &gadget, &mut sampler, &ctx)
        });
    });

    group.bench_function("generator_powers_d2048", |b| {
        b.iter(|| GeneratorPowers::new(d));
    });

    group.finish();
}

fn y_constants_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;

    c.bench_function("y_constants_generate", |b| {
        b.iter(|| YConstants::generate(d, q));
    });
}

criterion_group!(
    benches,
    pack_lwes_benchmark,
    inspiring2_benchmark,
    comparison_benchmark,
    production_comparison_benchmark,
    key_material_benchmark,
    y_constants_benchmark
);
criterion_main!(benches);
