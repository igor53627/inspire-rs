use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspire::inspiring::{
    pack_inspiring_legacy, pack_lwes, packing_offline, packing_online, packing_online_fully_ntt,
    precompute_inspiring, ClientPackingKeys, GeneratorPowers, OfflinePackingKeys, PackParams,
    YConstants,
};
use inspire::ks::generate_automorphism_ks_matrix;
use inspire::math::{GaussianSampler, NttContext, Poly};
use inspire::params::InspireParams;
use inspire::pir::setup;
use inspire::rgsw::GadgetVector;
use inspire::rlwe::RlweSecretKey;

fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        crt_moduli: vec![1152921504606830593],
        p: 65536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: inspire::params::SecurityLevel::Bits128,
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
                let rlwe_ct =
                    inspire::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
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
    let (_crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

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
                let rlwe_ct =
                    inspire::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
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
                b.iter(|| pack_inspiring_legacy(&lwe_cts, &precomp, &k_g, &params));
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
            let rlwe_ct =
                inspire::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
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
        b.iter(|| pack_inspiring_legacy(&lwe_cts, &precomp, &k_g, &params));
    });

    group.bench_function("inspiring2_full", |b| {
        b.iter(|| {
            let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);
            pack_inspiring_legacy(&lwe_cts, &precomp, &k_g, &params)
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
            let rlwe_ct =
                inspire::rlwe::RlweCiphertext::trivial_encrypt(&msg_poly, delta, &params);
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
        b.iter(|| pack_inspiring_legacy(&lwe_cts, &precomp, &k_g, &params));
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
        b.iter(|| generate_automorphism_ks_matrix(&rlwe_sk, 3, &gadget, &mut sampler, &ctx));
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
    let moduli = params.moduli();

    c.bench_function("y_constants_generate", |b| {
        b.iter(|| YConstants::generate(d, q, moduli));
    });
}

fn canonical_api_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let database: Vec<u8> = (0..(d * entry_size)).map(|i| (i % 256) as u8).collect();
    let (_crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let mut group = c.benchmark_group("canonical_api");

    for num_lwes in [8, 16, 32] {
        let a_polys: Vec<Poly> = (0..num_lwes).map(|_| Poly::random(d, q)).collect();

        let pack_params = PackParams::new(&params, num_lwes);
        let packing_key = OfflinePackingKeys::generate(&pack_params, [0u8; 32]);

        group.bench_with_input(
            BenchmarkId::new("packing_offline", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| packing_offline(&pack_params, &packing_key, &a_polys, &ctx));
            },
        );

        let mut precomp = packing_offline(&pack_params, &packing_key, &a_polys, &ctx);
        precomp.ensure_ntt_cached(&ctx);

        let client_keys =
            ClientPackingKeys::generate(&rlwe_sk, &pack_params, [0u8; 32], &mut sampler);
        let b_poly = Poly::random(d, q);

        group.bench_with_input(
            BenchmarkId::new("packing_online", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| packing_online(&precomp, &client_keys.y_all, &b_poly, &ctx));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("packing_online_fully_ntt", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| {
                    packing_online_fully_ntt(&precomp, &client_keys.y_all_ntt, &b_poly, &ctx)
                });
            },
        );
    }

    group.finish();
}

fn ntt_automorphism_benchmark(c: &mut Criterion) {
    let params = production_params();
    let d = params.ring_dim;
    let q = params.q;
    let _ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let mut group = c.benchmark_group("ntt_automorphism_d2048");
    group.sample_size(50);

    let pack_params = PackParams::new(&params, 16);

    group.bench_function("automorph_table_generation", |b| {
        b.iter(|| PackParams::new(&params, 16));
    });

    group.bench_function("offline_packing_keys_generate", |b| {
        b.iter(|| OfflinePackingKeys::generate(&pack_params, [0u8; 32]));
    });

    let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
    group.bench_function("client_packing_keys_generate", |b| {
        b.iter(|| ClientPackingKeys::generate(&rlwe_sk, &pack_params, [0u8; 32], &mut sampler));
    });

    group.finish();
}

fn production_inspiring2_benchmark(c: &mut Criterion) {
    let params = production_params();
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);

    let mut group = c.benchmark_group("production_inspiring2_d2048");
    group.sample_size(20);

    for num_lwes in [16, 32, 64, 128] {
        let a_polys: Vec<Poly> = (0..num_lwes).map(|_| Poly::random(d, q)).collect();

        let pack_params = PackParams::new(&params, num_lwes);
        let packing_key = OfflinePackingKeys::generate(&pack_params, [0u8; 32]);

        group.bench_with_input(
            BenchmarkId::new("offline", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| packing_offline(&pack_params, &packing_key, &a_polys, &ctx));
            },
        );

        let mut precomp = packing_offline(&pack_params, &packing_key, &a_polys, &ctx);
        precomp.ensure_ntt_cached(&ctx);
        let client_keys =
            ClientPackingKeys::generate(&rlwe_sk, &pack_params, [0u8; 32], &mut sampler);
        let b_poly = Poly::random(d, q);

        group.bench_with_input(
            BenchmarkId::new("online_fully_ntt", format!("{}_lwes", num_lwes)),
            &num_lwes,
            |b, _| {
                b.iter(|| {
                    packing_online_fully_ntt(&precomp, &client_keys.y_all_ntt, &b_poly, &ctx)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    pack_lwes_benchmark,
    inspiring2_benchmark,
    comparison_benchmark,
    production_comparison_benchmark,
    key_material_benchmark,
    y_constants_benchmark,
    canonical_api_benchmark,
    ntt_automorphism_benchmark,
    production_inspiring2_benchmark
);
criterion_main!(benches);
