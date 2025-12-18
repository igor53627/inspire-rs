use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspire_pir::inspiring::{pack_lwes, YConstants};
use inspire_pir::math::{GaussianSampler, NttContext};
use inspire_pir::params::InspireParams;
use inspire_pir::pir::setup;

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

fn pack_lwes_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();
    let ctx = NttContext::new(d, q);
    let mut sampler = GaussianSampler::new(params.sigma);

    // Create minimal database for setup
    let entry_size = 32;
    let num_entries = d;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let mut group = c.benchmark_group("pack_lwes");

    for num_lwes in [1, 2, 4, 8, 16, 32] {
        // Create LWE ciphertexts by sample-extracting from RLWE
        let lwe_cts: Vec<_> = (0..num_lwes)
            .map(|i| {
                let msg = (i as u64) % 256;
                let mut msg_coeffs = vec![0u64; d];
                msg_coeffs[0] = msg;
                let msg_poly = inspire_pir::math::Poly::from_coeffs(msg_coeffs, q);
                let a = inspire_pir::math::Poly::random(d, q);
                
                // Create trivial RLWE encryption (for benchmark purposes)
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

fn y_constants_benchmark(c: &mut Criterion) {
    let params = test_params();
    let d = params.ring_dim;
    let q = params.q;

    c.bench_function("y_constants_generate", |b| {
        b.iter(|| YConstants::generate(d, q));
    });
}

criterion_group!(benches, pack_lwes_benchmark, y_constants_benchmark);
criterion_main!(benches);
