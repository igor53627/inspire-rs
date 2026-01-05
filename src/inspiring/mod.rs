//! InspiRING: Ring packing algorithm for InsPIRe PIR
//!
//! Packs d LWE ciphertexts into a single RLWE ciphertext using only 2 key-switching matrices,
//! compared to log(d) in prior CDKS approach.
//!
//! # Three Stages
//! 1. **Transform**: LWE → Intermediate ciphertexts
//! 2. **Aggregation**: Combine intermediate ciphertexts
//! 3. **Collapse**: Convert to RLWE using key-switching
//!
//! # Key Insight
//! In the CRS model, the `a` vectors are fixed, so most computation can be precomputed offline.
//! Only `b` values change per query.
//!
//! # Example Usage
//!
//! ```ignore
//! use inspire_pir::inspiring::{pack, precompute_packing, pack_online, PackingPrecomputation};
//! use inspire_pir::ks::KeySwitchingMatrix;
//! use inspire_pir::lwe::LweCiphertext;
//! use inspire_pir::params::InspireParams;
//!
//! let params = InspireParams::secure_128_d2048();
//!
//! // Generate keys and LWE ciphertexts...
//! // let k_g = ...;
//! // let k_h = ...;
//! // let lwe_ciphertexts = ...;
//!
//! // Full packing
//! // let packed = pack(&lwe_ciphertexts, &k_g, &k_h, &params);
//!
//! // Or with online/offline separation:
//! // let precomp = precompute_packing(&crs_a_vectors, &k_g, &k_h, &params);
//! // let packed = pack_online(&b_values, &precomp, &k_g, &k_h, &params);
//! ```

pub mod automorph_pack;
mod collapse;
mod collapse_one;
pub mod inspiring2;
mod pack;
mod simple_pack;
mod transform;
mod types;

pub use automorph_pack::{
    homomorphic_automorph, pack_lwes, pack_lwes_inner, pack_rlwes_tree, pack_single_lwe,
    prep_pack_lwes, YConstants,
};
pub use collapse::{collapse, collapse_half, collapse_partial};
pub use collapse_one::collapse_one;
pub use inspiring2::{
    full_packing_offline,
    generate_rotations,
    pack_inspiring,
    pack_inspiring_full,
    pack_inspiring_legacy,
    pack_inspiring_partial,
    packing_offline,
    packing_online,
    packing_online_fully_ntt,
    precompute_inspiring,
    ClientPackingKeys,
    // Legacy API (compatibility)
    GeneratorPowers,
    InspiringPrecomputation,
    OfflinePackingKeys,
    // New canonical API (client/server separation)
    PackParams,
    PackingKeyBody, // Type alias for backward compatibility
    PrecompInsPIR,
    RotatedKsMatrix,
};
pub use pack::{pack, pack_online, partial_pack, precompute_packing, PackingPrecomputation};
pub use simple_pack::{pack_lwe_to_rlwe, pack_rlwe_coeffs};
pub use transform::{aggregate, transform, transform_at_slot, transform_partial};
pub use types::{AggregatedCiphertext, IntermediateCiphertext};
