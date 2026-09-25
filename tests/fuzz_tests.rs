//! Infraestructura de fuzzing para BC.
//!
//! Usa `proptest` para generar inputs malformados y verificar que las funciones
//! de parsing rechazan sin panic.
//!
//! Ejecución: `cargo test --test fuzz_tests`
//!
//! No es una campaña exhaustiva; es infraestructura funcional inicial.

use std::fs;

use boxkey_core::frost_adapter;
use boxkey_core::{Commitment, PartialSignature, PublicKey};
use proptest::prelude::*;

/// Genera bytes arbitrarios para fuzzing.
fn arb_bytes(min: usize, max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), min..=max)
}

proptest! {
    /// Fuzz: parse_commitment con inputs truncados, oversized, malformados.
    #[test]
    fn fuzz_parse_commitment(
        bytes in arb_bytes(0, 200),
    ) {
        let comm = Commitment(bytes);
        // bc_commitment_to_frost internamente llama a deserialize en los
        // subcampos. Debe devolver Error, nunca panic.
        let _result = frost_adapter::debug_parse_commitment(&comm);
    }

    /// Fuzz: parse_public_key (x-only BIP340) con inputs arbitrarios.
    #[test]
    fn fuzz_parse_public_key(
        bytes in arb_bytes(0, 64),
    ) {
        if bytes.len() == 32 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            let _result = frost_adapter::debug_parse_public_key(&pk);
        }
    }

    /// Fuzz: parse_partial_signature con inputs arbitrarios.
    #[test]
    fn fuzz_parse_partial_signature(
        bytes in arb_bytes(0, 200),
    ) {
        if bytes.len() == 36 {
            let mut sig = [0u8; 36];
            sig.copy_from_slice(&bytes);
            let ps = PartialSignature(sig);
            // Verificar que el z_bytes no paniquea
            let _id = ps.identifier();
            let _z = ps.z_bytes();
        }
    }

    /// Fuzz: commitment con longitud incorrecta.
    #[test]
    fn fuzz_commitment_wrong_length(
        len in 0usize..200,
    ) {
        let bytes: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
        let comm = Commitment(bytes);
        let _result = frost_adapter::debug_parse_commitment(&comm);
    }

    /// Fuzz: public key con bytes inválidos (fuera de curva, punto impar, etc.)
    #[test]
    fn fuzz_public_key_invalid(
        bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let _result = frost_adapter::debug_parse_public_key(&bytes);
    }
}

/// Test: leer un vector de fuzzing desde disco (si existe) y verificar que no paniquea.
#[test]
fn fuzz_reads_corpus_if_exists() {
    let corpus_dir = "tests/fuzz_corpus";
    if let Ok(entries) = fs::read_dir(corpus_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(data) = fs::read(&path) {
                // Probar como commitment
                let comm = Commitment(data.clone());
                let _ = frost_adapter::debug_parse_commitment(&comm);

                // Probar como public key si es 32 bytes
                if data.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&data);
                    let _ = frost_adapter::debug_parse_public_key(&pk);
                }
            }
        }
    }
    // Si no existe corpus, el test pasa sin hacer nada.
}