//! Verificación de vectores criptográficos fijos contra BC.
//!
//! Lee los fixtures de `tests/vectors/` y verifica que BC produce los
//! resultados esperados. NO regenera ni modifica los vectores.
//!
//! Uso: `cargo test --test vector_verification`

use std::fs;

use boxkey_core::frost_adapter;
use boxkey_core::{PublicKey, SchnorrSignature};

/// Parsea un hex string a `[u8; 32]`.
fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex válido");
    bytes.try_into().expect("32 bytes")
}

/// Parsea un hex string a `[u8; 64]`.
fn hex64(s: &str) -> [u8; 64] {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex válido");
    bytes.try_into().expect("64 bytes")
}

#[test]
fn dkg_2of3_vector_verification() {
    let raw = fs::read_to_string("tests/vectors/dkg_2of3.json")
        .expect("vector dkg_2of3.json debe existir");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("json válido");

    let group_pk = hex32(v["group_public_key"].as_str().unwrap());
    let msg_hash = hex32(v["signing_digest"].as_str().unwrap());
    let agg_sig_hex = v["aggregate_signature"].as_str().unwrap();
    let expected_verification = v["expected_verification"].as_bool().unwrap();

    let bc_pk = PublicKey::from_bytes(group_pk);
    let bc_sig = SchnorrSignature(hex64(agg_sig_hex));

    // Verificar la firma agregada vía BC (k256::schnorr)
    let result = frost_adapter::verify_schnorr(&bc_sig, &bc_pk, &msg_hash);
    assert_eq!(
        result.is_ok(),
        expected_verification,
        "verificación de vector DKG 2-of-3: esperado={expected_verification}, obtenido={}",
        if result.is_ok() { "ok" } else { "error" }
    );
}

#[test]
fn bip340_interop_vector_verification() {
    let raw = fs::read_to_string("tests/vectors/bip340_interop.json")
        .expect("vector bip340_interop.json debe existir");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("json válido");

    let pk = hex32(v["public_key"].as_str().unwrap());
    let msg = hex32(v["message"].as_str().unwrap());
    let sig = hex64(v["signature"].as_str().unwrap());
    let expected = v["expected_verification"].as_bool().unwrap();

    let bc_pk = PublicKey::from_bytes(pk);
    let bc_sig = SchnorrSignature(sig);

    let result = frost_adapter::verify_schnorr(&bc_sig, &bc_pk, &msg);
    assert_eq!(
        result.is_ok(),
        expected,
        "verificación de vector BIP340: esperado={expected}, obtenido={}",
        if result.is_ok() { "ok" } else { "error" }
    );
}

#[test]
fn vector_verification_via_independent_k256() {
    // Verificar la firma agregada del vector DKG 2-of-3 usando
    // k256::schnorr (RustCrypto) como verificador independiente de FROST.
    let raw = fs::read_to_string("tests/vectors/dkg_2of3.json")
        .expect("vector dkg_2of3.json debe existir");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("json válido");

    let group_pk = hex32(v["group_public_key"].as_str().unwrap());
    let msg_hash = hex32(v["signing_digest"].as_str().unwrap());
    let agg_sig = hex64(v["aggregate_signature"].as_str().unwrap());

    use k256::schnorr::VerifyingKey;
    let vk = VerifyingKey::from_bytes(&group_pk).expect("clave x-only válida");
    let sig_obj = k256::schnorr::Signature::try_from(agg_sig.as_slice())
        .expect("firma Schnorr válida");
    vk.verify_raw(&msg_hash, &sig_obj)
        .expect("firma agregada verificada por k256::schnorr (independiente de FROST)");
}

#[test]
fn vector_verification_detecta_firma_invalida() {
    // Verificar que un vector manipulado es rechazado
    let raw = fs::read_to_string("tests/vectors/bip340_interop.json")
        .expect("vector bip340_interop.json debe existir");
    let mut v: serde_json::Value = serde_json::from_str(&raw).expect("json válido");

    let pk = hex32(v["public_key"].as_str().unwrap());
    let msg = hex32(v["message"].as_str().unwrap());
    let mut sig = hex64(v["signature"].as_str().unwrap());
    sig[0] ^= 0x01; // manipular

    let bc_pk = PublicKey::from_bytes(pk);
    let bc_sig = SchnorrSignature(sig);
    let result = frost_adapter::verify_schnorr(&bc_sig, &bc_pk, &msg);
    assert!(result.is_err(), "firma manipulada debe ser rechazada");
}