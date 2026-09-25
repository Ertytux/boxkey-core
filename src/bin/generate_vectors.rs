//! Generador de vectores criptográficos fijos para BC.
//!
//! Uso: `cargo run --bin generate_vectors`

use std::fs;

use rand::rngs::OsRng;
use sha2::Digest;

use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::{PublicKey, SchnorrSignature, SigningSession};

fn main() {
    println!("=== Generando vectores criptográficos fijos ===");

    // ── Vector DKG 2-of-3 ──────────────────────────────────────────────
    let (shares, _) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();

    let msg = b"BoxKey P0 Test Vector";
    let msg_hash: [u8; 32] = sha2::Sha256::digest(msg).into();

    let signers = &shares[..2];
    let mut rng = OsRng;

    let mut handles = Vec::new();
    let mut commitments = Vec::new();
    let mut verifying = Vec::new();
    for s in signers {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        handles.push(h);
        commitments.push(comm);
        verifying.push((s.identifier(), s.full_public_key_point()));
    }

    let session = SigningSession::new(msg_hash, group_key, 2, commitments, verifying)
        .expect("sesión válida");

    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        sigs.push(
            frost_adapter::sign_partial(s, &session, &mut handles[i]).unwrap(),
        );
    }

    let agg = frost_adapter::aggregate_signatures(&sigs, &session).unwrap();
    frost_adapter::verify_schnorr(&agg, &group_key, &msg_hash)
        .expect("vector auto-verificado");

    let vector = serde_json::json!({
        "suite": "secp256k1-bip340-frost-v1",
        "threshold": 2,
        "participants": 3,
        "group_public_key": hex::encode(group_key.0),
        "message": hex::encode(msg),
        "signing_digest": hex::encode(msg_hash),
        "participants_used": [1, 2],
        "signature_shares": sigs.iter().map(|s| hex::encode(&s.0)).collect::<Vec<_>>(),
        "aggregate_signature": hex::encode(agg.0),
        "expected_verification": true,
    });

    fs::write(
        "tests/vectors/dkg_2of3.json",
        serde_json::to_string_pretty(&vector).unwrap(),
    )
    .expect("escribe dkg_2of3.json");
    println!("  ✓ tests/vectors/dkg_2of3.json");

    // ── Vector BIP340 Interoperabilidad ────────────────────────────────
    use k256::schnorr::SigningKey;
    let sk_seed = [0xabu8; 32];
    let signing_key = SigningKey::from_bytes(&sk_seed).expect("clave desde seed");
    let verifying_key = signing_key.verifying_key();
    let bip_msg = [0xabu8; 32];
    let bip_sig = signing_key.sign_raw(&bip_msg, &[0u8; 32]).unwrap();

    let sig_bytes = bip_sig.to_bytes();
    let pk_bytes = verifying_key.to_bytes();
    let pk_arr: [u8; 32] = pk_bytes.into();

    // Auto-verificar
    let bc_pk = PublicKey::from_bytes(pk_arr);
    let bc_sig = SchnorrSignature(sig_bytes);
    frost_adapter::verify_schnorr(&bc_sig, &bc_pk, &bip_msg).unwrap();

    let vector = serde_json::json!({
        "suite": "secp256k1-bip340-frost-v1",
        "key_type": "direct_BIP340",
        "public_key": hex::encode(pk_arr),
        "message": hex::encode(bip_msg),
        "signature": hex::encode(sig_bytes),
        "expected_verification": true,
        "bc_verification": true,
    });

    fs::write(
        "tests/vectors/bip340_interop.json",
        serde_json::to_string_pretty(&vector).unwrap(),
    )
    .expect("escribe bip340_interop.json");
    println!("  ✓ tests/vectors/bip340_interop.json");
}