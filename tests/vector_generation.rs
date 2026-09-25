//! Generación de vectores criptográficos (NO ejecutar durante `cargo test`).
//!
//! Este archivo queda como referencia histórica. La generación real se hace
//! con `cargo run --bin generate_vectors`.
//!
//! La verificación de vectores fijos se hace en `tests/vector_verification.rs`.

use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::SigningSession;
use sha2::Digest;

#[test]
fn verify_dkg_2of3_flow() {
    let (shares, _) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    let mut rng = rand::rngs::OsRng;

    let signers = &shares[..2];
    let msg = b"BoxKey P0 Test Vector";
    let msg_hash: [u8; 32] = sha2::Sha256::digest(msg).into();

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
        .expect("BIP340 verification via k256");
}

#[test]
fn verify_bip340_interop_flow() {
    use k256::schnorr::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let msg = [0xabu8; 32];
    let sig = signing_key.sign_raw(&msg, &[0u8; 32]).unwrap();

    let sig_bytes = sig.to_bytes();
    let pk_bytes = verifying_key.to_bytes();
    let pk_arr: [u8; 32] = pk_bytes.into();

    // Verify via k256
    use k256::schnorr::VerifyingKey;
    let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
    vk.verify_raw(&msg, &sig).unwrap();

    // Verify via BC
    let bc_pk = boxkey_core::PublicKey::from_bytes(pk_arr);
    let bc_sig = boxkey_core::SchnorrSignature(sig_bytes);
    frost_adapter::verify_schnorr(&bc_sig, &bc_pk, &msg).unwrap();
}