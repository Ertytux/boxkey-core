use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use sha2::Digest;

#[test]
fn generate_dkg_2of3_vector() {
    let (shares, _) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    let mut rng = rand::rngs::OsRng;

    let signers = &shares[..2];
    let msg = b"BoxKey P0 Test Vector";
    let msg_hash: [u8; 32] = sha2::Sha256::digest(msg).into();

    let mut hidden = Vec::new();
    let mut commitments = Vec::new();
    for s in signers {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        hidden.push(h);
        commitments.push(comm);
    }

    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        sigs.push(
            frost_adapter::sign_partial(s, &msg_hash, &commitments, &hidden[i]).unwrap(),
        );
    }

    let agg = frost_adapter::aggregate_signatures(&sigs, &group_key, &msg_hash).unwrap();
    frost_adapter::verify_schnorr(&agg, &group_key, &msg_hash)
        .expect("BIP340 verification via k256");

    // Write vector file
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

    std::fs::write(
        "tests/vectors/dkg_2of3.json",
        serde_json::to_string_pretty(&vector).unwrap(),
    )
    .expect("write vector");
}

#[test]
fn generate_bip340_interop_vector() {
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

    let vector = serde_json::json!({
        "suite": "secp256k1-bip340-frost-v1",
        "key_type": "direct_BIP340",
        "public_key": hex::encode(pk_arr),
        "message": hex::encode(msg),
        "signature": hex::encode(sig_bytes),
        "expected_verification": true,
        "k256_verification": true,
        "bc_verification": true,
    });

    std::fs::write(
        "tests/vectors/bip340_interop.json",
        serde_json::to_string_pretty(&vector).unwrap(),
    )
    .expect("write vector");
}