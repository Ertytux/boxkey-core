use boxkey_core::dkg;
use boxkey_core::frost;

#[test]
fn firma_2_de_3_verificada() {
    let (shares, _keys) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let signers = &shares[..2];
    let mut commitments = Vec::new();
    let mut full_keys = Vec::new();
    let mut hidden = Vec::new();
    for s in signers {
        let (h, comm) = frost::generate_nonces(s, &msg).unwrap();
        commitments.push((s.identifier(), comm));
        full_keys.push((s.identifier(), s.full_public_key_point()));
        hidden.push(h);
    }

    let round = frost::SigningRound::new(msg, group_key, &commitments, &full_keys).unwrap();
    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        sigs.push(frost::sign_partial(&round, s, &hidden[i]).unwrap());
    }
    for (i, s) in signers.iter().enumerate() {
        frost::verify_partial(&sigs[i], &s.partial_public_key(), &msg)
            .expect("parcial de signer válida");
    }

    let agg = frost::aggregate_signatures(&sigs, &group_key, &msg).unwrap();
    assert!(
        frost::verify_schnorr(&agg, &group_key, &msg).is_ok(),
        "la firma Schnorr 2-de-3 verifica"
    );
}

#[test]
fn firma_con_share_invalida_rechazada() {
    let (shares, _keys) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let signer = &shares[0];
    let (hidden, comm) = frost::generate_nonces(signer, &msg).unwrap();
    let round = frost::SigningRound::new(
        msg,
        group_key,
        &[(signer.identifier(), comm)],
        &[(signer.identifier(), signer.full_public_key_point())],
    )
    .unwrap();

    let mut sig = frost::sign_partial(&round, signer, &hidden).unwrap();

    let n = sig.0.len();
    sig.0[n - 1] ^= 0x01;

    assert!(
        frost::verify_partial(&sig, &signer.partial_public_key(), &msg).is_err(),
        "firma con share inválida rechazada por verify_partial"
    );
}
