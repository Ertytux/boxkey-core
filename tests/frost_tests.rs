use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::SigningSession;

#[test]
fn firma_2_de_3_verificada() {
    let (shares, _) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    let signers = &shares[..2];
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let mut handles = Vec::new();
    let mut commitments = Vec::new();
    let mut verifying = Vec::new();
    for s in signers {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        handles.push(h);
        commitments.push(comm);
        verifying.push((s.identifier(), s.full_public_key_point()));
    }

    let session = SigningSession::new(msg, group_key, 2, commitments, verifying)
        .expect("sesión válida");

    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        sigs.push(
            frost_adapter::sign_partial(s, &session, &mut handles[i]).unwrap(),
        );
    }

    let agg = frost_adapter::aggregate_signatures(&sigs, &session).unwrap();
    frost_adapter::verify_schnorr(&agg, &group_key, &msg).expect("firma 2-de-3 verifica");
}

#[test]
fn firma_con_share_invalida_rechazada() {
    let (shares, _) = dkg::run_dkg(2, 2);
    let group_key = shares[0].group_public_key();
    let msg = [0xabu8; 32];

    let mut rng = rand::rngs::OsRng;
    let mut handles = Vec::new();
    let mut commitments = Vec::new();
    let mut verifying = Vec::new();
    for s in &shares[..2] {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        handles.push(h);
        commitments.push(comm);
        verifying.push((s.identifier(), s.full_public_key_point()));
    }

    let session = SigningSession::new(msg, group_key, 2, commitments, verifying)
        .expect("sesión válida");

    let sig0 = frost_adapter::sign_partial(&shares[0], &session, &mut handles[0]).unwrap();
    let mut bad_sig = sig0;
    bad_sig.0[4] ^= 0xff;  // corrupt z

    let sig1 = frost_adapter::sign_partial(&shares[1], &session, &mut handles[1]).unwrap();
    let result = frost_adapter::aggregate_signatures(&[bad_sig, sig1], &session);
    assert!(result.is_err(), "firma corrupta debe fallar en aggregate");
}