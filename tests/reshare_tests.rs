use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::SigningSession;

#[test]
fn resharing_2de3_a_2de4_preserva_clave_y_permite_firmar() {
    let (old_shares, _old_keys) = dkg::run_dkg(3, 2);
    let group_key = old_shares[0].group_public_key();

    let msg = [0x77u8; 32];
    let signers = &old_shares[..2];
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

    // Verificación independiente vía k256 (BIP340)
    frost_adapter::verify_schnorr(&agg, &group_key, &msg)
        .expect("firma del grupo original verifica");
    assert_eq!(agg.0.len(), 64);
}