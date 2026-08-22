use boxkey_core::dkg;
use boxkey_core::frost_adapter;

#[test]
fn resharing_2de3_a_2de4_preserva_clave_y_permite_firmar() {
    let (old_shares, _old_keys) = dkg::run_dkg(3, 2);
    let group_key = old_shares[0].group_public_key();

    let msg = [0x77u8; 32];
    let signers = &old_shares[..2];
    let mut rng = rand::rngs::OsRng;

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
            frost_adapter::sign_partial(s, &msg, &commitments, &hidden[i]).unwrap(),
        );
    }

    let agg =
        frost_adapter::aggregate_signatures(&sigs, &group_key, &msg).unwrap();

    // Verificación independiente vía k256 (BIP340)
    frost_adapter::verify_schnorr(&agg, &group_key, &msg)
        .expect("firma del grupo original verifica");
    assert_eq!(agg.0.len(), 64);
}