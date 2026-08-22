use boxkey_core::dkg;
use boxkey_core::frost_adapter;

#[test]
fn firma_2_de_3_verificada() {
    let (shares, _) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    let signers = &shares[..2];
    let msg = [0x42u8; 32];

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

    let agg = frost_adapter::aggregate_signatures(&sigs, &group_key, &msg).unwrap();
    frost_adapter::verify_schnorr(&agg, &group_key, &msg).expect("firma 2-de-3 verifica");
}

#[test]
fn firma_con_share_invalida_rechazada() {
    let (shares, _) = dkg::run_dkg(2, 2);
    let group_key = shares[0].group_public_key();
    let msg = [0xabu8; 32];

    let mut rng = rand::rngs::OsRng;
    let mut hidden = Vec::new();
    let mut commitments = Vec::new();
    for s in &shares[..2] {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        hidden.push(h);
        commitments.push(comm);
    }

    let sig0 = frost_adapter::sign_partial(&shares[0], &msg, &commitments, &hidden[0]).unwrap();
    let mut bad_sig = sig0;
    bad_sig.0[103] ^= 0xff;

    let sig1 = frost_adapter::sign_partial(&shares[1], &msg, &commitments, &hidden[1]).unwrap();
    let result = frost_adapter::aggregate_signatures(&[bad_sig, sig1], &group_key, &msg);
    assert!(result.is_err(), "firma corrupta debe fallar en aggregate");
}