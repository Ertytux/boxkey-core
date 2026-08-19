use boxkey_core::dkg;
use boxkey_core::frost;
use boxkey_core::{BoxKeyCore, BoxKeyCoreImpl};

#[test]
fn flujo_completo_via_trait() {
    let n = 3u8;
    let t = 2u8;

    let mut pks = Vec::new();
    let mut sk_pairs = Vec::new();
    for _ in 0..n {
        let (sk, pk) = dkg::generate_participant_key();
        sk_pairs.push(sk);
        pks.push(pk);
    }

    let mut first_commitments = Vec::new();
    let mut all_commitments = Vec::new();
    let mut encrypted = Vec::new();
    for _ in 0..n {
        let secret = <BoxKeyCoreImpl as BoxKeyCore>::generate_secret();
        let configured = dkg::secret_with_threshold(&secret, t, n).expect("configura umbral");
        let comms = <BoxKeyCoreImpl as BoxKeyCore>::compute_commitments(&secret, t, n);
        let pok = dkg::generate_proof_of_knowledge(&configured);
        <BoxKeyCoreImpl as BoxKeyCore>::verify_commitments(&comms, &pok).expect("commits válidos");
        first_commitments.push(comms[0].clone());
        all_commitments.push(comms);
        encrypted.push(
            <BoxKeyCoreImpl as BoxKeyCore>::generate_shares(&configured, &pks).expect("shares"),
        );
    }

    let mut shares = Vec::new();
    for (i, sk) in sk_pairs.iter().enumerate() {
        let mut partials = Vec::new();
        for j in 0..n as usize {
            let mine = encrypted[j].iter().find(|e| e.recipient == pks[i]).unwrap();
            let part = <BoxKeyCoreImpl as BoxKeyCore>::verify_and_decrypt_share(mine, sk)
                .expect("descifra");
            dkg::verify_share(&part, &all_commitments[j]).expect("Feldman ok");
            partials.push(part);
        }
        let combined =
            dkg::combine_shares(&partials, t, &first_commitments).expect("combina shares");
        shares.push(combined);
    }

    let group = dkg::derive_public_key(&shares).expect("clave de grupo");
    assert_eq!(group, shares[0].group_public_key());

    let (hidden, comm) = <BoxKeyCoreImpl as BoxKeyCore>::generate_nonces(&shares[0]);
    assert_eq!(hidden.len(), 64);
    assert_eq!(comm.len(), 70);
}

#[test]
fn envelope_versionado_se_serializa_y_valida() {
    let (shares, _keys) = dkg::run_dkg(1, 1);
    let signer = &shares[0];
    let (sk, pk) = dkg::generate_participant_key();
    let msg = [0x42u8; 32];

    let (hidden, comm) = frost::generate_nonces(signer, &msg).unwrap();
    let sig =
        <BoxKeyCoreImpl as BoxKeyCore>::sign_partial(signer, &msg, std::slice::from_ref(&comm))
            .expect("firma parcial");

    let envelope = boxkey_core::Envelope::new(boxkey_core::MessageKind::PartialSignature {
        sender: signer.partial_public_key(),
        signature: sig,
    });

    boxkey_core::validate_versioning(&envelope).expect("versionado correcto");

    let signature = envelope.sign(&sk).expect("firma del envelope");
    boxkey_core::Envelope::verify(&envelope, &pk, &signature).expect("firma válida");

    let json = envelope.encode().expect("encode");
    assert!(
        json.contains("\"protocolVersion\""),
        "protocolVersion presente"
    );
    assert!(json.contains("\"cryptoSuite\""), "cryptoSuite presente");
    assert!(
        json.contains("\"messageVersion\""),
        "messageVersion presente"
    );

    let decoded = boxkey_core::Envelope::decode(&json).expect("round-trip");
    assert_eq!(decoded.message_type, envelope.message_type);

    let _ = hidden;
    let _ = msg;
}
