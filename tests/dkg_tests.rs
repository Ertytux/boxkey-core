use boxkey_core::dkg;
use boxkey_core::Commitment;

#[test]
fn dkg_feliz_dos_participantes_misma_clave_publica() {
    let (shares, _keys) = dkg::run_dkg(2, 2);
    assert_eq!(
        shares[0].group_public_key(),
        shares[1].group_public_key(),
        "ambas shares derivan la misma clave pública"
    );
}

#[test]
fn dkg_commitments_inconsistentes_se_detectan() {
    let n = 3u8;
    let t = 2u8;

    let secret = dkg::generate_secret();
    let configured = dkg::secret_with_threshold(&secret, t, n).unwrap();
    let pok = dkg::generate_proof_of_knowledge(&configured);

    let honest: Vec<Commitment> = dkg::compute_commitments(&configured);
    assert_eq!(honest.len(), 2, "grado = threshold - 1");
    dkg::verify_commitments(&honest, &pok).expect("commitments honestos verifican");

    let mut tampered = honest.clone();
    let last = tampered.pop().unwrap();
    tampered.insert(0, last);
    assert_ne!(
        tampered, honest,
        "commitments reordenados difieren del orden honesto"
    );

    let rejected = dkg::verify_commitments(&tampered, &pok);
    assert!(rejected.is_err(), "participante malicioso abortado");
}
