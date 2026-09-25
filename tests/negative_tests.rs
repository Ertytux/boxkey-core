//! Tests de semántica message / SigningDigest (C6) y tests negativos (C9).

use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::SigningSession;

/// C6: BC recibe un hash de 32 bytes (SigningDigest), no un mensaje raw.
/// El hash debe hacerse externamente (SHA-256).
#[test]
fn correct_digest_verifica() {
    let (shares, _) = dkg::run_dkg(1, 1);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut handle, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let vk = shares[0].full_public_key_point();

    let session = SigningSession::new(msg, group, 1, vec![comm], vec![(shares[0].identifier(), vk)])
        .expect("sesión");
    let sig = frost_adapter::sign_partial(&shares[0], &session, &mut handle).unwrap();
    let agg = frost_adapter::aggregate_signatures(&[sig], &session).unwrap();
    assert!(frost_adapter::verify_schnorr(&agg, &group, &msg).is_ok());
}

/// C6: Digest incorrecto debe ser rechazado.
#[test]
fn wrong_digest_rechazado() {
    let (shares, _) = dkg::run_dkg(1, 1);
    let group = shares[0].group_public_key();
    let correct_msg = [0x42u8; 32];
    let wrong_msg = [0x43u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut handle, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let vk = shares[0].full_public_key_point();

    let session = SigningSession::new(correct_msg, group, 1, vec![comm], vec![(shares[0].identifier(), vk)])
        .expect("sesión");
    let sig = frost_adapter::sign_partial(&shares[0], &session, &mut handle).unwrap();
    let agg = frost_adapter::aggregate_signatures(&[sig], &session).unwrap();

    // Verificar con digest incorrecto
    assert!(frost_adapter::verify_schnorr(&agg, &group, &wrong_msg).is_err());
}

/// C6: Doble hashing accidental debe detectarse.
#[test]
fn double_hash_detectado() {
    use sha2::Digest;
    let (shares, _) = dkg::run_dkg(1, 1);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];
    let double_hashed: [u8; 32] = sha2::Sha256::digest(&msg[..]).into();

    let mut rng = rand::rngs::OsRng;
    let (mut handle, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let vk = shares[0].full_public_key_point();

    let session = SigningSession::new(msg, group, 1, vec![comm], vec![(shares[0].identifier(), vk)])
        .expect("sesión");
    let sig = frost_adapter::sign_partial(&shares[0], &session, &mut handle).unwrap();
    let agg = frost_adapter::aggregate_signatures(&[sig], &session).unwrap();

    // Verificar con double-hashed: debe fallar
    assert!(frost_adapter::verify_schnorr(&agg, &group, &double_hashed).is_err());
}

// ── Tests negativos (C9) ─────────────────────────────────────────────────

/// Wrong group public key: firma contra grupo A, verificar con grupo B.
#[test]
fn wrong_group_public_key_rechazado() {
    let (shares_a, _) = dkg::run_dkg(2, 2);
    let (shares_b, _) = dkg::run_dkg(2, 2);
    let group_a = shares_a[0].group_public_key();
    let group_b = shares_b[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut h1, c1) = frost_adapter::generate_nonces(&shares_a[0], &mut rng).unwrap();
    let (mut h2, c2) = frost_adapter::generate_nonces(&shares_a[1], &mut rng).unwrap();

    let session = SigningSession::new(msg, group_a, 2,
        vec![c1, c2],
        vec![(shares_a[0].identifier(), shares_a[0].full_public_key_point()),
             (shares_a[1].identifier(), shares_a[1].full_public_key_point())],
    ).unwrap();

    let sig0 = frost_adapter::sign_partial(&shares_a[0], &session, &mut h1).unwrap();
    let sig1 = frost_adapter::sign_partial(&shares_a[1], &session, &mut h2).unwrap();
    let agg = frost_adapter::aggregate_signatures(&[sig0, sig1], &session).unwrap();

    // Verificar con grupo B
    assert!(frost_adapter::verify_schnorr(&agg, &group_b, &msg).is_err());
}

/// Wrong participant ID en commitment.
#[test]
fn wrong_participant_id_rechazado() {
    let (shares, _) = dkg::run_dkg(3, 2);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut h1, mut c1) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let (mut h2, c2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();

    // Tamper commitment: cambiar id de 1 a 99
    c1.0[..4].copy_from_slice(&99u32.to_be_bytes());

    let session = SigningSession::new(msg, group, 2,
        vec![c1, c2],
        vec![(shares[0].identifier(), shares[0].full_public_key_point()),
             (shares[1].identifier(), shares[1].full_public_key_point())],
    );

    // Debe fallar porque el id del commitment no coincide
    assert!(session.is_err(), "commitment con id erróneo debe rechazarse");
    let _ = h1;
    let _ = h2;
}

/// Insufficient threshold: solo 1 firma cuando se requieren 2.
#[test]
fn insufficient_threshold_rechazado() {
    let (shares, _) = dkg::run_dkg(2, 2);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut h1, c1) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let (mut _h2, c2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();

    // Session con 2 commitments (threshold 2) pero solo 1 firma
    let session = SigningSession::new(msg, group, 2,
        vec![c1, c2],
        vec![(shares[0].identifier(), shares[0].full_public_key_point()),
             (shares[1].identifier(), shares[1].full_public_key_point())],
    ).expect("sesión con 2 firmantes");

    let sig0 = frost_adapter::sign_partial(&shares[0], &session, &mut h1).unwrap();
    // Solo 1 firma para threshold 2
    let result = frost_adapter::aggregate_signatures(&[sig0], &session);
    assert!(result.is_err(), "threshold insuficiente debe fallar");
}

/// Nonce reuse: mismo commitment usado dos veces.
#[test]
fn nonce_reuse_detectado() {
    let (shares, _) = dkg::run_dkg(2, 2);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut h1, c1) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let (mut h2, c2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();

    let session = SigningSession::new(msg, group, 2,
        vec![c1, c2],
        vec![(shares[0].identifier(), shares[0].full_public_key_point()),
             (shares[1].identifier(), shares[1].full_public_key_point())],
    ).expect("sesión");

    let sig0 = frost_adapter::sign_partial(&shares[0], &session, &mut h1).unwrap();
    let sig1 = frost_adapter::sign_partial(&shares[1], &session, &mut h2).unwrap();

    // Intentar agregar la misma firma dos veces como si fueran firmantes distintos
    let result = frost_adapter::aggregate_signatures(&[sig0.clone(), sig0, sig1], &session);
    assert!(result.is_err(), "nonce reuse debe ser detectado");
}

/// Invalid BIP340 signature: firma agregada manipulada.
#[test]
fn invalid_bip340_signature_rechazada() {
    let (shares, _) = dkg::run_dkg(1, 1);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut handle, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let vk = shares[0].full_public_key_point();

    let session = SigningSession::new(msg, group, 1, vec![comm], vec![(shares[0].identifier(), vk)])
        .expect("sesión");
    let sig = frost_adapter::sign_partial(&shares[0], &session, &mut handle).unwrap();
    let mut agg = frost_adapter::aggregate_signatures(&[sig], &session).unwrap();
    agg.0[0] ^= 0x01;  // manipular R

    assert!(frost_adapter::verify_schnorr(&agg, &group, &msg).is_err());
}

/// NonceHandle consumido: no se puede reutilizar.
#[test]
fn nonce_handle_consumido_no_reutilizable() {
    let (shares, _) = dkg::run_dkg(1, 1);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut handle, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let vk = shares[0].full_public_key_point();

    let session = SigningSession::new(msg, group, 1, vec![comm], vec![(shares[0].identifier(), vk)])
        .expect("sesión");

    // Primera firma: ok
    frost_adapter::sign_partial(&shares[0], &session, &mut handle).unwrap();
    assert!(handle.is_consumed());

    // Segunda firma: debe fallar (handle consumido)
    let result = frost_adapter::sign_partial(&shares[0], &session, &mut handle);
    assert!(result.is_err(), "handle consumido debe rechazar segunda firma");
}

/// Wrong share ↔ nonce handle: NonceHandle(A) con Share(B) debe rechazar.
#[test]
fn wrong_share_nonce_handle_is_rejected() {
    let (shares, _) = dkg::run_dkg(2, 2);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;

    // Generar nonces para ambos firmantes
    let (mut h1, c1) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let (mut h2, c2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();

    let vk1 = shares[0].full_public_key_point();
    let vk2 = shares[1].full_public_key_point();

    let session = SigningSession::new(msg, group, 2,
        vec![c1, c2],
        vec![(shares[0].identifier(), vk1), (shares[1].identifier(), vk2)],
    ).expect("sesión");

    // Intentar firmar con share[0] pero NonceHandle[1] → debe rechazar
    let result = frost_adapter::sign_partial(&shares[0], &session, &mut h2);
    assert!(result.is_err(), "share A + handle B debe rechazar");

    // El handle B no debe quedar consumido tras el rechazo
    assert!(!h2.is_consumed(), "handle B no debe consumirse tras error de asociación");

    // La combinación correcta sí funciona
    let sig1 = frost_adapter::sign_partial(&shares[0], &session, &mut h1).unwrap();
    let sig2 = frost_adapter::sign_partial(&shares[1], &session, &mut h2).unwrap();
    let agg = frost_adapter::aggregate_signatures(&[sig1, sig2], &session).unwrap();
    assert!(frost_adapter::verify_schnorr(&agg, &group, &msg).is_ok());
}

/// Missing signer: firmante no incluido en la sesión.
#[test]
fn missing_signer_rechazado() {
    let (shares, _) = dkg::run_dkg(3, 2);
    let group = shares[0].group_public_key();
    let msg = [0x42u8; 32];

    let mut rng = rand::rngs::OsRng;
    let (mut h1, c1) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
    let (mut h2, c2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();
    let (mut _h3, c3) = frost_adapter::generate_nonces(&shares[2], &mut rng).unwrap();

    // Session con 3 commitments pero solo 2 firmas (shares[0] y shares[1])
    // y shares[2] no firma
    let session = SigningSession::new(msg, group, 2,
        vec![c1, c2, c3],
        vec![
            (shares[0].identifier(), shares[0].full_public_key_point()),
            (shares[1].identifier(), shares[1].full_public_key_point()),
            (shares[2].identifier(), shares[2].full_public_key_point()),
        ],
    ).expect("sesión con 3 firmantes");

    let sig0 = frost_adapter::sign_partial(&shares[0], &session, &mut h1).unwrap();
    let sig1 = frost_adapter::sign_partial(&shares[1], &session, &mut h2).unwrap();
    let result = frost_adapter::aggregate_signatures(&[sig0, sig1], &session);
    // Con 3 firmantes en la sesión, se esperan 3 firmas (ver aggregate)
    // Pero solo damos 2, así que debe fallar
    assert!(result.is_err(), "missing signer debe fallar");
}