use sha2::Digest;

use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::reshare;
use boxkey_core::{PublicKey, SigningSession};

fn main() {
    println!("=== BoxKey Core (BC) — Demo End-to-End ===");
    println!();

    // ── Paso 1: DKG 2-de-3 ──────────────────────────────────────────────
    println!("[1] DKG 2-de-3 (3 participantes, umbral 2)");
    let (shares, _keys) = dkg::run_dkg(3, 2);
    let group_key = shares[0].group_public_key();
    println!("    Clave pública del BoxKey: {}", hex::encode(group_key.0));
    println!("    Shares generadas: 3 (ids 1, 2, 3)");
    for s in &shares {
        println!(
            "      Participante {}: key parcial = {}",
            s.identifier(),
            hex::encode(s.partial_public_key().0)
        );
    }
    println!();

    // ── Paso 2: Firma FROST 2-de-3 ──────────────────────────────────────
    let msg = b"BoxKey Protocol - FROST over secp256k1";
    let msg_hash: [u8; 32] = {
        let mut h = sha2::Sha256::new();
        h.update(msg);
        h.finalize().into()
    };
    println!("[2] Firma FROST (2 signatarios)");
    println!("    Mensaje: \"{}\"", core::str::from_utf8(msg).unwrap());
    println!("    Hash:    {}", hex::encode(msg_hash));

    let signers: &[boxkey_core::Share] = &shares[..2];
    let mut rng = rand::rngs::OsRng;

    // Cada firmante genera nonces via frost-core (RFC 9591)
    let mut handles = Vec::new();
    let mut commitments = Vec::new();
    let mut verifying = Vec::new();
    for s in signers {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        handles.push(h);
        commitments.push(comm);
        verifying.push((s.identifier(), s.full_public_key_point()));
    }
    println!("    Nonces generados para 2 firmantes");

    let session = SigningSession::new(msg_hash, group_key, 2, commitments, verifying)
        .expect("sesión válida");

    // Cada firmante produce su contribución parcial
    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        let sig = frost_adapter::sign_partial(s, &session, &mut handles[i]).unwrap();
        sigs.push(sig);
        println!(
            "      Firmante {}: contribución parcial ({} B)",
            s.identifier(),
            sigs[i].as_bytes().len()
        );
    }
    println!("    ✓ 2 contribuciones parciales generadas");

    // Agregación via frost-core
    let agg = frost_adapter::aggregate_signatures(&sigs, &session)
        .expect("agregación válida");
    println!("    Firma Schnorr BIP340: {}", hex::encode(agg.0));

    // Verificación final via k256::schnorr (independiente de FROST)
    frost_adapter::verify_schnorr(&agg, &group_key, &msg_hash).expect("firma final válida");
    println!("    ✓ Firma BIP340 verificada contra la clave del BoxKey");
    println!();

    // ── Paso 3: Redistribución 2-de-3 → 2-de-4 ─────────────────────────
    println!("[3] Redistribución (resharing) 2-de-3 → 2-de-4");
    let new_keys: Vec<(boxkey_core::SecretKey, PublicKey)> =
        (0..4).map(|_| dkg::generate_participant_key()).collect();
    let new_ids: Vec<u32> = (1u32..=4).collect();
    let contributor_set: Vec<u32> = signers
        .iter()
        .map(|s: &boxkey_core::Share| s.identifier())
        .collect();

    let mut deliveries = Vec::new();
    for c in signers.iter().take(2) {
        let mut vec = Vec::new();
        for k in 0..4 {
            let enc = reshare::redistribute_one(c, &contributor_set, new_ids[k], 2, &new_keys[k].1)
                .unwrap();
            vec.push(enc);
        }
        deliveries.push(vec);
    }
    println!(
        "    {} contribuyentes → 4 nuevos participantes",
        deliveries.len()
    );

    // Nuevos participantes combinan sus shares
    let mut new_shares = Vec::new();
    for k in 0..4 {
        let mut contributions = Vec::new();
        for j in 0..2 {
            let enc = &deliveries[j][k];
            let share =
                reshare::verify_and_decrypt_redistributed(enc, &new_keys[k].0, new_ids[k]).unwrap();
            reshare::verify_redistributed_share(
                &share,
                &signers[j].full_public_key_point(),
                &contributor_set,
                signers[j].identifier(),
            )
            .expect("contribución redistribuida verificada");
            contributions.push(share);
        }
        let combined = reshare::combine_redistributed_shares(&contributions, group_key).unwrap();
        assert_eq!(combined.group_public_key(), group_key);
        println!("      Nuevo participante {}: share ok", new_ids[k],);
        new_shares.push(combined);
    }
    println!(
        "    ✓ Clave de grupo preservada: {}",
        hex::encode(group_key.0)
    );
    println!();

    // ── Paso 4: Nuevos firmantes firman ─────────────────────────────────
    println!("[4] Nuevos firmantes (2-de-4) firman el mismo mensaje");
    let new_signers: &[boxkey_core::Share] = &new_shares[..2];
    let mut new_handles = Vec::new();
    let mut new_commitments = Vec::new();
    let mut new_verifying = Vec::new();
    for s in new_signers {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        new_handles.push(h);
        new_commitments.push(comm);
        new_verifying.push((s.identifier(), s.full_public_key_point()));
    }

    let new_session = SigningSession::new(msg_hash, group_key, 2, new_commitments, new_verifying)
        .expect("nueva sesión válida");

    let mut new_sigs = Vec::new();
    for (i, s) in new_signers.iter().enumerate() {
        let sig = frost_adapter::sign_partial(s, &new_session, &mut new_handles[i]).unwrap();
        new_sigs.push(sig);
    }

    let new_agg = frost_adapter::aggregate_signatures(&new_sigs, &new_session)
        .expect("nueva agregación válida");
    frost_adapter::verify_schnorr(&new_agg, &group_key, &msg_hash)
        .expect("nueva firma final válida");
    println!(
        "    ✓ Nueva firma BIP340 válida: {}",
        hex::encode(new_agg.0)
    );
    println!();
    println!("=== Demo completada exitosamente ===");
}