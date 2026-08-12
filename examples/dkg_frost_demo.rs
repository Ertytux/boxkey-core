//! Demo end-to-end de BoxKey Core (BC):
//! 1. DKG 2-de-3 → 3 participantes generan un BoxKey
//! 2. Firma FROST 2-de-3 → 2 firmantes firman un mensaje
//! 3. Verificación Schnorr BIP340 de la firma agregada
//! 4. Redistribución (resharing) 2-de-3 → 2-de-4
//! 5. Nuevos firmantes firman con la misma clave de grupo
//!
//! Uso: cargo run --example dkg_frost_demo

use sha2::Digest;

use boxkey_core::dkg;
use boxkey_core::frost;
use boxkey_core::reshare;
use boxkey_core::PublicKey;

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

    let signers: &[boxkey_core::Share] = &shares[..2]; // firmantes 1 y 2

    // Cada firmante genera nonces deterministas
    let mut commitments = Vec::new();
    let mut full_public_keys = Vec::new();
    let mut hidden = Vec::new();
    for s in signers {
        let (h, comm) = frost::generate_nonces(s, &msg_hash).unwrap();
        commitments.push((s.identifier(), comm.clone()));
        full_public_keys.push((s.identifier(), s.full_public_key_point()));
        hidden.push(h);
    }

    // El coordinador arma el round
    let round =
        frost::SigningRound::new(msg_hash, group_key, &commitments, &full_public_keys).unwrap();
    println!("    Round de firma con {} firmante(s)", round.signers.len());

    // Cada firmante produce su contribución parcial
    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        let sig = frost::sign_partial(&round, s, &hidden[i]).unwrap();
        sigs.push(sig);
        println!(
            "      Firmante {}: contribución parcial ({} B)",
            s.identifier(),
            sigs[i].as_bytes().len()
        );
    }

    // Verificación cruzada de las contribuciones parciales
    for (i, s) in signers.iter().enumerate() {
        frost::verify_partial(&sigs[i], &s.partial_public_key(), &msg_hash)
            .expect("contribución parcial válida");
    }
    println!("    ✓ 2 contribuciones parciales verificadas");

    // Agregación
    let agg = frost::aggregate_signatures(&sigs, &group_key, &msg_hash).expect("agregación válida");
    println!("    Firma Schnorr BIP340: {}", hex::encode(agg.0));

    // Verificación final
    frost::verify_schnorr(&agg, &group_key, &msg_hash).expect("firma final válida");
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
    let mut new_commitments = Vec::new();
    let mut new_full_pks = Vec::new();
    let mut new_hidden = Vec::new();
    for s in new_signers {
        let (h, comm) = frost::generate_nonces(s, &msg_hash).unwrap();
        new_commitments.push((s.identifier(), comm.clone()));
        new_full_pks.push((s.identifier(), s.full_public_key_point()));
        new_hidden.push(h);
    }
    let new_round =
        frost::SigningRound::new(msg_hash, group_key, &new_commitments, &new_full_pks).unwrap();

    let mut new_sigs = Vec::new();
    for (i, s) in new_signers.iter().enumerate() {
        let sig = frost::sign_partial(&new_round, s, &new_hidden[i]).unwrap();
        new_sigs.push(sig);
    }
    for (i, s) in new_signers.iter().enumerate() {
        frost::verify_partial(&new_sigs[i], &s.partial_public_key(), &msg_hash)
            .expect("nueva contribución válida");
    }
    let new_agg = frost::aggregate_signatures(&new_sigs, &group_key, &msg_hash)
        .expect("nueva agregación válida");
    frost::verify_schnorr(&new_agg, &group_key, &msg_hash).expect("nueva firma final válida");
    println!(
        "    ✓ Nueva firma BIP340 válida: {}",
        hex::encode(new_agg.0)
    );
    println!();
    println!("=== Demo completada exitosamente ===");
}
