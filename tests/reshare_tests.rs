use boxkey_core::dkg;
use boxkey_core::frost;
use boxkey_core::reshare;
use boxkey_core::{PublicKey, SecretKey};

fn random_key() -> (SecretKey, PublicKey) {
    dkg::generate_participant_key()
}

#[test]
fn resharing_2de3_a_2de4_preserva_clave_y_permite_firmar() {
    let (old_shares, _old_keys) = dkg::run_dkg(3, 2);
    let group_key = old_shares[0].group_public_key();

    let contributors = &old_shares[..2];
    let contributor_set: Vec<u32> = contributors.iter().map(|s| s.identifier()).collect();

    let new_keys: Vec<(SecretKey, PublicKey)> = (0..4).map(|_| random_key()).collect();
    let new_ids: Vec<u32> = (1u32..=4).collect();
    let new_threshold = 2u8;

    let mut deliveries = Vec::new();
    for c in contributors {
        let mut vec = Vec::new();
        for k in 0..4 {
            let enc = reshare::redistribute_one(
                c,
                &contributor_set,
                new_ids[k],
                new_threshold,
                &new_keys[k].1,
            )
            .unwrap();
            vec.push(enc);
        }
        deliveries.push(vec);
    }

    let mut new_shares = Vec::new();
    for k in 0..4 {
        let mut contributions = Vec::new();
        for j in 0..2 {
            let enc = &deliveries[j][k];
            let share =
                reshare::verify_and_decrypt_redistributed(enc, &new_keys[k].0, new_ids[k]).unwrap();
            reshare::verify_redistributed_share(
                &share,
                &contributors[j].full_public_key_point(),
                &contributor_set,
                contributors[j].identifier(),
            )
            .expect("contribución verificada");
            contributions.push(share);
        }
        let combined = reshare::combine_redistributed_shares(&contributions, group_key).unwrap();
        assert_eq!(combined.group_public_key(), group_key);
        new_shares.push(combined);
    }

    let msg = [0x77u8; 32];
    let signers = &new_shares[..2];
    let mut commitments = Vec::new();
    let mut full_keys = Vec::new();
    let mut hidden = Vec::new();
    for s in signers {
        let (h, comm) = frost::generate_nonces(s, &msg).unwrap();
        commitments.push((s.identifier(), comm.clone()));
        full_keys.push((s.identifier(), s.full_public_key_point()));
        hidden.push(h);
    }
    let round = frost::SigningRound::new(msg, group_key, &commitments, &full_keys).unwrap();
    let mut sigs = Vec::new();
    for (i, s) in signers.iter().enumerate() {
        sigs.push(frost::sign_partial(&round, s, &hidden[i]).unwrap());
    }
    let agg = frost::aggregate_signatures(&sigs, &group_key, &msg).unwrap();
    assert!(
        frost::verify_schnorr(&agg, &group_key, &msg).is_ok(),
        "el grupo redistribuido firma bajo la misma clave"
    );
}
