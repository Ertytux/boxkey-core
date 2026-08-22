//! Bench de firma FROST via frost-core adapter (frost-secp256k1-tr).
//! Mide coste por contribución parcial y por agregación,
//! sobre un DKG 2-de-3 montado con la API pública.

use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::{EncryptedShare, Share};
use criterion::{criterion_group, criterion_main, Criterion};

/// Un DKG completo con la API pública (n participantes, umbral t).
fn build_shares(n: u8, t: u8) -> Vec<Share> {
    let keys: Vec<_> = (0..n).map(|_| dkg::generate_participant_key()).collect();
    let pks: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();

    let mut first = Vec::new();
    let mut all = Vec::new();
    let mut encrypted_by = Vec::new();
    for _ in 0..n {
        let s = dkg::secret_with_threshold(&dkg::generate_secret(), t, n).unwrap();
        let comm = dkg::compute_commitments(&s);
        first.push(comm[0].clone());
        all.push(comm);
        encrypted_by.push(dkg::generate_shares(&s, &pks).unwrap());
    }

    let mut shares = Vec::new();
    for (sk, pk) in keys.iter() {
        let mut partials = Vec::new();
        for j in 0..n as usize {
            let mine: &EncryptedShare =
                encrypted_by[j].iter().find(|e| e.recipient == *pk).unwrap();
            let part = dkg::verify_and_decrypt_share(mine, sk).unwrap();
            dkg::verify_share(&part, &all[j]).unwrap();
            partials.push(part);
        }
        shares.push(dkg::combine_shares(&partials, t, &first).unwrap());
    }
    shares
}

fn bench_partial_sign(c: &mut Criterion) {
    let shares = build_shares(3, 2);
    let group = shares[0].group_public_key();
    let msg = [0x9u8; 32];
    let signers = &shares[..2];

    let mut rng = rand::rngs::OsRng;
    let mut hidden = Vec::new();
    let mut commitments = Vec::new();
    for s in signers {
        let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
        hidden.push(h);
        commitments.push(comm);
    }

    c.bench_function("frost_adapter_partial_sign", |b| {
        b.iter(|| {
            let sig = frost_adapter::sign_partial(&signers[0], &msg, &commitments, &hidden[0])
                .unwrap();
            std::hint::black_box(sig);
        })
    });

    let sig = frost_adapter::sign_partial(&signers[0], &msg, &commitments, &hidden[0]).unwrap();
    let all_sigs = vec![sig];
    c.bench_function("frost_adapter_aggregate", |b| {
        b.iter(|| {
            let agg =
                frost_adapter::aggregate_signatures(&all_sigs, &group, &msg).unwrap();
            std::hint::black_box(agg);
        })
    });
}

criterion_group!(benches, bench_partial_sign);
criterion_main!(benches);