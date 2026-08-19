//! Bench de firma FROST (ver plan Fase 1). Mide coste por contribución parcial
//! y por verificación, sobre un DKG 2-de-3 montado con la API pública.

use boxkey_core::dkg;
use boxkey_core::frost;
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

    let mut commitments = Vec::new();
    let mut full_public_keys = Vec::new();
    let mut hidden = Vec::new();
    for s in signers {
        let (h, comm) = frost::generate_nonces(s, &msg).unwrap();
        commitments.push((s.identifier(), comm));
        full_public_keys.push((s.identifier(), s.full_public_key_point()));
        hidden.push(h);
    }
    let round = frost::SigningRound::new(msg, group, &commitments, &full_public_keys).unwrap();

    c.bench_function("frost_partial_sign", |b| {
        b.iter(|| {
            let sig = frost::sign_partial(&round, &signers[0], &hidden[0]).unwrap();
            std::hint::black_box(sig);
        })
    });

    let sig = frost::sign_partial(&round, &signers[0], &hidden[0]).unwrap();
    c.bench_function("frost_verify_partial", |b| {
        b.iter(|| {
            frost::verify_partial(&sig, &signers[0].partial_public_key(), &msg).unwrap();
        });
    });
}

criterion_group!(benches, bench_partial_sign);
criterion_main!(benches);
