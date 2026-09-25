//! Resharing — redistribución de un BoxKey existente a un nuevo conjunto de
//! participantes (t'-de-n'), preservando la misma clave pública del grupo.
//!
//! Esquema (evaluación de Lagrange del polinomio original `f` en los nuevos
//! identificadores):
//!
//! 1. Un conjunto de contribuyentes `S` (basta el umbral del grupo original)
//!    elige qué identificadores usará el nuevo grupo `T`.
//! 2. Cada contribuyente `j ∈ S` entrega, cifrada vía ECDH a cada nuevo
//!    participante `k ∈ T`, el término `λ_{j,S}(k)·f(j)`, donde
//!    `λ_{j,S}(k) = ∏_{l∈S∖{j}} (k−l)/(j−l)`.
//! 3. El nuevo participante `k` descifra, verifica cada término contra la clave
//!    pública parcial del contribuyente ([`verify_redistributed_share`]) y
//!    suma: obtiene `f(k)` — share válida del **mismo** polinomio.
//! 4. La clave del grupo es la conocida (pública) del BoxKey original:
//!    [`combine_redistributed_shares`] la fija tal cual.
//!
//! # Advertencia de seguridad
//! Tras completar la ronda, los contribuyentes DEBEN destruir sus shares
//! antiguas (política de la capa BS). Si no, el conjunto de seguridad sigue
//! siendo el antiguo. Este módulo no automatiza esa destrucción.
//!
//! Ver `rfc.md §3.4` y `BZ.md Anexo A`.

use crate::dkg::lagrange_coeff;
use crate::error::Error;
use crate::secp256k1::{
    point_from_bytes, point_mul_base, point_to_bytes, scalar_from_canonical_or_zero,
    scalar_to_bytes, Fs,
};
use crate::types::{EncryptedShare, PublicKey, SecretKey, Share};
use zeroize::Zeroizing;

/// Cifra el término `λ_{j,S}(k)·f(j)` del contribuyente hacia el nuevo
/// participante `k`.
///
/// - `contributor`: share del contribuyente del grupo original.
/// - `contributor_set`: identificadores de los contribuyentes (`S`).
/// - `new_id`: identificador del nuevo participante (`k ∈ T`).
/// - `new_threshold`: umbral del nuevo BoxKey (se embebe en el payload).
/// - `recipient`: clave pública x-only del nuevo participante.
pub fn redistribute_one(
    contributor: &Share,
    contributor_set: &[u32],
    new_id: u32,
    new_threshold: u8,
    recipient: &PublicKey,
) -> Result<EncryptedShare, Error> {
    if new_id == 0 {
        return Err(Error::InvalidShare("identificador nuevo inválido".into()));
    }
    if !contributor_set.contains(&contributor.identifier()) {
        return Err(Error::InconsistentGroup(
            "contribuyente fuera del conjunto declarado".into(),
        ));
    }
    let lambda = lagrange_coeff(new_id, contributor_set, contributor.identifier());
    let f_j = scalar_from_canonical_or_zero(&contributor.value)
        .map_err(|_| Error::InvalidShare("share de contribuyente inválida".into()))?;
    let term = lambda * f_j;

    let mut plain = Vec::with_capacity(37);
    plain.extend_from_slice(&new_id.to_be_bytes());
    plain.push(new_threshold);
    plain.extend_from_slice(&scalar_to_bytes(&term));

    let ciphertext = crate::dkg::encrypt_payload(&plain, recipient)?;
    Ok(EncryptedShare {
        recipient: *recipient,
        ciphertext,
    })
}

/// Descifra un término de redistribución recibido.
///
/// Reutiliza el formato de [`Share`] del protocolo: `identifier = new_id`,
/// `threshold = new_threshold`, `value = λ·f(j)`, `group_public_key` se fija
/// después al combinar.
pub fn verify_and_decrypt_redistributed(
    encrypted: &EncryptedShare,
    my_key: &SecretKey,
    expected_new_id: u32,
) -> Result<Share, Error> {
    let share = crate::dkg::verify_and_decrypt_share(encrypted, my_key)?;
    if share.identifier() != expected_new_id {
        return Err(Error::InconsistentGroup(format!(
            "identificador {} != esperado {expected_new_id}",
            share.identifier()
        )));
    }
    Ok(share)
}

/// Verifica que `share.value == λ_{j,S}(new_id)·f(j)` frente al punto
/// SEC1 comprimido del contribuyente (con paridad Y): `value·G == λ·Y_j`.
pub fn verify_redistributed_share(
    share: &Share,
    contributor_full_public_key: &[u8; 33],
    contributor_set: &[u32],
    contributor_id: u32,
) -> Result<(), Error> {
    let lambda = lagrange_coeff(share.identifier(), contributor_set, contributor_id);
    let term = scalar_from_canonical_or_zero(&share.value)
        .map_err(|_| Error::InvalidShare("valor inválido".into()))?;
    let lhs_pt = point_mul_base(&term);

    let y = point_from_bytes(contributor_full_public_key)?;
    let rhs = y * lambda;
    if point_to_bytes(&lhs_pt) != point_to_bytes(&rhs) {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

/// Suma los términos descifrados y verificados (`Σ_j λ_j(k)·f(j) = f(k)`),
/// fijando la clave pública del grupo (preservada del BoxKey original).
pub fn combine_redistributed_shares(
    contributions: &[Share],
    group_public_key: PublicKey,
) -> Result<Share, Error> {
    if contributions.is_empty() {
        return Err(Error::InvalidShare("sin contribuciones".into()));
    }
    let new_id = contributions[0].identifier();
    if contributions.iter().any(|c| c.identifier() != new_id) {
        return Err(Error::InconsistentGroup(
            "identificadores distintos en contribuciones".into(),
        ));
    }
    let t = usize::from(contributions[0].threshold());
    if contributions.len() < t {
        return Err(Error::ThresholdNotMet {
            required: t,
            received: contributions.len(),
        });
    }

    let mut sk = Fs::ZERO;
    for c in contributions {
        let v = scalar_from_canonical_or_zero(&c.value)
            .map_err(|_| Error::InvalidShare("contribución inválida".into()))?;
        sk += v;
    }
    if sk.is_zero().into() {
        return Err(Error::InvalidShare("share combinada cero".into()));
    }

    Ok(Share {
        identifier: new_id,
        value: Zeroizing::new(scalar_to_bytes(&sk)),
        threshold: contributions[0].threshold(),
        group_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;
    use crate::frost_adapter;
    use crate::secp256k1::{point_x_bytes, scalar_random, scalar_to_bytes};
    use rand::rngs::OsRng;

    fn random_key() -> (SecretKey, PublicKey) {
        let s = scalar_random(&mut OsRng);
        let sk = SecretKey(scalar_to_bytes(&s));
        let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
        (sk, pk)
    }

    /// 2-de-3 → 2-de-4: el nuevo grupo sigue firmando bajo la MISMA clave.
    #[test]
    fn resharing_preserves_group_key_and_signs() {
        let (old_shares, _old_keys) = dkg::run_dkg(3, 2);
        let group_key = old_shares[0].group_public_key();

        let contributors = &old_shares[..2];
        let contributor_set: Vec<u32> = contributors.iter().map(|s| s.identifier()).collect();

        // Nuevo grupo de 4 participantes con ids 1..=4.
        let new_keys: Vec<(SecretKey, PublicKey)> = (0..4).map(|_| random_key()).collect();
        let new_ids: Vec<u32> = (1u32..=4).collect();
        let new_threshold = 2u8;

        // Cada contribuyente entrega a cada nuevo participant.
        let mut deliveries_per_contributor = Vec::new();
        for c in contributors.iter().take(2) {
            let mut vec = Vec::new();
            for k in 0..4 {
                let enc = redistribute_one(
                    c,
                    &contributor_set,
                    new_ids[k],
                    new_threshold,
                    &new_keys[k].1,
                )
                .unwrap();
                vec.push(enc);
            }
            deliveries_per_contributor.push(vec);
        }

        // Cada nuevo participante combina sus contribuciones.
        let mut new_shares = Vec::new();
        for k in 0..4 {
            let mut contributions = Vec::new();
            for j in 0..2 {
                let enc = &deliveries_per_contributor[j][k];
                let share =
                    verify_and_decrypt_redistributed(enc, &new_keys[k].0, new_ids[k]).unwrap();
                verify_redistributed_share(
                    &share,
                    &contributors[j].full_public_key_point(),
                    &contributor_set,
                    contributors[j].identifier(),
                )
                .expect("contribución verificada");
                contributions.push(share);
            }
            let combined = combine_redistributed_shares(&contributions, group_key).unwrap();
            assert_eq!(combined.group_public_key(), group_key);
            new_shares.push(combined);
        }

        // Dos de los cuatro nuevos firmantes firman y la FROST (frost-core) verifica.
        let msg = [0x77u8; 32];
        let signers = &new_shares[..2];
        let mut rng = OsRng;
        let mut handles = Vec::new();
        let mut commitments = Vec::new();
        let mut verifying = Vec::new();
        for s in signers {
            let (h, comm) = frost_adapter::generate_nonces(s, &mut rng).unwrap();
            handles.push(h);
            commitments.push(comm);
            verifying.push((s.identifier(), s.full_public_key_point()));
        }
        let session = crate::types::SigningSession::new(
            msg, group_key, 2, commitments, verifying,
        ).unwrap();
        let mut sigs = Vec::new();
        for (i, s) in signers.iter().enumerate() {
            sigs.push(
                frost_adapter::sign_partial(s, &session, &mut handles[i]).unwrap(),
            );
        }
        let agg = frost_adapter::aggregate_signatures(&sigs, &session)
            .unwrap();
        frost_adapter::verify_schnorr(&agg, &group_key, &msg)
            .expect("firma del grupo redistribuido");
    }
}
