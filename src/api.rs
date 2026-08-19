//! Capa de API conforme a `contratos.md §2` de `boxkey-protocol`.
//!
//! Define el trait [`BoxKeyCore`] con las firmas de la interfaz pública de BC,
//! implementado por la struct vacía [`BoxKeyCoreImpl`]. Los métodos delegan en
//! el motor criptográfico verificado (`dkg`, `frost`, `reshare`) y añaden las
//! conveniencias de la Fase 1.0 (umbral por parámetro, nonces deterministas,
//! rediseño de shares).
//!
//! # Desviaciones frente al contrato
//!
//! El contrato declara firmas "desnudas" (`Vec`/`PublicKey`/`PartialSignature`
//! sin `Result`). Esta capa devuelve `Result` en toda operación que puede
//! fallar, marcando cada desviación con `/// Desviación: ...`. El contrato no
//! prohíbe estos tipos; los trata como una firma compatible y segura.
//!
//! Limitaciones del contrato (documentadas en cada método):
//! - `generate_nonces(share)` deriva nonces de un mensaje por defecto
//!   (`DEFAULT_NONCE_MSG`): la firma real (`sign_partial`) exige nonces
//!   ligados al mensaje (via `frost::generate_nonces(share, msg)`).
//! - `reshare_begin` asume un único contribuyente (`S = {old_share.id}`).
//!   El resharing threshold real queda en `reshare` (API avanzada).
//! - `reshare_accept` no fija `group_public_key` hasta combinar.

use crate::dkg;
use crate::error::Error;
use crate::frost;
use crate::reshare;
use crate::types::{
    Commitment, EncryptedShare, PartialSignature, PublicKey, SchnorrSignature, SecretKey,
    SecretShare, Share,
};

/// Mensaje por defecto para derivar nonces en `generate_nonces` (Fase 1.0).
///
/// La firma real (`sign_partial`) re-deriva los nonces del hash de mensaje
/// concreto; este valor solo cubre la conveniencia del contrato.
pub const DEFAULT_NONCE_MSG: [u8; 32] = [
    0x62, 0x6f, 0x78, 0x6b, 0x65, 0x79, 0x2f, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x6e,
    0x6f, 0x6e, 0x63, 0x65, 0x2d, 0x6d, 0x73, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Interfaz pública de BoxKey Core (BC), conforme a `contratos.md §2`.
pub trait BoxKeyCore {
    /// Genera un secreto local para el DKG (polinomio aleatorio).
    fn generate_secret() -> SecretShare;

    /// Computa los compromisos de coeficientes (Feldman VSS) fijando el umbral
    /// y el total de participantes.
    ///
    /// Devuelve `Vec::new()` si el umbral no puede configurarse (desviación:
    /// el contrato no cubre la falla de configuración; se informa vacío).
    fn compute_commitments(
        share: &SecretShare,
        threshold: u8,
        total_participants: u8,
    ) -> Vec<Commitment>;

    /// Verifica los compromisos recibidos de un participante.
    fn verify_commitments(
        commitments: &[Commitment],
        proof_of_knowledge: &[u8],
    ) -> Result<(), Error>;

    /// Genera shares cifradas para cada participante.
    /// Desviación: devuelve `Result` porque la configuración puede fallar.
    fn generate_shares(
        secret: &SecretShare,
        participants: &[PublicKey],
    ) -> Result<Vec<EncryptedShare>, Error>;

    /// Descifra y verifica una share recibida.
    fn verify_and_decrypt_share(
        encrypted: &EncryptedShare,
        my_key: &SecretKey,
    ) -> Result<Share, Error>;

    /// Deriva la clave pública agregada del BoxKey a partir de todas las shares.
    /// Desviación: devuelve `Result` (interpolación puede fallar).
    fn derive_public_key(shares: &[Share]) -> Result<PublicKey, Error>;

    /// Deriva la clave pública parcial de un participante.
    fn derive_partial_public_key(share: &Share) -> PublicKey;

    /// Genera nonces para firma parcial (hiding + binding), deterministas.
    ///
    /// Devuelve `(nonces_secretos, commitment_publicado)`:
    /// - primer elemento: `d || e` (64 bytes), se conserva en privado.
    /// - segundo: `id(4) || D(33) || E(33)` (70 bytes, BZ-0010 §2.8/2.9).
    ///
    /// Desviación: deriva los nonces de `DEFAULT_NONCE_MSG`, no del mensaje
    /// real. Para firmar se re-derivan del mensaje en `sign_partial`.
    /// Devuelve tuplas vacías si la share no tiene identificador (imposible en
    /// la práctica; nunca panic en biblioteca).
    fn generate_nonces(share: &Share) -> (Vec<u8>, Vec<u8>);

    /// Genera una firma parcial sobre `message_hash`.
    ///
    /// Desviación: devuelve `Result`; el contrato declara `PartialSignature`.
    /// Construye un `SigningRound` internamente a partir de los `commitments`
    /// recibidos y re-deriva los nonces del `message_hash` (los bloques `Y`
    /// ajenos no se usan en `z_i` y se rellenan con la clave parcial propia).
    fn sign_partial(
        share: &Share,
        message_hash: &[u8; 32],
        commitments: &[Commitment],
    ) -> Result<PartialSignature, Error>;

    /// Verifica una firma parcial.
    ///
    /// Desviación: `sign_partial` no recibe las claves públicas de los demás
    /// firmantes del round, por lo que rellena sus bloques `Y` con la clave
    /// parcial propia. Consecuencia documentada: solo es fiable para rounds de
    /// un solo firmante o para el firmante cuyo bloque ocupa la primera
    /// posición; los demás deben verificar con la API avanzada
    /// (`frost::verify_partial` sobre un `SigningRound` con claves reales).
    fn verify_partial(
        sig: &PartialSignature,
        participant_pubkey: &PublicKey,
        message_hash: &[u8; 32],
    ) -> bool;

    /// Agrega firmas parciales en una firma Schnorr completa.
    fn aggregate_signatures(
        sigs: &[PartialSignature],
        pubkey: &PublicKey,
        message_hash: &[u8; 32],
    ) -> Result<SchnorrSignature, Error>;

    /// Verifica una firma Schnorr BIP340.
    fn verify_schnorr(sig: &SchnorrSignature, pubkey: &PublicKey, message_hash: &[u8; 32]) -> bool;

    /// Inicia resharing: genera nuevas shares para el nuevo conjunto.
    ///
    /// Desviación: devuelve `Result`; el contrato declara `Vec`. Convención del
    /// trait: `S = {old_share.identifier()}` (un único contribuyente,
    /// `λ = 1`). El resharing threshold real (varios contribuyentes con `S`
    /// común) queda expuesto en el módulo `reshare` (API avanzada).
    fn reshare_begin(
        old_share: &Share,
        new_participants: &[PublicKey],
        new_threshold: u8,
    ) -> Result<Vec<EncryptedShare>, Error>;

    /// Acepta una share de resharing y deriva la nueva share local.
    ///
    /// Desviación: la clave de grupo no se conoce en este punto; `Share.group_public_key`
    /// queda sin fijar hasta `reshare::combine_redistributed_shares` (API avanzada).
    fn reshare_accept(encrypted: &EncryptedShare, my_new_key: &SecretKey) -> Result<Share, Error>;
}

/// Implementación de [`BoxKeyCore`] que delega en el motor criptográfico.
#[derive(Default, Clone, Copy, Debug)]
pub struct BoxKeyCoreImpl;

impl BoxKeyCore for BoxKeyCoreImpl {
    fn generate_secret() -> SecretShare {
        dkg::generate_secret()
    }

    fn compute_commitments(
        share: &SecretShare,
        threshold: u8,
        total_participants: u8,
    ) -> Vec<Commitment> {
        match dkg::secret_with_threshold(share, threshold, total_participants) {
            Ok(s) => dkg::compute_commitments(&s),
            Err(_) => Vec::new(),
        }
    }

    fn verify_commitments(
        commitments: &[Commitment],
        proof_of_knowledge: &[u8],
    ) -> Result<(), Error> {
        dkg::verify_commitments(commitments, proof_of_knowledge)
    }

    fn generate_shares(
        secret: &SecretShare,
        participants: &[PublicKey],
    ) -> Result<Vec<EncryptedShare>, Error> {
        dkg::generate_shares(secret, participants)
    }

    fn verify_and_decrypt_share(
        encrypted: &EncryptedShare,
        my_key: &SecretKey,
    ) -> Result<Share, Error> {
        dkg::verify_and_decrypt_share(encrypted, my_key)
    }

    fn derive_public_key(shares: &[Share]) -> Result<PublicKey, Error> {
        dkg::derive_public_key(shares)
    }

    fn derive_partial_public_key(share: &Share) -> PublicKey {
        dkg::derive_partial_public_key(share)
    }

    fn generate_nonces(share: &Share) -> (Vec<u8>, Vec<u8>) {
        match frost::generate_nonces(share, &DEFAULT_NONCE_MSG) {
            Ok((hidden, commitment)) => (hidden, commitment.0),
            Err(_) => (Vec::new(), Vec::new()),
        }
    }

    fn sign_partial(
        share: &Share,
        message_hash: &[u8; 32],
        commitments: &[Commitment],
    ) -> Result<PartialSignature, Error> {
        let (hidden, own_commitment) = frost::generate_nonces(share, message_hash)?;
        let mut ids = Vec::with_capacity(commitments.len());
        for comm in commitments {
            if comm.0.len() < 4 {
                return Err(Error::InvalidSignature(
                    "commitment de nonces con longitud insuficiente".into(),
                ));
            }
            ids.push(u32::from_be_bytes(comm.0[..4].try_into().unwrap()));
        }
        let full_keys: Vec<(u32, [u8; 33])> = ids
            .iter()
            .map(|id| (*id, share.full_public_key_point()))
            .collect();

        // El round debe contener el commitment del propio firmante ligado al
        // mensaje (nonce match en `frost::sign_partial`).
        if ids.contains(&share.identifier()) {
            let own = own_commitment;
            let mut round_commitments = Vec::with_capacity(commitments.len());
            for (id, comm) in ids.iter().zip(commitments) {
                if *id == share.identifier() {
                    round_commitments.push((*id, own.clone()));
                } else {
                    round_commitments.push((*id, comm.clone()));
                }
            }
            let round = frost::SigningRound::new(
                *message_hash,
                share.group_public_key(),
                &round_commitments,
                &full_keys,
            )?;
            return frost::sign_partial(&round, share, &hidden);
        }
        Err(Error::InvalidSignature(
            "la share no está entre los firmantes del round".into(),
        ))
    }

    fn verify_partial(
        sig: &PartialSignature,
        participant_pubkey: &PublicKey,
        message_hash: &[u8; 32],
    ) -> bool {
        frost::verify_partial(sig, participant_pubkey, message_hash).is_ok()
    }

    fn aggregate_signatures(
        sigs: &[PartialSignature],
        pubkey: &PublicKey,
        message_hash: &[u8; 32],
    ) -> Result<SchnorrSignature, Error> {
        frost::aggregate_signatures(sigs, pubkey, message_hash)
    }

    fn verify_schnorr(sig: &SchnorrSignature, pubkey: &PublicKey, message_hash: &[u8; 32]) -> bool {
        frost::verify_schnorr(sig, pubkey, message_hash).is_ok()
    }

    fn reshare_begin(
        old_share: &Share,
        new_participants: &[PublicKey],
        new_threshold: u8,
    ) -> Result<Vec<EncryptedShare>, Error> {
        let contributor_set = vec![old_share.identifier()];
        let mut out = Vec::with_capacity(new_participants.len());
        for (idx, recipient) in new_participants.iter().enumerate() {
            out.push(reshare::redistribute_one(
                old_share,
                &contributor_set,
                (idx as u32) + 1,
                new_threshold,
                recipient,
            )?);
        }
        Ok(out)
    }

    fn reshare_accept(encrypted: &EncryptedShare, my_new_key: &SecretKey) -> Result<Share, Error> {
        dkg::verify_and_decrypt_share(encrypted, my_new_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_commitments_fixes_threshold() {
        let secret = <BoxKeyCoreImpl as BoxKeyCore>::generate_secret();
        let comms = <BoxKeyCoreImpl as BoxKeyCore>::compute_commitments(&secret, 2, 3);
        assert_eq!(comms.len(), 2, "grado = threshold - 1 => 2 compromisos");
    }

    #[test]
    fn full_dkg_flow_via_trait() {
        let n = 3u8;
        let t = 2u8;
        let mut keys = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = dkg::generate_participant_key();
            keys.push((sk, pk));
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
            <BoxKeyCoreImpl as BoxKeyCore>::verify_commitments(&comms, &pok)
                .expect("commits válidos");
            first_commitments.push(comms[0].clone());
            all_commitments.push(comms);
            encrypted.push(
                <BoxKeyCoreImpl as BoxKeyCore>::generate_shares(&configured, &pks).expect("shares"),
            );
        }

        let mut shares = Vec::new();
        for (sk, _pk) in &keys {
            let mut partials = Vec::new();
            for j in 0..n as usize {
                let mine = encrypted[j]
                    .iter()
                    .find(|e| e.recipient == pks[shares.len()])
                    .unwrap();
                let part = <BoxKeyCoreImpl as BoxKeyCore>::verify_and_decrypt_share(mine, sk)
                    .expect("descifra");
                dkg::verify_share(&part, &all_commitments[j]).expect("Feldman ok");
                partials.push(part);
            }
            let combined = dkg::combine_shares(&partials, t, &first_commitments).expect("combina");
            shares.push(combined);
        }

        let group = dkg::derive_public_key(&shares).expect("clave de grupo");
        assert_eq!(group, shares[0].group_public_key());
    }

    #[test]
    fn single_signer_frost_round_via_trait() {
        let (shares, _) = dkg::run_dkg(1, 1);
        let signer = &shares[0];
        let group = signer.group_public_key();
        let msg = [0x42u8; 32];

        let (hidden, comm) = <BoxKeyCoreImpl as BoxKeyCore>::generate_nonces(signer);
        assert_eq!(hidden.len(), 64);
        assert_eq!(comm.len(), 70);

        // El wrapper re-deriva los nonces del mensaje real; el commitment
        // publicado debe ser el ligado al mensaje (via API avanzada) para que
        // `frost::sign_partial` acepte el nonce match.
        let (_hidden_msg, comm_msg) = frost::generate_nonces(signer, &msg).unwrap();
        let sig = <BoxKeyCoreImpl as BoxKeyCore>::sign_partial(
            signer,
            &msg,
            std::slice::from_ref(&comm_msg),
        )
        .expect("firma parcial 1-de-1");
        assert!(
            <BoxKeyCoreImpl as BoxKeyCore>::verify_partial(
                &sig,
                &signer.partial_public_key(),
                &msg
            ),
            "la única clave es la del bloque (verify_partial fiable en round 1-de-1)"
        );

        let agg = <BoxKeyCoreImpl as BoxKeyCore>::aggregate_signatures(&[sig], &group, &msg)
            .expect("agrega");
        assert!(
            <BoxKeyCoreImpl as BoxKeyCore>::verify_schnorr(&agg, &group, &msg),
            "firma final verifica"
        );
    }

    #[test]
    fn generate_nonces_is_deterministic() {
        let (shares, _) = dkg::run_dkg(2, 2);
        let (hidden1, comm1) = <BoxKeyCoreImpl as BoxKeyCore>::generate_nonces(&shares[0]);
        let (hidden2, comm2) = <BoxKeyCoreImpl as BoxKeyCore>::generate_nonces(&shares[0]);
        assert_eq!(hidden1, hidden2);
        assert_eq!(comm1, comm2);
        assert_eq!(hidden1.len(), 64);
        assert_eq!(comm1.len(), 70);
    }

    #[test]
    fn reshare_via_trait_preserves_group_key() {
        let (old_shares, _) = dkg::run_dkg(3, 2);
        let (old_group, old_threshold) = {
            let s = &old_shares[0];
            (s.group_public_key(), s.threshold())
        };

        let new_pairs: Vec<(SecretKey, PublicKey)> =
            (0..4).map(|_| dkg::generate_participant_key()).collect();
        let new_pks: Vec<PublicKey> = new_pairs.iter().map(|(_, pk)| *pk).collect();
        let new_keys: Vec<&SecretKey> = new_pairs.iter().map(|(sk, _)| sk).collect();

        let mut contributions = Vec::new();
        for contributor in &old_shares[..old_threshold as usize] {
            let encs =
                <BoxKeyCoreImpl as BoxKeyCore>::reshare_begin(contributor, &new_pks, old_threshold)
                    .expect("redistribuye");
            for (idx, enc) in encs.iter().enumerate() {
                if contributions.len() <= idx {
                    contributions.push(vec![]);
                }
                contributions[idx].push(enc.clone());
            }
        }

        for (idx, new_key) in new_keys.iter().enumerate() {
            let mut terms = Vec::new();
            for (contrib_idx, enc) in contributions[idx].iter().enumerate() {
                let part =
                    <BoxKeyCoreImpl as BoxKeyCore>::reshare_accept(enc, new_key).expect("acepta");
                let contrib = &old_shares[contrib_idx];
                let set = vec![contrib.identifier()];
                reshare::verify_redistributed_share(
                    &part,
                    &contrib.full_public_key_point(),
                    &set,
                    contrib.identifier(),
                )
                .expect("término verifica");
                terms.push(part);
            }
            let new_share =
                reshare::combine_redistributed_shares(&terms, old_group).expect("combina");
            assert_eq!(new_share.group_public_key(), old_group);
            assert_eq!(new_share.identifier(), (idx as u32) + 1);
        }
    }

    #[test]
    fn default_nonce_msg_is_fixed() {
        assert_eq!(
            DEFAULT_NONCE_MSG,
            [
                0x62, 0x6f, 0x78, 0x6b, 0x65, 0x79, 0x2f, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
                0x2d, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x2d, 0x6d, 0x73, 0x67, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
    }
}
