use rand::rngs::OsRng;

use crate::dkg;
use crate::error::Error;
use crate::frost_adapter;
use crate::reshare;
use crate::types::{
    Commitment, EncryptedShare, PartialSignature, PublicKey, SchnorrSignature, SecretKey,
    SecretShare, Share,
};

pub trait BoxKeyCore {
    fn generate_secret() -> SecretShare;

    fn compute_commitments(
        share: &SecretShare,
        threshold: u8,
        total_participants: u8,
    ) -> Vec<Commitment>;

    fn verify_commitments(
        commitments: &[Commitment],
        proof_of_knowledge: &[u8],
    ) -> Result<(), Error>;

    fn generate_shares(
        secret: &SecretShare,
        participants: &[PublicKey],
    ) -> Result<Vec<EncryptedShare>, Error>;

    fn verify_and_decrypt_share(
        encrypted: &EncryptedShare,
        my_key: &SecretKey,
    ) -> Result<Share, Error>;

    fn derive_public_key(shares: &[Share]) -> Result<PublicKey, Error>;

    fn derive_partial_public_key(share: &Share) -> PublicKey;

    fn generate_nonces(share: &Share) -> (Vec<u8>, Commitment);

    fn sign_partial(
        share: &Share,
        message_hash: &[u8; 32],
        commitments: &[Commitment],
    ) -> Result<PartialSignature, Error>;

    fn aggregate_signatures(
        sigs: &[PartialSignature],
        pubkey: &PublicKey,
        message_hash: &[u8; 32],
    ) -> Result<SchnorrSignature, Error>;

    fn verify_schnorr(sig: &SchnorrSignature, pubkey: &PublicKey, message_hash: &[u8; 32]) -> bool;

    fn reshare_begin(
        old_share: &Share,
        new_participants: &[PublicKey],
        new_threshold: u8,
    ) -> Result<Vec<EncryptedShare>, Error>;

    fn reshare_accept(encrypted: &EncryptedShare, my_new_key: &SecretKey) -> Result<Share, Error>;
}

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

    fn generate_nonces(share: &Share) -> (Vec<u8>, Commitment) {
        let mut rng = OsRng;
        match frost_adapter::generate_nonces(share, &mut rng) {
            Ok((hidden, commitment)) => (hidden, commitment),
            Err(_) => (Vec::new(), Commitment(Vec::new())),
        }
    }

    fn sign_partial(
        share: &Share,
        message_hash: &[u8; 32],
        commitments: &[Commitment],
    ) -> Result<PartialSignature, Error> {
        let mut rng = OsRng;
        let (hidden, own_comm) = frost_adapter::generate_nonces(share, &mut rng)?;

        let mut adjusted = commitments.to_vec();
        if let Some(pos) = adjusted.iter().position(|c| {
            c.0.len() >= 4 && u32::from_be_bytes(c.0[..4].try_into().unwrap()) == share.identifier()
        }) {
            adjusted[pos] = own_comm;
        }

        frost_adapter::sign_partial(share, message_hash, &adjusted, &hidden)
    }

    fn aggregate_signatures(
        sigs: &[PartialSignature],
        pubkey: &PublicKey,
        message_hash: &[u8; 32],
    ) -> Result<SchnorrSignature, Error> {
        frost_adapter::aggregate_signatures(sigs, pubkey, message_hash)
    }

    fn verify_schnorr(sig: &SchnorrSignature, pubkey: &PublicKey, message_hash: &[u8; 32]) -> bool {
        frost_adapter::verify_schnorr(sig, pubkey, message_hash).is_ok()
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

const DEFAULT_NONCE_MSG: [u8; 32] = [0u8; 32];

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
            let combined =
                dkg::combine_shares(&partials, t, &first_commitments).expect("combina");
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
        assert!(comm.0.len() >= 70);

        let sig = <BoxKeyCoreImpl as BoxKeyCore>::sign_partial(
            signer,
            &msg,
            std::slice::from_ref(&comm),
        )
        .expect("firma parcial 1-de-1");

        let agg = <BoxKeyCoreImpl as BoxKeyCore>::aggregate_signatures(
            &[sig],
            &group,
            &msg,
        )
        .expect("agrega");
        assert!(
            <BoxKeyCoreImpl as BoxKeyCore>::verify_schnorr(&agg, &group, &msg),
            "firma final verifica"
        );
        let _ = hidden;

        let sig = <BoxKeyCoreImpl as BoxKeyCore>::sign_partial(
            signer,
            &msg,
            std::slice::from_ref(&comm),
        )
        .expect("firma parcial 1-de-1");

        let agg = <BoxKeyCoreImpl as BoxKeyCore>::aggregate_signatures(
            &[sig],
            &group,
            &msg,
        )
        .expect("agrega");
        assert!(
            <BoxKeyCoreImpl as BoxKeyCore>::verify_schnorr(&agg, &group, &msg),
            "firma final verifica"
        );
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
}