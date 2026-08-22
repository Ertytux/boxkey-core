use std::collections::BTreeMap;

use frost_core::keys::KeyPackage;
use frost_core::round1::SigningCommitments;
use frost_core::round2::SignatureShare;
use frost_core::Identifier;
use frost_secp256k1_tr as frost;
use rand_core::{CryptoRng, RngCore};

use crate::error::Error;
use crate::secp256k1::{point_mul_base, scalar_from_canonical_or_zero, scalar_to_bytes, Fs};
use crate::types::{Commitment, PartialSignature, PublicKey, SchnorrSignature, Share};

fn scalar_to_signing_share(scalar: &Fs) -> frost_core::keys::SigningShare<frost::Secp256K1Sha256TR> {
    let bytes = scalar_to_bytes(scalar);
    frost_core::keys::SigningShare::deserialize(&bytes[..])
        .expect("scalar canónico es un SigningShare válido")
}

fn bc_id_to_frost(id: u32) -> Result<Identifier<frost::Secp256K1Sha256TR>, Error> {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&id.to_be_bytes());
    Identifier::deserialize(&bytes[..])
        .map_err(|e| Error::InvalidSignature(format!("id inválido: {e}")))
}

fn point_to_verifying_share(
    point_bytes: &[u8; 33],
) -> Result<frost_core::keys::VerifyingShare<frost::Secp256K1Sha256TR>, Error> {
    frost_core::keys::VerifyingShare::deserialize(&point_bytes[..])
        .map_err(|e| Error::InvalidPublicKey(format!("clave parcial inválida: {e}")))
}

fn xonly_to_verifying_key(
    xonly: &[u8; 32],
) -> Result<frost_core::VerifyingKey<frost::Secp256K1Sha256TR>, Error> {
    frost_core::VerifyingKey::deserialize(&xonly[..])
        .map_err(|e| Error::InvalidPublicKey(format!("clave inválida: {e}")))
}

fn bc_share_to_key_package(s: &Share) -> Result<KeyPackage<frost::Secp256K1Sha256TR>, Error> {
    let identifier = bc_id_to_frost(s.identifier())?;
    let scalar = scalar_from_canonical_or_zero(&s.value)
        .map_err(|_| Error::InvalidSecretKey("share inválida".into()))?;
    let signing_share = scalar_to_signing_share(&scalar);
    let point = point_mul_base(&scalar);
    let point_bytes = crate::secp256k1::point_to_bytes(&point);
    let verifying_share = point_to_verifying_share(&point_bytes)?;
    let group_pk = xonly_to_verifying_key(&s.group_public_key().0)?;
    let min_signers = s.threshold() as u16;
    Ok(KeyPackage::new(identifier, signing_share, verifying_share, group_pk, min_signers))
}

fn bc_commitment_to_frost(
    comm: &Commitment,
) -> Result<SigningCommitments<frost::Secp256K1Sha256TR>, Error> {
    if comm.0.len() != 70 {
        return Err(Error::InvalidSignature(format!(
            "commitment length {} != 70",
            comm.0.len()
        )));
    }
    let hiding_bytes: &[u8; 33] = &comm.0[4..37].try_into().map_err(|_| {
        Error::InvalidSignature("hiding commitment malformed".into())
    })?;
    let binding_bytes: &[u8; 33] = &comm.0[37..70].try_into().map_err(|_| {
        Error::InvalidSignature("binding commitment malformed".into())
    })?;
    let hiding = frost_core::round1::NonceCommitment::deserialize(&hiding_bytes[..])
        .map_err(|e| Error::InvalidSignature(format!("hiding commitment inválido: {e}")))?;
    let binding = frost_core::round1::NonceCommitment::deserialize(&binding_bytes[..])
        .map_err(|e| Error::InvalidSignature(format!("binding commitment inválido: {e}")))?;
    Ok(SigningCommitments::new(hiding, binding))
}

fn frost_comm_to_bc(id: u32, comm: &SigningCommitments<frost::Secp256K1Sha256TR>) -> Commitment {
    let mut bytes = Vec::with_capacity(70);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&comm.hiding().serialize().expect("serialización hiding"));
    bytes.extend_from_slice(&comm.binding().serialize().expect("serialización binding"));
    Commitment(bytes)
}

fn frost_sig_to_bc(sig: &frost_core::Signature<frost::Secp256K1Sha256TR>) -> SchnorrSignature {
    let bytes = sig.serialize().expect("serialización de firma");
    let arr: [u8; 64] = bytes.try_into().expect("firma de 64 bytes");
    SchnorrSignature(arr)
}

pub fn generate_nonces(
    share: &Share,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Vec<u8>, Commitment), Error> {
    let kp = bc_share_to_key_package(share)?;
    let (nonces, commitments) = frost_core::round1::commit(kp.signing_share(), rng);
    let hidden = nonces.serialize().expect("serialización de nonces");
    let id = share.identifier();
    let comm = frost_comm_to_bc(id, &commitments);
    Ok((hidden, comm))
}

pub fn sign_partial(
    share: &Share,
    message_hash: &[u8; 32],
    commitments: &[Commitment],
    hidden: &[u8],
) -> Result<PartialSignature, Error> {
    let kp = bc_share_to_key_package(share)?;
    let id = share.identifier();

    let mut comm_map = BTreeMap::new();
    for comm in commitments {
        if comm.0.len() < 4 {
            return Err(Error::InvalidSignature("commitment demasiado corto".into()));
        }
        let cid = u32::from_be_bytes(comm.0[..4].try_into().unwrap());
        let frost_cid = bc_id_to_frost(cid)?;
        let scomm = bc_commitment_to_frost(comm)?;
        comm_map.insert(frost_cid, scomm);
    }

    let nonces = frost_core::round1::SigningNonces::deserialize(hidden)
        .map_err(|e| Error::InvalidSignature(format!("nonces inválidos: {e}")))?;

    let signing_package = frost_core::SigningPackage::new(comm_map, message_hash);

    let sig_share = frost_core::round2::sign(&signing_package, &nonces, &kp)
        .map_err(|e| Error::InvalidSignature(format!("firma parcial falló: {e}")))?;

    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&sig_share.serialize());
    Ok(PartialSignature(out))
}

pub fn aggregate_signatures(
    sigs: &[PartialSignature],
    group_public_key: &PublicKey,
    message_hash: &[u8; 32],
    signing_commitments: &[Commitment],
) -> Result<SchnorrSignature, Error> {
    if sigs.is_empty() {
        return Err(Error::InvalidSignature("sin firmas parciales".into()));
    }

    let group_vk = xonly_to_verifying_key(&group_public_key.0)?;

    let mut sig_shares = BTreeMap::new();
    let mut comm_map = BTreeMap::new();
    for s in sigs {
        if s.0.len() != 36 {
            return Err(Error::InvalidSignature("firma parcial inválida".into()));
        }
        let id = u32::from_be_bytes(s.0[..4].try_into().unwrap());
        let frost_id = bc_id_to_frost(id)?;
        let sig_share = SignatureShare::deserialize(&s.0[4..36])
            .map_err(|e| Error::InvalidSignature(format!("sig share inválida: {e}")))?;
        sig_shares.insert(frost_id, sig_share);
    }

    for comm in signing_commitments {
        if comm.0.len() < 4 {
            return Err(Error::InvalidSignature("commitment demasiado corto".into()));
        }
        let cid = u32::from_be_bytes(comm.0[..4].try_into().unwrap());
        let frost_cid = bc_id_to_frost(cid)?;
        let scomm = bc_commitment_to_frost(comm)?;
        comm_map.insert(frost_cid, scomm);
    }

    let signing_package = frost_core::SigningPackage::new(comm_map, message_hash);

    let pubkey_package = frost_core::keys::PublicKeyPackage::new(
        BTreeMap::new(),
        group_vk,
        Some(sigs.len() as u16),
    );

    let frost_sig = frost_core::aggregate(&signing_package, &sig_shares, &pubkey_package)
        .map_err(|e| Error::InvalidSignature(format!("agregación falló: {e}")))?;

    Ok(frost_sig_to_bc(&frost_sig))
}

pub fn verify_schnorr(
    sig: &SchnorrSignature,
    group_public_key: &PublicKey,
    message_hash: &[u8; 32],
) -> Result<(), Error> {
    use k256::schnorr::VerifyingKey;

    let vk = VerifyingKey::from_bytes(&group_public_key.0)
        .map_err(|e| Error::InvalidPublicKey(format!("clave inválida: {e}")))?;
    let sig_obj = k256::schnorr::Signature::try_from(sig.0.as_slice())
        .map_err(|e| Error::invalid_signature(format!("firma inválida: {e}")))?;
    vk.verify_raw(message_hash, &sig_obj)
        .map_err(|e| Error::invalid_signature(format!("verificación falló: {e}")))?;
    Ok(())
}