use k256::schnorr::VerifyingKey;
use k256::schnorr::Signature;

use crate::error::Error;
use crate::secp256k1::{scalar_to_bytes, Fs};

pub fn verify_bip340(sig: &[u8; 64], pk_x: &[u8; 32], msg: &[u8; 32]) -> Result<(), Error> {
    let vk = VerifyingKey::from_bytes(pk_x)
        .map_err(|e| Error::invalid_signature(format!("clave inválida: {e}")))?;
    let sig_obj = Signature::try_from(sig.as_slice())
        .map_err(|e| Error::invalid_signature(format!("firma inválida: {e}")))?;
    vk.verify_raw(msg, &sig_obj)
        .map_err(|e| Error::invalid_signature(format!("verificación falló: {e}")))?;
    Ok(())
}

pub(crate) fn schnorr_sign(secret: &Fs, msg: &[u8; 32]) -> [u8; 64] {
    let sk_bytes = scalar_to_bytes(secret);
    let signing_key = k256::schnorr::SigningKey::from_bytes(&sk_bytes)
        .expect("escalar canónico es una clave válida");
    let sig = signing_key.sign_raw(msg, &[0u8; 32])
        .expect("firma BIP340 raw");
    sig.to_bytes()
}

pub(crate) fn schnorr_sign_bytes(secret: &[u8; 32], msg: &[u8; 32]) -> Result<[u8; 64], Error> {
    let signing_key = k256::schnorr::SigningKey::from_bytes(secret)
        .map_err(|e| Error::invalid_signature(format!("clave inválida: {e}")))?;
    let sig = signing_key.sign_raw(msg, &[0u8; 32])
        .map_err(|e| Error::invalid_signature(format!("firma falló: {e}")))?;
    Ok(sig.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip340_verifies_own_signature() {
        use k256::schnorr::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let msg = [7u8; 32];
        let sig = signing_key.sign_raw(&msg, &[0u8; 32]).unwrap();
        let sig_bytes = sig.to_bytes();
        let pk_bytes = verifying_key.to_bytes();
        let pk_arr: [u8; 32] = pk_bytes.into();
        verify_bip340(&sig_bytes, &pk_arr, &msg).expect("verifica con k256::schnorr");
    }

    #[test]
    fn bip340_rejects_tampered() {
        use k256::schnorr::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let msg = [7u8; 32];
        let sig = signing_key.sign_raw(&msg, &[0u8; 32]).unwrap();
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 1;
        let pk_bytes = verifying_key.to_bytes();
        let pk_arr: [u8; 32] = pk_bytes.into();
        assert!(verify_bip340(&sig_bytes, &pk_arr, &msg).is_err());
    }
}