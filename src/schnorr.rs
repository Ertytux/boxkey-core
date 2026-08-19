//! Schnorr BIP340 sobre `secp256k1`.
//!
//! Implementa firma y verificación Schnorr compatibles con [BIP340], siguiendo
//! la convención x-only / even-y del estándar. La verificación funciona sobre
//! los primitivos de `k256` y se contrasta de forma cruzada con la verificación
//! independiente de `rust-secp256k1` (oráculo externo).
//!
//! [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

use core::cmp::Ordering;

use k256::Scalar;

use crate::error::Error;
use crate::secp256k1::{
    point_from_bytes, point_has_even_y, point_is_zero, point_mul_base, point_x_bytes,
    scalar_from_canonical, scalar_reduce_mod_n, scalar_to_bytes, Fs, Gx,
};

/// Curva `p = 2^256 - 2^32 - 977` (byte-be).
const FIELD_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

fn be_cmp(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        match x.cmp(y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// "Levanta" la coordenada x con Y par (BIP340 `lift_x`).
fn lift_even(x_bytes: &[u8; 32]) -> Result<Gx, Error> {
    let mut enc = [0u8; 33];
    enc[0] = 0x02;
    enc[1..].copy_from_slice(x_bytes);
    point_from_bytes(&enc)
}

/// Firma Schnorr BIP340 determinística de un único escalar secreto.
///
/// Usada para las pruebas de conocimiento (PoK) del DKG y para APIs de firma
/// individual. El nonce se deriva de forma determinista del secreto y el
/// mensaje (variante determinística del estándar).
pub(crate) fn schnorr_sign(secret: &Fs, msg: &[u8; 32]) -> [u8; 64] {
    let pk_x = crate::secp256k1::public_x_bytes(secret);
    // BIP340: la clave de firma debe tener Y par (lift_x del verificador).
    // Si `secret·G` es impar, se firma con `-secret` (misma coordenada X).
    let secret_eff = crate::secp256k1::even_normalize_scalar(*secret).0;
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&scalar_to_bytes(&secret_eff));
    preimage.extend_from_slice(&pk_x);
    preimage.extend_from_slice(msg);

    let mut k = crate::secp256k1::scalar_from_hash(&preimage);
    loop {
        let n = crate::secp256k1::even_normalize_scalar(k).0;
        let rk = point_mul_base(&n);
        let r = point_x_bytes(&rk);

        let mut chal_pre = Vec::with_capacity(96);
        chal_pre.extend_from_slice(&r);
        chal_pre.extend_from_slice(&pk_x);
        chal_pre.extend_from_slice(msg);
        let digest = crate::secp256k1::tagged_hash(b"BIP0340/challenge", &chal_pre);
        let e = scalar_reduce_mod_n(&digest);

        let s = n + e * secret_eff;
        let sbytes = scalar_to_bytes(&s);
        if be_cmp(&sbytes, crate::secp256k1::ORDER) == Ordering::Greater {
            // s >= n inválido; nonce fallback raro (prob. nula)
            let mut retry = preimage.clone();
            retry.extend_from_slice(b":retry");
            k = crate::secp256k1::scalar_from_hash(&retry);
            continue;
        }
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&sbytes);
        return out;
    }
}

/// Firma Schnorr BIP340 determinística de un escalar secreto en bytes.
///
/// Wrapper sobre [`schnorr_sign`] para las APIs que operan con el material
/// secreto como `[u8; 32]` (p. ej. la firma de envelopes en `serialize`).
pub(crate) fn schnorr_sign_bytes(secret: &[u8; 32], msg: &[u8; 32]) -> Result<[u8; 64], Error> {
    let s = scalar_from_canonical(secret)?;
    Ok(schnorr_sign(&s, msg))
}

/// Verifica una firma Schnorr BIP340 frente a una clave pública x-only.
///
/// Implementa el algoritmo `Verify(pk, m, sig)` de BIP340 paso a paso.
pub(crate) fn verify_bip340(sig: &[u8; 64], pk_x: &[u8; 32], msg: &[u8; 32]) -> Result<(), Error> {
    let r = &sig[..32];
    let s = &sig[32..];

    let sr = <[u8; 32]>::try_from(r).expect("slice de 32");
    let ss = <[u8; 32]>::try_from(s).expect("slice de 32");

    if be_cmp(&sr, &FIELD_P) != Ordering::Less {
        return Err(Error::invalid_signature("r >= p"));
    }
    if be_cmp(&ss, crate::secp256k1::ORDER) != Ordering::Less {
        return Err(Error::invalid_signature("s >= n"));
    }

    let p = lift_even(pk_x)?;

    let mut chal_pre = Vec::with_capacity(96);
    chal_pre.extend_from_slice(r);
    chal_pre.extend_from_slice(pk_x);
    chal_pre.extend_from_slice(msg);
    let digest = crate::secp256k1::tagged_hash(b"BIP0340/challenge", &chal_pre);
    let e = scalar_reduce_mod_n(&digest);

    let s_scalar = scalar_from_canonical(&ss)?;
    let rs = point_mul_base(&s_scalar) + p * (Scalar::ZERO - e);

    if point_is_zero(&rs) {
        return Err(Error::invalid_signature("punto R en el infinito"));
    }
    if !point_has_even_y(&rs) {
        return Err(Error::invalid_signature("R no tiene Y par"));
    }
    if point_x_bytes(&rs) != *r {
        return Err(Error::invalid_signature("x(R) != r"));
    }
    Ok(())
}

/// Verifica una firma Schnorr BIP340 usando `rust-secp256k1` (oráculo externo
/// independiente de `k256`).
#[allow(dead_code)]
pub(crate) fn verify_bip340_external(
    sig: &[u8; 64],
    pk_x: &[u8; 32],
    msg: &[u8; 32],
) -> Result<(), Error> {
    use secp256k1::schnorr::Signature;
    use secp256k1::XOnlyPublicKey;

    let secp = secp256k1::Secp256k1::verification_only();
    // La firma BIP340 se construye como (R.bytes || s.bytes) en ambos motores.
    let parsed = Signature::from_byte_array(*sig);
    let pk = XOnlyPublicKey::from_byte_array(*pk_x)
        .map_err(|e| Error::invalid_signature(format!("rust-secp256k1 pk: {e}")))?;
    secp.verify_schnorr(&parsed, msg, &pk)
        .map_err(|e| Error::invalid_signature(format!("rust-secp256k1 verify: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::{point_mul_base, point_x_bytes};

    #[test]
    fn bip340_verifies_own_signature() {
        let sk = crate::secp256k1::secret_key_random();
        let pk = point_x_bytes(&point_mul_base(&sk));
        let msg = [7u8; 32];
        let sig = schnorr_sign(&sk, &msg);
        verify_bip340(&sig, &pk, &msg).expect("verifica con motor k256");
        verify_bip340_external(&sig, &pk, &msg).expect("verifica con rust-secp256k1");
    }

    #[test]
    fn bip340_rejects_tampered() {
        let sk = crate::secp256k1::secret_key_random();
        let pk = point_x_bytes(&point_mul_base(&sk));
        let msg = [7u8; 32];
        let sig = schnorr_sign(&sk, &msg);
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(verify_bip340(&bad, &pk, &msg).is_err());
        bad = sig;
        bad[63] ^= 1;
        assert!(verify_bip340_external(&bad, &pk, &msg).is_err());
    }
}
