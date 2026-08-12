//! Capa de aritmética de curva `secp256k1`.
//!
//! BC opera sobre la curva `secp256k1`. La aritmética de cuerpo/curva (sumas,
//! multiplicaciones, inversión, multiplicación por base) está implementada
//! sobre `k256` de RustCrypto (implementación auditada de `secp256k1`), ya que
//! `rust-secp256k1` no expone aritmética de escalares pública.
//!
//! `rust-secp256k1` se utiliza como oráculo independiente en las pruebas
//! (`tests/`) y en [`crate::schnorr::verify_bip340_external`] para verificar
//! firmas BIP340 de forma cruzada.
//!
//! Este módulo solo expone primitivas; no contiene lógica de negocio.

use k256::elliptic_curve::{
    rand_core::{CryptoRngCore, OsRng},
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Field, Group, PrimeField,
};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, InvalidCommitment};

/// Alias interno del escalar de cuerpo de `secp256k1`.
pub(crate) type Fs = k256::Scalar;

/// Alias interno del punto proyectivo de `secp256k1`.
pub(crate) type Gx = k256::ProjectivePoint;

/// Tamaño de un punto comprimido (SEC1 33 bytes).
pub(crate) const POINT_LEN: usize = 33;
/// Orden de la curva (constante para validación).
pub(crate) const ORDER: &[u8; 32] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Genera un escalar aleatorio uniforme en `[1, n-1]`.
pub(crate) fn scalar_random(rng: &mut impl CryptoRngCore) -> Fs {
    loop {
        let s = Scalar::random(&mut *rng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Escalar aleatorio para claves secretas de participantes.
pub(crate) fn secret_key_random() -> Fs {
    scalar_random(&mut OsRng)
}

/// Interpreta 32 bytes canónicos como escalar, rechazando valores `>= n` o `0`.
pub(crate) fn scalar_from_canonical(bytes: &[u8; 32]) -> Result<Fs, Error> {
    let s = Scalar::from_repr((*bytes).into())
        .into_option()
        .ok_or_else(|| Error::InvalidScalar("bytes fuera del dominio [1, n-1]".into()))?;
    if bool::from(s.is_zero()) {
        return Err(Error::InvalidScalar("escalar cero no permitido".into()));
    }
    Ok(s)
}

/// Interpreta bytes canónicos sin exigir que sean no nulos.
pub(crate) fn scalar_from_canonical_or_zero(bytes: &[u8; 32]) -> Result<Fs, Error> {
    Scalar::from_repr((*bytes).into())
        .into_option()
        .ok_or_else(|| Error::InvalidScalar("bytes fuera del dominio de la curva".into()))
}

/// Reduce un digest de 32 bytes a un escalar mediante rejection sampling
/// (buscando la primera representación canónica en `[1, n-1]`).
pub(crate) fn scalar_from_hash(material: &[u8]) -> Fs {
    let mut h = Sha256::new();
    h.update(material);
    for counter in 0u32..=u32::MAX {
        let mut ctx = h.clone();
        ctx.update(counter.to_be_bytes());
        let digest: [u8; 32] = ctx.finalize().into();
        if let Ok(s) = scalar_from_canonical_or_zero(&digest) {
            if !bool::from(s.is_zero()) {
                return s;
            }
        }
    }
    unreachable!("rejection sampling agotado")
}

/// Serializa un escalar a sus 32 bytes canónicos.
pub(crate) fn scalar_to_bytes(s: &Fs) -> [u8; 32] {
    s.to_bytes().into()
}

/// Multiplicación por el generador de la curva.
pub(crate) fn point_mul_base(s: &Fs) -> Gx {
    ProjectivePoint::GENERATOR * s
}

/// Serializa un punto como SEC1 comprimido (33 bytes). El punto en el
/// infinito devuelve `[0u8; 33]`.
pub(crate) fn point_to_bytes(p: &Gx) -> [u8; POINT_LEN] {
    if point_is_zero(p) {
        return [0u8; POINT_LEN];
    }
    let enc = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; POINT_LEN];
    out.copy_from_slice(enc.as_bytes());
    out
}

/// Deserializa un punto SEC1 comprimido (33 bytes), fallando si no es válido.
pub(crate) fn point_from_bytes(bytes: &[u8; POINT_LEN]) -> Result<Gx, Error> {
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "prefijo fuera de SEC1 comprimido".into(),
        )));
    }
    let enc = EncodedPoint::from_bytes(bytes.as_slice())
        .map_err(|e| Error::InvalidCommitment(InvalidCommitment(format!("SEC1 inválido: {e}"))))?;
    let pt = AffinePoint::from_encoded_point(&enc);
    if bool::from(pt.is_none()) {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "punto fuera de la curva".into(),
        )));
    }
    Ok(ProjectivePoint::from(pt.unwrap()))
}

/// Extrae la coordenada X (x-only) de un punto. El punto en el infinito
/// devuelve `[0u8; 32]`.
pub(crate) fn point_x_bytes(p: &Gx) -> [u8; 32] {
    if point_is_zero(p) {
        return [0u8; 32];
    }
    p.to_affine().to_encoded_point(true).as_bytes()[1..33]
        .try_into()
        .expect("len 32")
}

/// Indica si la coordenada Y del punto es par (convención BIP340). El punto
/// en el infinito devuelve `false`.
pub(crate) fn point_has_even_y(p: &Gx) -> bool {
    if point_is_zero(p) {
        return false;
    }
    p.to_affine().to_encoded_point(true).as_bytes()[0] == 0x02
}

/// Indica si el punto es el punto en el infinito.
pub(crate) fn point_is_zero(p: &Gx) -> bool {
    bool::from(p.is_identity())
}

/// Normaliza un escalar a la representación even-y: si `s·G` tiene Y impar
/// devuelve `(-s)` junto a `true` (fue negado).
pub(crate) fn even_normalize_scalar(s: Fs) -> (Fs, bool) {
    let pt = point_mul_base(&s);
    if point_has_even_y(&pt) {
        (s, false)
    } else {
        (-s, true)
    }
}

/// Punto x-only del público de una clave secreta escalar.
pub(crate) fn public_x_bytes(secret: &Fs) -> [u8; 32] {
    point_x_bytes(&point_mul_base(secret))
}

/// Argumento secreto compartido ECDH entre `my_priv` y el punto público ajeno.
///
/// El secreto compartido depende solo de la coordenada X (la negación de Y no
/// lo altera), de modo que las claves públicas x-only (BIP340) son suficientes.
pub(crate) fn ecdh_shared_x(my_priv: &Fs, peer_pub: &Gx) -> Zeroizing<[u8; 32]> {
    let shared = *peer_pub * my_priv;
    let x = point_x_bytes(&shared);
    let mut h = Sha256::new();
    h.update(b"boxkey-core/ecdh-v1");
    h.update(x);
    Zeroizing::new(h.finalize().into())
}

/// Hash etiquetado BIP340 estándar: `SHA256(SHA256(tag) || SHA256(tag) || preimage)`.
pub(crate) fn tagged_hash(tag: &[u8], preimage: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    let tag_hash = h.finalize();
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(preimage);
    h.finalize().into()
}

fn be_cmp(a: &[u8; 32], b: &[u8; 32]) -> core::cmp::Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        match x.cmp(y) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    core::cmp::Ordering::Equal
}

fn be_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = false;
    for i in (0..32).rev() {
        let sub = if borrow {
            (a[i] as i16) - (b[i] as i16) - 1
        } else {
            (a[i] as i16) - (b[i] as i16)
        };
        if sub < 0 {
            out[i] = (sub + 256) as u8;
            borrow = true;
        } else {
            out[i] = sub as u8;
            borrow = false;
        }
    }
    out
}

/// Reduce `int(digest) mod n` (basta una sustracción: `digest < 2n`).
pub(crate) fn scalar_reduce_mod_n(digest: &[u8; 32]) -> Fs {
    match be_cmp(digest, ORDER) {
        core::cmp::Ordering::Less => scalar_from_canonical_or_zero(digest).expect("en dominio"),
        core::cmp::Ordering::Equal => Fs::ZERO,
        core::cmp::Ordering::Greater => {
            let reduced = be_sub(digest, ORDER);
            scalar_from_canonical_or_zero(&reduced).expect("menor que n")
        }
    }
}
