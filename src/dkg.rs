//! DKG — Generación Distribuida de Claves para FROST.
//!
//! Protocolo de dos rondas (Gennaro/Feldman VSS adaptado a Schnorr BIP340):
//!
//! **Ronda 1** — cada participante crea un polinomio local aleatorio con
//! [`generate_secret`], fija el umbral con [`secret_with_threshold`], publica
//! los compromisos de Feldman ([`compute_commitments`]) y una prueba de
//! conocimiento del coeficiente libre ([`generate_proof_of_knowledge`]).
//!
//! **Ronda 2** — tras validar rondas ajenas ([`verify_commitments`]), cada
//! participante cifra la evaluación del polinomio para cada destinatario
//! ([`generate_shares`]) usando ECDH sobre `secp256k1`.
//!
//! **Recepción** — cada destinatario descifra ([`verify_and_decrypt_share`]),
//! aplica el chequeo de Feldman ([`verify_share`]) y combina contribuciones
//! ([`combine_shares`]) en su share final del BoxKey.
//!
//! La clave pública del BoxKey surge de la suma de compromisos `c_j[0]` (y es
//! independiente verificable con [`derive_public_key`] vía interpolación).
//!
//! Convención BIP340: si la clave de grupo (suma `c_j[0]`) tiene Y impar, los
//! shares combinados se niegan, de modo que el secreto de firma resultante es
//! even-y (idéntica coordenada X pública). Ver `rfc.md §3` y `BZ.md Anexo A`.

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use k256::elliptic_curve::Group as _;

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, InvalidCommitment};
use crate::schnorr::{schnorr_sign, verify_bip340};
use crate::secp256k1::{
    ecdh_shared_x, point_from_bytes, point_has_even_y, point_mul_base, point_to_bytes,
    point_x_bytes, scalar_from_canonical, scalar_from_canonical_or_zero, scalar_random,
    scalar_to_bytes, Fs, Gx,
};
use crate::types::{Commitment, EncryptedShare, PublicKey, SecretKey, SecretShare, Share};

/// Grado máximo del polinomio local (umbral máximo soportado).
pub(crate) const MAX_DEGREE: usize = 255;

/// Coeficientes `[a_0, a_1, ...]` de un `SecretShare`, limitados al umbral.
///
/// El protocolo usa polinomio de grado `threshold - 1`, por lo que solo los
/// primeros `threshold` coeficientes participan en evaluaciones y compromisos.
fn coefficients(share: &SecretShare) -> Result<Vec<Fs>, Error> {
    let t = usize::from(share.threshold);
    if t == 0 {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "umbral no configurado (usa secret_with_threshold)".into(),
        )));
    }
    let chunks = share.coefficients.chunks_exact(32);
    let all: Vec<&[u8]> = chunks.collect();
    if all.len() < t {
        return Err(Error::InvalidCommitment(InvalidCommitment(format!(
            "el polinomio ({}) es menor que el umbral ({t})",
            all.len()
        ))));
    }
    let mut out = Vec::with_capacity(t);
    for c in &all[..t] {
        let arr: [u8; 32] = (*c).try_into().expect("chunk de 32");
        out.push(scalar_from_canonical(&arr).map_err(|_| {
            Error::InvalidCommitment(InvalidCommitment("coeficiente inválido".into()))
        })?);
    }
    Ok(out)
}

/// Serializa `t` coeficientes en un `SecretShare`.
fn share_from_coefficients(coeffs: &[Fs], threshold: u8, total: u8) -> SecretShare {
    let mut bytes = Vec::with_capacity(coeffs.len() * 32);
    for c in coeffs {
        bytes.extend_from_slice(&scalar_to_bytes(c));
    }
    SecretShare {
        coefficients: Zeroizing::new(bytes),
        threshold,
        total_participants: total,
    }
}

/// Genera un secreto local para el DKG: polinomio aleatorio de grado
/// [`MAX_DEGREE`] con umbral "sin configurar" (`threshold = 0`).
///
/// El umbral (`threshold`) y el total de participantes (`total_participants`)
/// se fijan después con [`secret_with_threshold`] antes de cualquier uso.
pub fn generate_secret() -> SecretShare {
    let coeffs: Vec<Fs> = (0..=MAX_DEGREE)
        .map(|_| scalar_random(&mut OsRng))
        .collect();
    share_from_coefficients(&coeffs, 0, 0)
}

/// Fija el umbral `t` y el total `n` de un secreto local del DKG.
///
/// Requiere `1 <= threshold <= degree` y `threshold <= total_participants`.
/// Unifica la API pura de `contratos.md §2` (`generate_secret` sin parámetros)
/// con la configuración que `compute_commitments` y `generate_shares` precisan.
pub fn secret_with_threshold(
    secret: &SecretShare,
    threshold: u8,
    total_participants: u8,
) -> Result<SecretShare, Error> {
    let t = usize::from(threshold);
    let n = usize::from(total_participants);
    let degree = secret.coefficients.len() / 32;
    if t == 0 {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "threshold debe ser >= 1".into(),
        )));
    }
    if t > degree {
        return Err(Error::InvalidCommitment(InvalidCommitment(format!(
            "threshold ({t}) excede el grado del polinomio ({degree})"
        ))));
    }
    if n < t {
        return Err(Error::InvalidCommitment(InvalidCommitment(format!(
            "total_participants ({n}) menor que threshold ({t})"
        ))));
    }
    Ok(SecretShare {
        coefficients: secret.coefficients.clone(),
        threshold,
        total_participants,
    })
}

/// Evalúa el polinomio local de `share` en `x` (Horner, módulo `n`).
fn evaluate(share: &SecretShare, x: Fs) -> Fs {
    let coeffs = coefficients(share).expect("umbral configurado en generate_shares");
    let mut acc = Fs::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Compromisos de Feldman del polinomio: `c_j = a_j·G` para `j in [0, t)`.
pub fn compute_commitments(share: &SecretShare) -> Vec<Commitment> {
    let coeffs = match coefficients(share) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    coeffs
        .iter()
        .map(|c| Commitment(point_to_bytes(&point_mul_base(c)).to_vec()))
        .collect()
}

/// Mensaje de la prueba de conocimiento: etiqueta domain-separada sobre los
/// compromisos publicados (vincula la prueba a la lista exacta de `c_j`).
fn pok_message(commitments: &[Commitment]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"boxkey-core/pose-possession-v1");
    for c in commitments {
        h.update(&c.0);
    }
    h.finalize().into()
}

/// Genera la prueba de conocimiento del coeficiente libre `a_0`: una firma
/// Schnorr BIP340 determinística sobre `pok_message(commitments)`.
pub fn generate_proof_of_knowledge(share: &SecretShare) -> Vec<u8> {
    let commitments = compute_commitments(share);
    let coeffs = coefficients(share).expect("umbral configurado");
    let a0 = &coeffs[0];
    let msg = pok_message(&commitments);
    schnorr_sign(a0, &msg).to_vec()
}

/// Valida los compromisos recibidos de un participante:
/// 1. Cada compromiso es un punto SEC1 comprimido válido sobre la curva.
/// 2. La prueba de conocimiento certifica que el emisor conoce `a_0`.
pub fn verify_commitments(
    commitments: &[Commitment],
    proof_of_knowledge: &[u8],
) -> Result<(), Error> {
    if commitments.is_empty() {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "sin compromisos".into(),
        )));
    }
    for c in commitments {
        if c.0.len() != 33 {
            return Err(Error::InvalidCommitment(InvalidCommitment(format!(
                "longitud {} != 33",
                c.0.len()
            ))));
        }
        let bytes: [u8; 33] = c.0.as_slice().try_into().expect("len 33");
        point_from_bytes(&bytes)?;
    }
    let pok: [u8; 64] = proof_of_knowledge
        .try_into()
        .map_err(|_| Error::InvalidProofOfKnowledge)?;
    let pk_x = point_x_bytes(&point_from_bytes(
        &commitments[0].0.as_slice().try_into().expect("len 33"),
    )?);
    let msg = pok_message(commitments);
    verify_bip340(&pok, &pk_x, &msg).map_err(|e| match e {
        Error::InvalidSignature(_) => Error::InvalidProofOfKnowledge,
        other => other,
    })
}

/// Punto de clave pública x-only (lift con Y par), BIP340.
pub(crate) fn lift_xonly(pk: &PublicKey) -> Result<Gx, Error> {
    let mut enc = [0u8; 33];
    enc[0] = 0x02;
    enc[1..].copy_from_slice(&pk.0);
    point_from_bytes(&enc)
}

/// Escalar del identificador de participante `1..=n` (big-endian de 32 bytes).
pub(crate) fn index_scalar(identifier: u32) -> Fs {
    let mut bytes = [0u8; 32];
    bytes[28] = (identifier >> 24) as u8;
    bytes[29] = (identifier >> 16) as u8;
    bytes[30] = (identifier >> 8) as u8;
    bytes[31] = identifier as u8;
    scalar_from_canonical(&bytes).expect("identificador de participante válido")
}

/// Cifra un payload arbitrario end-to-end hacia una clave pública x-only.
///
/// Formato: `ephemeral_pubkey(33) || nonce(12) || ct(tag incluido)` con
/// ChaCha20-Poly1305; el nonce deriva del secreto compartido ECDH (único por
/// par emisor→receptor y por ronda). El BS (coordinador) nunca puede leer el
/// contenido.
pub fn encrypt_payload(payload: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, Error> {
    let eph = scalar_random(&mut OsRng);
    let eph_pub = point_mul_base(&eph);
    let point = lift_xonly(recipient)?;
    let key = ecdh_shared_x(&eph, &point);

    let nonce = GenericArray::from_slice(&key[..12]);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]));
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: payload,
                aad: &[],
            },
        )
        .map_err(|_| Error::Crypto("ChaCha20-Poly1305: cifrado".into()))?;

    let mut out = Vec::with_capacity(33 + 12 + ct.len());
    out.extend_from_slice(&point_to_bytes(&eph_pub));
    out.extend_from_slice(&key[..12]);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Descifra un payload (`ephemeral_pubkey(33) || nonce(12) || ct`) hacia una
/// clave secreta. Valida la firma AEAD (tag) y devuelve los bytes planos.
pub fn decrypt_payload(ciphertext: &[u8], my_key: &SecretKey) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 33 + 12 + 16 {
        return Err(Error::InvalidShare("payload AEAD demasiado corto".into()));
    }
    let eph = point_from_bytes(&ciphertext[..33].try_into().expect("len 33"))?;
    let nonce = &ciphertext[33..33 + 12];
    let ct = &ciphertext[33 + 12..];

    let my_scalar = scalar_from_canonical(&my_key.0)
        .map_err(|_| Error::InvalidSecretKey("clave privada fuera de rango".into()))?;
    let key = ecdh_shared_x(&my_scalar, &eph);

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]));
    cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload { msg: ct, aad: &[] },
        )
        .map_err(|_| Error::InvalidShare("descifrado AEAD fallido".into()))
}

/// Coeficiente de Lagrange del índice `j` del conjunto `set` evaluado en el
/// punto `point` (identificadores): `∏_{k≠j} (point − k)/(j − k)`.
pub(crate) fn lagrange_coeff(point: u32, set: &[u32], j: u32) -> Fs {
    let x = index_scalar(point);
    let mut num = Fs::ONE;
    let mut den = Fs::ONE;
    for k in set {
        if *k != j {
            let xk = index_scalar(*k);
            num *= x - xk;
            den *= index_scalar(j) - xk;
        }
    }
    num * den.invert().unwrap()
}

/// Ronda 2: cifra para cada destinatario la evaluación `f_j(identifier)`.
///
/// El payload cifrado es `identifier(4 BE) || threshold(1) || f(32)` y su
/// envoltura `ciphertext = ephemeral_pubkey(33) || nonce(12) || ct`. El nonce
/// deriva del secreto compartido ECDH (determinístico, único por par emisor →
/// receptor y por ronda).
pub fn generate_shares(
    secret: &SecretShare,
    participants: &[PublicKey],
) -> Result<Vec<EncryptedShare>, Error> {
    let t = usize::from(secret.threshold);
    if t == 0 {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "umbral no configurado (usa secret_with_threshold)".into(),
        )));
    }
    let n = participants.len();
    if n < t {
        return Err(Error::InvalidCommitment(InvalidCommitment(format!(
            "participantes ({n}) < threshold ({t})"
        ))));
    }

    let mut out = Vec::with_capacity(n);
    for (idx, recipient) in participants.iter().enumerate() {
        let identifier = (idx as u32) + 1;

        let f = evaluate(secret, index_scalar(identifier));
        let mut plain = Vec::with_capacity(37);
        plain.extend_from_slice(&identifier.to_be_bytes());
        plain.push(secret.threshold);
        plain.extend_from_slice(&scalar_to_bytes(&f));

        let ciphertext = encrypt_payload(&plain, recipient)?;
        out.push(EncryptedShare {
            recipient: *recipient,
            ciphertext,
        });
    }
    Ok(out)
}

/// Descifra una share recibida y devuelve la contribución parcial.
///
/// No normaliza even-y: el chequeo de Feldman ([`verify_share`]) opera sobre
/// el valor crudo. La clave pública de grupo se completa en [`combine_shares`].
pub fn verify_and_decrypt_share(
    encrypted: &EncryptedShare,
    my_key: &SecretKey,
) -> Result<Share, Error> {
    if encrypted.ciphertext.len() < 33 + 12 + 16 + 37 {
        return Err(Error::InvalidShare("payload AEAD demasiado corto".into()));
    }
    if encrypted.ciphertext.len() - 33 - 12 - 16 != 37 {
        return Err(Error::InvalidShare(
            "longitud de ciphertext inválida".into(),
        ));
    }

    let plain = decrypt_payload(&encrypted.ciphertext, my_key)?;
    if plain.len() != 37 {
        return Err(Error::InvalidShare("longitud de payload inválida".into()));
    }

    let identifier = u32::from_be_bytes(plain[..4].try_into().expect("len 4"));
    if identifier == 0 {
        return Err(Error::InvalidShare("identificador inválido".into()));
    }
    let threshold = plain[4];
    let value_bytes: [u8; 32] = plain[5..37].try_into().expect("len 32");
    let value = scalar_from_canonical_or_zero(&value_bytes)
        .map_err(|_| Error::InvalidShare("share fuera del dominio".into()))?;

    Ok(Share {
        identifier,
        value: Zeroizing::new(scalar_to_bytes(&value)),
        threshold,
        group_public_key: PublicKey([0u8; 32]), // se completa en combine_shares
    })
}

/// Verificación de Feldman: comprueba que `share.value` sea `f_j(x)` del
/// polinomio comprometido por el emisor (`f(x)·G == Σ c_k · x^k`).
pub fn verify_share(share: &Share, issuer_commitments: &[Commitment]) -> Result<(), Error> {
    let x = index_scalar(share.identifier);
    let f = scalar_from_canonical_or_zero(&share.value)
        .map_err(|_| Error::InvalidShare("share fuera del dominio".into()))?;
    let lhs = point_mul_base(&f);

    let mut rhs = Gx::IDENTITY;
    let mut xpow = Fs::ONE;
    for c in issuer_commitments {
        if c.0.len() != 33 {
            return Err(Error::InvalidCommitment(InvalidCommitment(
                "compromiso de 33 bytes esperado".into(),
            )));
        }
        let bytes: [u8; 33] = c.0.as_slice().try_into().expect("len 33");
        let cp = point_from_bytes(&bytes)?;
        rhs += cp * xpow;
        xpow *= x;
    }

    if point_to_bytes(&lhs) != point_to_bytes(&rhs) {
        return Err(Error::InvalidShare(
            "share inconsistente con los compromisos del emisor".into(),
        ));
    }
    Ok(())
}

/// Combina las contribuciones recibidas (una por participante) en la share
/// final del BoxKey del destinatario.
///
/// 1. Suma los valores parciales: `sk_i = Σ_j f_j(i)`.
/// 2. Normaliza even-y del secreto: si la clave de grupo suma `c_j[0]` tiene
///    Y impar, niega la share (convención BIP340).
/// 3. Fija la clave pública del BoxKey (coordenada X de la suma de `c_j[0]`).
///
/// Las contribuciones deben haber pasado por [`verify_share`] previamente.
pub fn combine_shares(
    partials: &[Share],
    threshold: u8,
    commitments_first: &[Commitment],
) -> Result<Share, Error> {
    if partials.is_empty() {
        return Err(Error::InvalidShare("sin contribuciones".into()));
    }
    let identifier = partials[0].identifier;
    if partials.iter().any(|s| s.identifier != identifier) {
        return Err(Error::InvalidShare(
            "identificadores inconsistentes entre contribuciones".into(),
        ));
    }
    let t = usize::from(threshold);
    if partials.len() < t {
        return Err(Error::ThresholdNotMet {
            required: t,
            received: partials.len(),
        });
    }

    let mut sk = Fs::ZERO;
    for p in partials {
        let v = scalar_from_canonical_or_zero(&p.value)
            .map_err(|_| Error::InvalidShare("valor parcial inválido".into()))?;
        sk += v;
    }

    let mut group = Gx::IDENTITY;
    for c in commitments_first {
        if c.0.len() != 33 {
            return Err(Error::InvalidCommitment(InvalidCommitment(
                "compromiso de 33 bytes esperado".into(),
            )));
        }
        let bytes: [u8; 33] = c.0.as_slice().try_into().expect("len 33");
        group += point_from_bytes(&bytes)?;
    }
    if bool::from(group.is_identity()) {
        return Err(Error::Crypto("clave de grupo en el infinito".into()));
    }

    if sk.is_zero().into() {
        return Err(Error::InvalidShare("share combinada cero".into()));
    }

    // BIP340 (criterio frost-ref): todos los shares de un mismo BoxKey se
    // niegan a la vez si la clave de grupo (Σ c_j[0]) tiene Y impar; así la
    // interpolación de Lagrange reconstruye `±f(0)` y el protocolo es
    // coherente con la clave pública x-only del grupo.
    let sk_final = if point_has_even_y(&group) { sk } else { -sk };
    let group_x = point_x_bytes(&group);

    Ok(Share {
        identifier,
        value: Zeroizing::new(scalar_to_bytes(&sk_final)),
        threshold,
        group_public_key: PublicKey(group_x),
    })
}

/// Deriva la clave pública del BoxKey interpolando el término independiente
/// del polinomio (Lagrange en `x = 0`) a partir de un conjunto de shares.
///
/// Es una verificación independiente de la clave de grupo derivada de los
/// compromisos en [`combine_shares`].
pub fn derive_public_key(shares: &[Share]) -> Result<PublicKey, Error> {
    let a0 = lagrange_at_zero(shares)?;
    Ok(PublicKey(public_x_bytes_impl(&a0)))
}

fn public_x_bytes_impl(s: &Fs) -> [u8; 32] {
    point_x_bytes(&point_mul_base(s))
}

/// Deriva la clave pública parcial de un participante a partir de su share.
pub fn derive_partial_public_key(share: &Share) -> PublicKey {
    share.partial_public_key()
}

/// Interpola el valor del polinomio en `x = 0` (coeficiente libre `a_0`).
fn lagrange_at_zero(shares: &[Share]) -> Result<Fs, Error> {
    if shares.is_empty() {
        return Err(Error::InvalidShare("sin shares".into()));
    }
    let t = usize::from(shares[0].threshold);
    if shares.len() < t {
        return Err(Error::ThresholdNotMet {
            required: t,
            received: shares.len(),
        });
    }

    let mut ids = Vec::with_capacity(shares.len());
    let mut vals = Vec::with_capacity(shares.len());
    for s in shares {
        if usize::from(s.threshold) != t {
            return Err(Error::InconsistentGroup(
                "umbrales distintos entre shares".into(),
            ));
        }
        ids.push(index_scalar(s.identifier));
        vals.push(
            scalar_from_canonical_or_zero(&s.value)
                .map_err(|_| Error::InvalidShare("valor de share inválido".into()))?,
        );
    }

    // λ_i = ∏_{j≠i} (-id_j) / (id_i - id_j)
    let mut acc = Fs::ZERO;
    for i in 0..ids.len() {
        let mut num = Fs::ONE;
        let mut den = Fs::ONE;
        for j in 0..ids.len() {
            if i == j {
                continue;
            }
            num *= -ids[j];
            den *= ids[i] - ids[j];
        }
        let lambda = num * den.invert().unwrap();
        acc += lambda * vals[i];
    }
    Ok(acc)
}

/// Genera un par de claves `secp256k1` x-only para un participante.
///
/// Útil para pruebas locales, benchmarks y para que un participante materialice
/// su par ECDH antes de entrar al protocolo.
pub fn generate_participant_key() -> (SecretKey, PublicKey) {
    let s = crate::secp256k1::secret_key_random();
    let bytes = scalar_to_bytes(&s);
    let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
    (SecretKey(bytes), pk)
}

/// Genera un `SecretShare` cuyo término independiente es la share aportada
/// por un contribuyente y el resto del polinomio es aleatorio.
///
/// Usada en resharing: contribuyentes del grupo original generan cada uno un
/// polinomio `g(x)` con `g(0) = sk_i` y lo cifran a los nuevos participantes
/// (ver `crate::reshare`).
pub fn secret_from_share(
    contributor: &Share,
    threshold: u8,
    total_participants: u8,
) -> Result<SecretShare, Error> {
    let t = usize::from(threshold);
    if t == 0 {
        return Err(Error::InvalidCommitment(InvalidCommitment(
            "threshold debe ser >= 1".into(),
        )));
    }
    if usize::from(total_participants) < t {
        return Err(Error::InvalidCommitment(InvalidCommitment(format!(
            "total_participants ({total_participants}) menor que threshold ({threshold})"
        ))));
    }
    let constant = scalar_from_canonical_or_zero(&contributor.value)
        .map_err(|_| Error::InvalidShare("share de contribuyente inválida".into()))?;
    if bool::from(constant.is_zero()) {
        return Err(Error::InvalidShare("share de contribuyente cero".into()));
    }
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(constant);
    for _ in 1..t {
        coeffs.push(scalar_random(&mut OsRng));
    }
    Ok(share_from_coefficients(
        &coeffs,
        threshold,
        total_participants,
    ))
}

/// Ejecuta un DKG completo de `n` participantes con umbral `t` y devuelve
/// las shares finales junto a `(SecretKey, PublicKey)` de cada uno.
///
/// Útil para pruebas, benchmarks y demos. Cada participante genera su par de
/// claves localmente con [`generate_participant_key`].
pub fn run_dkg(n: u8, t: u8) -> (Vec<Share>, Vec<(SecretKey, PublicKey)>) {
    let nn = n as usize;
    let mut keys = Vec::with_capacity(nn);
    let mut all_commitments = Vec::with_capacity(nn);
    let mut first_commitments = Vec::with_capacity(nn);
    let mut encrypted_by = Vec::with_capacity(nn);
    let mut pks = Vec::with_capacity(nn);

    for _ in 0..nn {
        let (sk, pk) = generate_participant_key();
        keys.push((sk, pk));
        pks.push(pk);
    }
    for _ in 0..nn {
        let s = secret_with_threshold(&generate_secret(), t, n).unwrap();
        let comm = compute_commitments(&s);
        let pok = generate_proof_of_knowledge(&s);
        verify_commitments(&comm, &pok).unwrap();
        first_commitments.push(comm[0].clone());
        all_commitments.push(comm);
        encrypted_by.push(generate_shares(&s, &pks).unwrap());
    }

    let mut shares = Vec::with_capacity(nn);
    for (sk, pk) in &keys {
        let mut partials = Vec::with_capacity(nn);
        for j in 0..nn {
            let enc = &encrypted_by[j];
            let mine = enc.iter().find(|e| e.recipient == *pk).unwrap();
            let part = verify_and_decrypt_share(mine, sk).unwrap();
            verify_share(&part, &all_commitments[j]).unwrap();
            partials.push(part);
        }
        let combined = combine_shares(&partials, t, &first_commitments).unwrap();
        shares.push(combined);
    }
    (shares, keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant_key() -> (SecretKey, PublicKey) {
        generate_participant_key()
    }

    #[allow(clippy::type_complexity)]
    fn setup_two() -> (
        SecretShare,
        SecretShare,
        Vec<Commitment>,
        Vec<Commitment>,
        Vec<u8>,
        Vec<u8>,
        (SecretKey, PublicKey),
        (SecretKey, PublicKey),
    ) {
        let n = 2u8;
        let t = 2u8;
        let keys = (participant_key(), participant_key());
        let sa = secret_with_threshold(&generate_secret(), t, n).unwrap();
        let sb = secret_with_threshold(&generate_secret(), t, n).unwrap();
        let ca = compute_commitments(&sa);
        let cb = compute_commitments(&sb);
        let pok_a = generate_proof_of_knowledge(&sa);
        let pok_b = generate_proof_of_knowledge(&sb);
        (sa, sb, ca, cb, pok_a, pok_b, keys.0, keys.1)
    }

    #[test]
    fn generates_and_verifies_commitments() {
        let (_, _, ca, cb, pok_a, pok_b, _, _) = setup_two();
        assert!(verify_commitments(&ca, &pok_a).is_ok());
        assert!(verify_commitments(&cb, &pok_b).is_ok());

        let mut tampered = cb.clone();
        tampered[0].0[0] ^= 0x01;
        assert!(verify_commitments(&tampered, &pok_b).is_err());
        assert!(verify_commitments(&cb, b"tampered").is_err());
    }

    #[test]
    fn two_participants_reach_same_group_key() {
        let (sa, sb, ca, cb, _pok_a, _pok_b, (sk_a, pk_a), (sk_b, pk_b)) = setup_two();

        let pubkeys = [pk_a, pk_b];
        let shares_a = generate_shares(&sa, &pubkeys).unwrap();
        let shares_b = generate_shares(&sb, &pubkeys).unwrap();

        // A recibe la contribución de A hacia sí y de B hacia sí.
        let p_a1 = shares_a.iter().find(|e| e.recipient == pk_a).unwrap();
        let p_b1 = shares_b.iter().find(|e| e.recipient == pk_a).unwrap();
        let pa_a = verify_and_decrypt_share(p_a1, &sk_a).unwrap();
        let pb_a = verify_and_decrypt_share(p_b1, &sk_a).unwrap();
        verify_share(&pa_a, &ca).unwrap();
        verify_share(&pb_a, &cb).unwrap();
        let share_a = combine_shares(&[pa_a, pb_a], 2, &[ca[0].clone(), cb[0].clone()]).unwrap();

        // B idéntico.
        let p_a2 = shares_a.iter().find(|e| e.recipient == pk_b).unwrap();
        let p_b2 = shares_b.iter().find(|e| e.recipient == pk_b).unwrap();
        let pa_b = verify_and_decrypt_share(p_a2, &sk_b).unwrap();
        let pb_b = verify_and_decrypt_share(p_b2, &sk_b).unwrap();
        verify_share(&pa_b, &ca).unwrap();
        verify_share(&pb_b, &cb).unwrap();
        let share_b = combine_shares(&[pa_b, pb_b], 2, &[ca[0].clone(), cb[0].clone()]).unwrap();

        assert_eq!(share_a.group_public_key, share_b.group_public_key);
        assert_eq!(
            derive_public_key(&[share_a.clone(), share_b.clone()]).unwrap(),
            share_a.group_public_key
        );
        assert_ne!(share_a.partial_public_key(), share_b.partial_public_key());
    }

    #[test]
    fn feldman_rejects_a_tampered_share() {
        let (sa, _sb, ca, _cb, _pa, _pb, (_sk_a, pk_a), (_sk_b, pk_b)) = setup_two();
        let shares = generate_shares(&sa, &[pk_a, pk_b]).unwrap();
        let to_a = shares.iter().find(|e| e.recipient == pk_a).unwrap();
        let mut bad = to_a.clone();
        bad.ciphertext[33 + 12] ^= 0xff; // corrompe el payload cifrado
        assert!(verify_and_decrypt_share(&bad, &_sk_a).is_err());
        let ok = verify_and_decrypt_share(to_a, &_sk_a).unwrap();
        let mut tampered = ok.clone();
        tampered.value.as_mut()[0] ^= 0x01;
        assert!(verify_share(&tampered, &ca).is_err());
    }
}
