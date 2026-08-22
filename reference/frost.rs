//! FROST — Firma Schnorr distribuida (RFC 9591) sobre `secp256k1`.
//!
//! Flujo de firma (t-de-n):
//! 1. El coordinador recopila firmantes `S` (`|S| >= t`), sus compromisos de
//!    nonces `(D_i, E_i)` y sus claves públicas parciales `Y_i` →
//!    [`SigningRound`].
//! 2. Cada firmante genera nonces deterministas con [`generate_nonces`] y
//!    publica su compromiso `(id || D || E)`.
//! 3. Cada firmante calcula su contribución [`sign_partial`]. Quien la reciba
//!    la valida con [`verify_partial`].
//! 4. El coordinador agrega [`aggregate_signatures`] y cualquiera verifica la
//!    Schnorr BIP340 final con [`verify_schnorr`].
//!
//! Convenciones (consistentes con DKG):
//! - Claves y nonces normalizados even-y; el desafío `e` usa `xonly(R)`.
//! - `rho_i` (binding factor) es un hash etiquetado determinista.
//! - El agregador niega `s` cuando `R` tiene Y impar (BIP340).
//!
//! La decisión de mantener un motor FROST propio (en lugar de
//! `frost-secp256k1-tr`) está documentada en `docs/decisions/0001-frost-propia.md`.

use crate::error::Error;
use crate::schnorr::verify_bip340;
use crate::secp256k1::{
    even_normalize_scalar, point_from_bytes, point_has_even_y, point_is_zero, point_mul_base,
    point_to_bytes, point_x_bytes, scalar_from_canonical_or_zero, scalar_from_hash,
    scalar_reduce_mod_n, scalar_to_bytes, tagged_hash, Fs, Gx,
};
use crate::types::{Commitment, PartialSignature, PublicKey, SchnorrSignature, Share};

/// Etiqueta del binding factor.
const RHO_TAG: &[u8] = b"boxkey/frost-rho";
/// Etiqueta de derivación determinista de nonces.
const NONCE_TAG: &[u8] = b"boxkey/frost-nonce";
/// Tamaño del bloque `id(4) || D(33) || E(33) || Y(33)` en firma parcial.
const BLOCK_LEN: usize = 4 + 33 + 33 + 33;
/// Longitud del sufijo `id_z(4) || z(32)`.
const Z_SUFFIX_LEN: usize = 4 + 32;

/// Información de un firmante dentro de un [`SigningRound`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerInfo {
    /// Identificador del firmante (1..=n).
    pub identifier: u32,
    /// Compromiso de nonces publicado: `id(4) || D(33) || E(33)`.
    pub nonce_commitment: Commitment,
    /// Clave pública parcial del firmante (x-only BIP340, 32 bytes).
    pub public_key: PublicKey,
    /// Clave pública parcial en punto comprimido SEC1 (33 bytes, con paridad).
    /// Necesaria para la verificación de FROST (el `lift_xonly` no es
    /// suficiente cuando el punto subyacente tiene Y impar).
    pub full_public_key: [u8; 33],
}

/// Round de firma: conjunto de firmantes y mensaje a firmar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningRound {
    /// Hash del mensaje que se firma (32 bytes).
    pub message_hash: [u8; 32],
    /// Clave pública del BoxKey (grupo).
    pub group_public_key: PublicKey,
    /// Firmantes del round, ordenados por identificador ascendente.
    pub signers: Vec<SignerInfo>,
}

impl SigningRound {
    /// Construye un round validando compromisos y ordenando por identificador.
    ///
    /// `full_public_keys` son las claves públicas parciales de cada firmante
    /// en formato SEC1 comprimido (33 bytes, con paridad Y). La x-only se
    /// extrae automáticamente de los últimos 32 bytes.
    pub fn new(
        message_hash: [u8; 32],
        group_public_key: PublicKey,
        commitments: &[(u32, Commitment)],
        full_public_keys: &[(u32, [u8; 33])],
    ) -> Result<Self, Error> {
        if commitments.is_empty() || commitments.len() != full_public_keys.len() {
            return Err(Error::InvalidSignature(
                "compromisos y claves públicas incompatibles".into(),
            ));
        }
        let mut signers = Vec::with_capacity(commitments.len());
        for (id, comm) in commitments {
            if *id == 0 {
                return Err(Error::InvalidSignature("identificador inválido".into()));
            }
            if comm.0.len() != 4 + 33 + 33 {
                return Err(Error::InvalidSignature(format!(
                    "commitment de nonces con longitud {} != 70",
                    comm.0.len()
                )));
            }
            if comm.0[..4] != id.to_be_bytes() {
                return Err(Error::InvalidSignature(
                    "id incoherente dentro del commitment".into(),
                ));
            }
            let full_key = full_public_keys
                .iter()
                .find(|(pid, _)| pid == id)
                .map(|(_, fk)| *fk)
                .ok_or_else(|| {
                    Error::InvalidSignature(format!("sin clave pública para firmante {id}"))
                })?;
            if full_key[0] != 0x02 && full_key[0] != 0x03 {
                return Err(Error::InvalidSignature(
                    "clave pública parcial malformada".into(),
                ));
            }
            let pk = PublicKey(full_key[1..].try_into().unwrap());
            signers.push(SignerInfo {
                identifier: *id,
                nonce_commitment: comm.clone(),
                public_key: pk,
                full_public_key: full_key,
            });
        }
        signers.sort_by_key(|s| s.identifier);
        Ok(Self {
            message_hash,
            group_public_key,
            signers,
        })
    }
}

/// Preimagen de `rho_i`: `id(4 BE) || msg || group_x || commit-list`.
fn rho_preimage(
    id: u32,
    message: &[u8; 32],
    group_x: &[u8; 32],
    commitments: &[Commitment],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 32 + 32 + commitments.len() * 70);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(message);
    v.extend_from_slice(group_x);
    for c in commitments {
        v.extend_from_slice(&c.0);
    }
    v
}

/// Commit-list del round (orden de identificador).
fn commitments_of(round: &SigningRound) -> Vec<Commitment> {
    round
        .signers
        .iter()
        .map(|s| s.nonce_commitment.clone())
        .collect()
}

/// Binding factor determinista `rho_i`.
fn binding_factor(round: &SigningRound, identifier: u32) -> Fs {
    let digest = tagged_hash(
        RHO_TAG,
        &rho_preimage(
            identifier,
            &round.message_hash,
            &round.group_public_key.0,
            &commitments_of(round),
        ),
    );
    scalar_from_hash(&digest)
}

/// Descompone `id(4)||D(33)||E(33)` en los dos puntos.
fn split_nonce_commitment(c: &Commitment) -> Option<(&[u8; 33], &[u8; 33])> {
    if c.0.len() != 4 + 33 + 33 {
        return None;
    }
    let d: &[u8; 33] = c.0[4..4 + 33].try_into().ok()?;
    let e: &[u8; 33] = c.0[4 + 33..4 + 33 + 33].try_into().ok()?;
    Some((d, e))
}

/// Punto `R = Σ_i (D_i + rho_i · E_i)`.
fn aggregate_nonce_point(round: &SigningRound) -> Gx {
    let mut acc = Gx::IDENTITY;
    for s in &round.signers {
        let rho = binding_factor(round, s.identifier);
        let (d, e) = split_nonce_commitment(&s.nonce_commitment)
            .expect("commitment validado por SigningRound::new");
        let d_pt = point_from_bytes(d).expect("D validado");
        let e_pt = point_from_bytes(e).expect("E validado");
        acc += d_pt + e_pt * rho;
    }
    acc
}

/// Desafío BIP340 `e = reduce(tag_hash(BIP0340/challenge, r || pubkey || m))`.
fn challenge(r: &[u8; 32], pubkey: &[u8; 32], message: &[u8; 32]) -> Fs {
    let mut pre = Vec::with_capacity(96);
    pre.extend_from_slice(r);
    pre.extend_from_slice(pubkey);
    pre.extend_from_slice(message);
    scalar_reduce_mod_n(&tagged_hash(b"BIP0340/challenge", &pre))
}

fn index_scalar(id: u32) -> Fs {
    let mut bytes = [0u8; 32];
    bytes[28] = (id >> 24) as u8;
    bytes[29] = (id >> 16) as u8;
    bytes[30] = (id >> 8) as u8;
    bytes[31] = id as u8;
    scalar_from_canonical_or_zero(&bytes).expect("identificador de firmante válido")
}

/// Coeficiente de Lagrange `λ_id` dentro del conjunto de firmantes.
fn lagrange(id: u32, others: &[u32]) -> Fs {
    let x = index_scalar(id);
    let mut acc = Fs::ONE;
    for o in others {
        if *o != id {
            let xj = index_scalar(*o);
            acc *= (-xj) * (x - xj).invert().unwrap();
        }
    }
    acc
}

/// Genera nonces deterministas `(d, e)` a partir de la share y el mensaje.
///
/// Devuelve `(hidden, commitment)`:
/// - `hidden` (`d(32) || e(32)`) solo lo conserva el titular.
/// - `commitment` (`id(4) || D(33) || E(33)`) es lo que se publica.
pub fn generate_nonces(
    share: &Share,
    message_hash: &[u8; 32],
) -> Result<(Vec<u8>, Commitment), Error> {
    let id = share.identifier();
    if id == 0 {
        return Err(Error::InvalidSignature("share sin identificador".into()));
    }
    let mut pre = Vec::with_capacity(32 + 4 + 32 + 32);
    pre.extend_from_slice(&share.value[..]);
    pre.extend_from_slice(&id.to_be_bytes());
    pre.extend_from_slice(&share.group_public_key().0);
    pre.extend_from_slice(message_hash);
    let seed = tagged_hash(NONCE_TAG, &pre);

    let (d, _) = even_normalize_scalar(scalar_from_hash(
        &[seed.as_slice(), b":d".as_slice()].concat(),
    ));
    let (e, _) = even_normalize_scalar(scalar_from_hash(
        &[seed.as_slice(), b":e".as_slice()].concat(),
    ));

    let mut hidden = Vec::with_capacity(64);
    hidden.extend_from_slice(&scalar_to_bytes(&d));
    hidden.extend_from_slice(&scalar_to_bytes(&e));

    let mut comm = Vec::with_capacity(70);
    comm.extend_from_slice(&id.to_be_bytes());
    let mut d_enc = [0u8; 33];
    d_enc[0] = 0x02;
    d_enc[1..].copy_from_slice(&point_x_bytes(&point_mul_base(&d)));
    let mut e_enc = [0u8; 33];
    e_enc[0] = 0x02;
    e_enc[1..].copy_from_slice(&point_x_bytes(&point_mul_base(&e)));
    comm.extend_from_slice(&d_enc);
    comm.extend_from_slice(&e_enc);

    Ok((hidden, Commitment(comm)))
}

/// Serializa una firma parcial con toda la información del round.
///
/// Layout: `threshold(1) || count(4 BE) || group_x(32) || [bloques de
/// firmante: id(4)||D(33)||E(33)||Y(33)]*count || id_z(4) || z(32)`.
fn serialize_partial(
    round: &SigningRound,
    threshold: u8,
    z_signer: u32,
    z: &Fs,
) -> PartialSignature {
    let mut v = Vec::with_capacity(1 + 4 + 32 + round.signers.len() * BLOCK_LEN + Z_SUFFIX_LEN);
    v.push(threshold);
    v.extend_from_slice(&(round.signers.len() as u32).to_be_bytes());
    v.extend_from_slice(&round.group_public_key.0);
    for s in &round.signers {
        // nonce_commitment ya incluye `id(4) || D(33) || E(33)`
        v.extend_from_slice(&s.nonce_commitment.0);
        v.extend_from_slice(&s.full_public_key);
    }
    v.extend_from_slice(&z_signer.to_be_bytes());
    v.extend_from_slice(&scalar_to_bytes(z));
    PartialSignature(v)
}

/// Firma una contribución parcial para el round.
pub fn sign_partial(
    round: &SigningRound,
    signer: &Share,
    hidden: &[u8],
) -> Result<PartialSignature, Error> {
    if hidden.len() != 64 {
        return Err(Error::InvalidSignature("nonces hidden de 64 bytes".into()));
    }
    let id = signer.identifier();
    let si = round
        .signers
        .iter()
        .find(|s| s.identifier == id)
        .ok_or_else(|| Error::InvalidSignature("firmante no está en el round".into()))?;

    let d = scalar_from_canonical_or_zero(&hidden[..32].try_into().expect("32"))
        .map_err(|_| Error::InvalidSignature("nonce d inválido".into()))?;
    let e = scalar_from_canonical_or_zero(&hidden[32..].try_into().expect("32"))
        .map_err(|_| Error::InvalidSignature("nonce e inválido".into()))?;

    // Los nonces deben coincidir con los comprometidos públicamente.
    let (d_enc, e_enc) = split_nonce_commitment(&si.nonce_commitment)
        .ok_or_else(|| Error::InvalidSignature("commitment malformado".into()))?;
    if d_enc[1..] != point_x_bytes(&point_mul_base(&d))
        || e_enc[1..] != point_x_bytes(&point_mul_base(&e))
    {
        return Err(Error::InvalidSignature(
            "nonces no coinciden con el compromiso publicado".into(),
        ));
    }

    let rho = binding_factor(round, id);
    let r_point = aggregate_nonce_point(round);
    let r = point_x_bytes(&r_point);
    let c = challenge(&r, &round.group_public_key.0, &round.message_hash);

    let others: Vec<u32> = round.signers.iter().map(|s| s.identifier).collect();
    let lambda = lagrange(id, &others);

    let sk = scalar_from_canonical_or_zero(&signer.value)
        .map_err(|_| Error::InvalidSignature("share inválida".into()))?;

    // BIP340: si el R agregado tiene Y impar, cada firmante NIEGA sus nonces
    // (criterio frost-secp256k1-tr). Esto cambia el signo de la parte `k` de
    // la contribución sin alterar `lambda·c·sk`.
    let (d_eff, e_eff) = if point_has_even_y(&r_point) {
        (d, e)
    } else {
        (-d, -e)
    };

    // z_i = d + rho·e + lambda·c·sk_i  (con nonces ya ajustados a BIP340)
    let z = d_eff + rho * e_eff + lambda * c * sk;

    Ok(serialize_partial(round, signer.threshold(), id, &z))
}

/// Payload parseado de una firma parcial.
struct ParsedPartial {
    threshold: u8,
    group_public_key: PublicKey,
    signers: Vec<SignerInfo>,
    z_signer: u32,
    z: Fs,
}

/// Parsea una firma parcial validando estructura completa.
fn parse_partial(sig: &PartialSignature) -> Result<ParsedPartial, Error> {
    let b = &sig.0;
    if b.len() < 37 + BLOCK_LEN + Z_SUFFIX_LEN {
        return Err(Error::InvalidSignature(
            "firma parcial demasiado corta".into(),
        ));
    }
    let threshold = b[0];
    if threshold == 0 {
        return Err(Error::InvalidSignature("umbral inválido".into()));
    }
    let count = u32::from_be_bytes(b[1..5].try_into().unwrap()) as usize;
    if count == 0 {
        return Err(Error::InvalidSignature("conteo inválido".into()));
    }
    let expected = 1 + 4 + 32 + count * BLOCK_LEN + Z_SUFFIX_LEN;
    if b.len() != expected {
        return Err(Error::InvalidSignature(format!(
            "longitud {} != esperada {expected}",
            b.len()
        )));
    }

    let group_public_key = PublicKey(b[5..37].try_into().unwrap());
    let mut signers = Vec::with_capacity(count);
    let mut ids = Vec::with_capacity(count);
    let mut pos = 37;
    for _ in 0..count {
        let comm = Commitment(b[pos..pos + 70].to_vec());
        let id = u32::from_be_bytes(comm.0[..4].try_into().unwrap());
        let y_enc: &[u8; 33] = b[pos + 70..pos + 70 + 33]
            .try_into()
            .map_err(|_| Error::InvalidSignature("bloque Y malformado".into()))?;
        if y_enc[0] != 0x02 && y_enc[0] != 0x03 {
            return Err(Error::InvalidSignature("clave parcial malformada".into()));
        }
        if comm.0[..4] != id.to_be_bytes() {
            return Err(Error::InvalidSignature("id incoherente en bloque".into()));
        }
        signers.push(SignerInfo {
            identifier: id,
            nonce_commitment: comm,
            public_key: PublicKey(y_enc[1..].try_into().unwrap()),
            full_public_key: *y_enc,
        });
        ids.push(id);
        pos += BLOCK_LEN;
    }
    signers.sort_by_key(|s| s.identifier);

    let z_signer = u32::from_be_bytes(b[pos..pos + 4].try_into().unwrap());
    let z_bytes: &[u8; 32] = b[pos + 4..pos + 4 + 32].try_into().unwrap();
    let z = scalar_from_canonical_or_zero(z_bytes)
        .map_err(|_| Error::InvalidSignature("z fuera del dominio".into()))?;
    if !ids.contains(&z_signer) {
        return Err(Error::InvalidSignature("firmante sin bloque".into()));
    }

    Ok(ParsedPartial {
        threshold,
        group_public_key,
        signers,
        z_signer,
        z,
    })
}

/// Reconstruye el round con el mensaje real a partir de un partial parseado.
fn parsed_round(message_hash: &[u8; 32], p: &ParsedPartial) -> Result<SigningRound, Error> {
    let commitments: Vec<(u32, Commitment)> = p
        .signers
        .iter()
        .map(|s| (s.identifier, s.nonce_commitment.clone()))
        .collect();
    let full_public_keys: Vec<(u32, [u8; 33])> = p
        .signers
        .iter()
        .map(|s| (s.identifier, s.full_public_key))
        .collect();
    SigningRound::new(
        *message_hash,
        p.group_public_key,
        &commitments,
        &full_public_keys,
    )
}

/// Verifica la contribución de un firmante contra su clave pública parcial.
pub fn verify_partial(
    sig: &PartialSignature,
    signer_public_key: &PublicKey,
    message_hash: &[u8; 32],
) -> Result<(), Error> {
    let p = parse_partial(sig)?;
    let idx = p
        .signers
        .iter()
        .position(|s| s.public_key == *signer_public_key)
        .ok_or_else(|| Error::InvalidSignature("firmante ajeno al round".into()))?;
    let info = &p.signers[idx];

    let round = parsed_round(message_hash, &p)?;
    if round.group_public_key != p.group_public_key {
        return Err(Error::InvalidSignature(
            "clave de grupo inconsistente".into(),
        ));
    }

    let rho = binding_factor(&round, p.z_signer);
    let r_point = aggregate_nonce_point(&round);
    let r = point_x_bytes(&r_point);
    let c = challenge(&r, &round.group_public_key.0, message_hash);

    let others: Vec<u32> = round.signers.iter().map(|s| s.identifier).collect();
    let lambda = lagrange(p.z_signer, &others);

    let (d_enc, e_enc) = split_nonce_commitment(&info.nonce_commitment)
        .ok_or_else(|| Error::InvalidSignature("commitment malformado".into()))?;
    let d_pt = point_from_bytes(d_enc)?;
    let e_pt = point_from_bytes(e_enc)?;
    let y_pt = point_from_bytes(&info.full_public_key)?;

    // BIP340: si R tiene Y impar, el commitment de grupo `D + rho·E` se niega
    // (consistente con la negación de nonces del firmante).
    let nonce_commit = d_pt + e_pt * rho;
    let nonce_commit = if point_has_even_y(&r_point) {
        nonce_commit
    } else {
        -nonce_commit
    };

    // z·G == (D + rho·E) + lambda·c·Y
    let lhs = point_mul_base(&p.z);
    let rhs = nonce_commit + y_pt * (lambda * c);
    if point_to_bytes(&lhs) != point_to_bytes(&rhs) {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

/// Cuerpo canónico de un partial (todo hasta antes de `z`).
fn canonical_body(raw: &[u8]) -> Result<&[u8], Error> {
    if raw.len() < 5 {
        return Err(Error::InvalidSignature("parcial corto".into()));
    }
    let count = u32::from_be_bytes(raw[1..5].try_into().unwrap()) as usize;
    let body_len = 1 + 4 + 32 + count * BLOCK_LEN;
    if raw.len() < body_len + Z_SUFFIX_LEN {
        return Err(Error::InvalidSignature("body incompleto".into()));
    }
    Ok(&raw[..body_len])
}

/// Agrega contribuciones de distintos firmantes en una Schnorr BIP340 final.
///
/// Exige que todos los partials describan el mismo round, que haya al menos
/// `threshold` contribuciones de firmantes distintos y que la agregación
/// verifique.
pub fn aggregate_signatures(
    sigs: &[PartialSignature],
    group_public_key: &PublicKey,
    message_hash: &[u8; 32],
) -> Result<SchnorrSignature, Error> {
    if sigs.is_empty() {
        return Err(Error::InvalidSignature("sin firmas parciales".into()));
    }

    let first = parse_partial(&sigs[0])?;
    if first.group_public_key != *group_public_key {
        return Err(Error::InvalidSignature("clave de grupo distinta".into()));
    }

    // Todos deben describir el mismo round (mismos bloques, mismo orden).
    let canon = canonical_body(&sigs[0].0)?.to_vec();
    for s in &sigs[1..] {
        if canonical_body(&s.0)? != canon {
            return Err(Error::InvalidSignature(
                "rounds distintos entre firmas parciales".into(),
            ));
        }
    }

    let round = parsed_round(message_hash, &first)?;
    let threshold = usize::from(first.threshold);

    // Suma de z sobre firmantes distintos.
    let mut seen = Vec::with_capacity(sigs.len());
    let mut z_sum = Fs::ZERO;
    for s in sigs {
        let p = parse_partial(s)?;
        if p.z_signer == 0 {
            return Err(Error::InvalidSignature("z_signer inválido".into()));
        }
        if seen.contains(&p.z_signer) {
            return Err(Error::NonceReuse);
        }
        if p.z_signer > usize::MAX as u32 {
            unreachable!()
        }
        seen.push(p.z_signer);
        z_sum += p.z;
    }
    if seen.len() < threshold {
        return Err(Error::ThresholdNotMet {
            required: threshold,
            received: seen.len(),
        });
    }
    if seen.len() != round.signers.len() {
        return Err(Error::InvalidSignature(
            "conjunto de firmantes distinto del round descrito".into(),
        ));
    }

    let r_point = aggregate_nonce_point(&round);
    if point_is_zero(&r_point) {
        return Err(Error::InvalidSignature("R en el infinito".into()));
    }
    let r = point_x_bytes(&r_point);

    // BIP340: los partials ya incorporan la negación de nonces cuando R es
    // impar (ver `sign_partial`), así que `s = Σz_i` sin más ajustes.
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&scalar_to_bytes(&z_sum));
    let sig_out = SchnorrSignature(out);

    verify_schnorr(&sig_out, group_public_key, message_hash)?;
    Ok(sig_out)
}

/// Verifica una firma Schnorr BIP340 final contra la clave de grupo.
pub fn verify_schnorr(
    sig: &SchnorrSignature,
    group_public_key: &PublicKey,
    message_hash: &[u8; 32],
) -> Result<(), Error> {
    verify_bip340(&sig.0, &group_public_key.0, message_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;

    fn two_of_three_round() -> (Vec<Share>, SigningRound) {
        let (shares, _keys) = dkg::run_dkg(3, 2);
        let msg = [0x42u8; 32];
        let group = shares[0].group_public_key();
        let signers = &shares[..2];

        let mut commitments = Vec::new();
        let mut full_public_keys = Vec::new();
        for s in signers {
            let (_h, comm) = generate_nonces(s, &msg).unwrap();
            commitments.push((s.identifier(), comm.clone()));
            let full_pk = s.full_public_key_point();
            full_public_keys.push((s.identifier(), full_pk));
        }
        let round = SigningRound::new(msg, group, &commitments, &full_public_keys).unwrap();
        (signers.to_vec(), round)
    }

    fn partial_signatures(round: &SigningRound, signers: &[Share]) -> Vec<PartialSignature> {
        signers
            .iter()
            .map(|s| {
                let (hidden, _comm) = generate_nonces(s, &round.message_hash).unwrap();
                sign_partial(round, s, &hidden).unwrap()
            })
            .collect()
    }

    #[test]
    fn one_of_one_signs_and_verifies() {
        let (shares, _keys) = dkg::run_dkg(1, 1);
        let msg = [0x42u8; 32];
        let signer = &shares[0];
        let (hidden, comm) = generate_nonces(signer, &msg).unwrap();
        let round = SigningRound::new(
            msg,
            signer.group_public_key(),
            &[(signer.identifier(), comm)],
            &[(signer.identifier(), signer.full_public_key_point())],
        )
        .unwrap();
        let sig = sign_partial(&round, signer, &hidden).unwrap();
        verify_partial(&sig, &signer.partial_public_key(), &msg).expect("1-de-1 válida");

        let agg = aggregate_signatures(&[sig], &round.group_public_key, &msg).unwrap();
        verify_schnorr(&agg, &round.group_public_key, &msg).expect("firma final válida");
    }

    #[test]
    fn two_of_three_signs_and_verifies() {
        let (signers, round) = two_of_three_round();
        let sigs = partial_signatures(&round, &signers);

        for (s, sig) in signers.iter().zip(sigs.iter()) {
            verify_partial(sig, &s.partial_public_key(), &round.message_hash)
                .expect("contribución válida");
        }

        let agg = aggregate_signatures(&sigs, &round.group_public_key, &round.message_hash)
            .expect("agregación válida");
        verify_schnorr(&agg, &round.group_public_key, &round.message_hash)
            .expect("firma final válida");

        let mut bad = agg;
        bad.0[63] ^= 0x01;
        assert!(verify_schnorr(&bad, &round.group_public_key, &round.message_hash).is_err());
    }
}
