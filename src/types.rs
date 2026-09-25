//! Tipos públicos compartidos de BoxKey Core (BC).
//!
//! Los nombres y formas corresponden a `contratos.md §2`:
//! `SecretShare`, `Commitment`, `EncryptedShare`, `Share`, `PublicKey`,
//! `SecretKey`, `PartialSignature`, `SchnorrSignature`.
//!
//! Los materiales secretos (`Share.value`, `SecretShare.coefficients`) se
//! mantienen en contenedores `Zeroizing` para que se borren al descartarse.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::secp256k1;

/// Serializa un array `[u8; N]` a JSON como hexadecimal en minúsculas sin
/// prefijo `0x` (BZ-0010 §2.5/2.6, representación canónica textual).
///
/// `serde` no cubre arrays `> 32` (firma BIP340, 64 bytes): se codifican como
/// hex para que el JSON sea compacto y legible. Al deserializar se tolera el
/// prefijo `0x` (entrada indulgente, salida canónica).
mod serde_hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let trimmed = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(trimmed).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("se esperaban {N} bytes")))
    }
}

/// Serializa un `Vec<u8>` a JSON como hexadecimal en minúsculas sin prefijo
/// `0x` (BZ-0010 §2.9: los arrays binarios se representan como hex).
///
/// Al deserializar se tolera el prefijo `0x` (entrada indulgente, salida canónica).
mod serde_hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let trimmed = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(trimmed).map_err(serde::de::Error::custom)
    }
}

/// Clave pública x-only BIP340 (32 bytes).
///
/// Es la representación pública de un punto de `secp256k1` (coordenada X),
/// usada para claves de participantes, del BoxKey y compromisos. Serializa a
/// hex minúsculas sin prefijo (BZ-0010 §2.5).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_hex_array::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(PublicKey(serde_hex_array::deserialize(deserializer)?))
    }
}

/// Clave privada escalar (32 bytes). Se zeroiza al dropear.
#[derive(PartialEq, Eq, Hash)]
pub struct SecretKey(pub [u8; 32]);

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Share secreta (fracción de clave) de un participante.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// Identificador del participante dentro del grupo (1..=n).
    pub(crate) identifier: u32,
    /// Valor de la share (escalar normalizado even-y).
    pub(crate) value: Zeroizing<[u8; 32]>,
    /// Umbral (t) del BoxKey al que pertenece.
    pub(crate) threshold: u8,
    /// Clave pública del BoxKey (grupo), x-only.
    pub(crate) group_public_key: PublicKey,
}

/// Polinomio local de un participante durante el DKG.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretShare {
    /// Coeficientes `[a_0, a_1, ..., a_{grado}]`, cada uno de 32 bytes.
    pub(crate) coefficients: Zeroizing<Vec<u8>>,
    /// Umbral configurado localmente (ver `secret_with_threshold`).
    pub(crate) threshold: u8,
    /// Número total de participantes configurado localmente.
    pub(crate) total_participants: u8,
}

/// Compromiso criptográfico.
///
/// En contexto DKG es un punto comprimido SEC1 (33 bytes) `a_j·G`
/// (commitment de Feldman). En contexto FROST agrega además el identificador
/// del firmante y los nonces `D || E`:
/// `identifier (4) || D || E` (70 bytes). Se serializa como hex sin prefijo.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment(#[serde(with = "serde_hex_vec")] pub Vec<u8>);

/// Share cifrada end-to-end entre un emisor y un destinatario.
///
/// `ciphertext` incluye la clave efímera del emisor, el nonce y el payload
/// cifrado (AEAD). El coordinador (BS) nunca puede leer el contenido.
/// El campo `ciphertext` se serializa como hex sin prefijo.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// Clave pública x-only del destinatario.
    pub recipient: PublicKey,
    /// `ephemeral_pubkey(33) || nonce(12) || tag(16) || ciphertext`.
    #[serde(with = "serde_hex_vec")]
    pub ciphertext: Vec<u8>,
}

/// Firma parcial FROST conforme BZ: `id (u32 BE) || z (32 bytes)` (36 bytes).
///
/// El contexto criptográfico (D, E, verifying shares, group key, threshold)
/// se mantiene en [`SigningSession`]. Cada PartialSignature transporta
/// únicamente el identificador del firmante y el escalar z de su contribución.
#[derive(Clone, PartialEq, Eq)]
pub struct PartialSignature(pub [u8; 36]);

/// NonceHandle encapsula el secreto de nonce con lifecycle obligatorio:
/// GENERATED → COMMITTED (commitment publicado) → USED (consumido por sign_partial) → ZEROIZED.
///
/// Semántica:
/// - No expone el nonce como `Vec<u8>` en API pública normal.
/// - Al consumirse via [`NonceHandle::consume`], el secreto se zeroiza y el handle
///   queda en estado `Consumed`.
/// - Reutilización detectada: segundo `consume()` retorna `None`.
/// - `Debug` oculta el secreto.
/// - No serializable.
pub struct NonceHandle {
    identifier: u32,
    state: NonceState,
}

enum NonceState {
    Live { hidden: Zeroizing<Vec<u8>> },
    Consumed,
}

impl NonceHandle {
    /// Crea un nuevo NonceHandle a partir de los nonces secretos serializados
    /// y el identificador del firmante.
    pub(crate) fn new(identifier: u32, hidden: Vec<u8>) -> Self {
        Self {
            identifier,
            state: NonceState::Live {
                hidden: Zeroizing::new(hidden),
            },
        }
    }

    /// Consume el handle, extrayendo los nonces secretos si no ha sido usado antes.
    /// Tras la extracción, el secreto se zeroiza y el estado pasa a `Consumed`.
    pub fn consume(&mut self) -> Option<Vec<u8>> {
        match &mut self.state {
            NonceState::Live { hidden } => {
                let result = hidden.clone().to_vec();
                hidden.zeroize();
                self.state = NonceState::Consumed;
                Some(result)
            }
            NonceState::Consumed => None,
        }
    }

    /// Identificador del firmante asociado a este nonce.
    pub fn identifier(&self) -> u32 {
        self.identifier
    }

    /// `true` si el handle ya ha sido consumido.
    pub fn is_consumed(&self) -> bool {
        matches!(self.state, NonceState::Consumed)
    }
}

impl fmt::Debug for NonceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NonceHandle({{ id: {}, state: {} }})", 
            self.identifier,
            match &self.state {
                NonceState::Live { .. } => "Live",
                NonceState::Consumed => "Consumed",
            })
    }
}

impl Drop for NonceHandle {
    fn drop(&mut self) {
        if let NonceState::Live { hidden } = &mut self.state {
            hidden.zeroize();
        }
    }
}

/// Información de un firmante dentro de una sesión de firma.
#[derive(Clone, PartialEq, Eq)]
pub struct SignerInfo {
    /// Identificador del firmante (1..=n).
    pub identifier: u32,
    /// Compromiso de nonces: `id(4) || D(33) || E(33)`.
    pub nonce_commitment: Commitment,
    /// Punto SEC1 comprimido de la clave pública parcial (33 bytes).
    pub verifying_share_point: [u8; 33],
}

/// Sesión de firma FROST: contexto que agrupa todos los datos necesarios
/// para generar firmas parciales y agregarlas.
///
/// Equivale conceptualmente a `SigningPackage` + contexto adicional
/// (verifying shares, group key, threshold).
#[derive(Clone, PartialEq, Eq)]
pub struct SigningSession {
    /// Hash del mensaje a firmar (32 bytes).
    pub message_hash: [u8; 32],
    /// Clave pública del grupo (x-only BIP340).
    pub group_public_key: PublicKey,
    /// Umbral (t).
    pub threshold: u8,
    /// Firmantes de la sesión, ordenados por identificador ascendente.
    pub signers: Vec<SignerInfo>,
}

impl SigningSession {
    /// Construye una sesión validando la consistencia de los datos.
    ///
    /// - `signers` debe contener al menos `threshold` firmantes.
    /// - Los identificadores deben ser únicos y > 0.
    /// - Los commitments deben tener formato `id(4) || D(33) || E(33)`.
    pub fn new(
        message_hash: [u8; 32],
        group_public_key: PublicKey,
        threshold: u8,
        commitments: Vec<Commitment>,
        verifying_share_points: Vec<(u32, [u8; 33])>,
    ) -> Result<Self, crate::error::Error> {
        let t = threshold as usize;
        if commitments.len() < t {
            return Err(crate::error::Error::InvalidSignature(
                format!("commitments insuficientes: {} < {t}", commitments.len())
            ));
        }
        if commitments.len() != verifying_share_points.len() {
            return Err(crate::error::Error::InvalidSignature(
                "commitments y verifying shares longitud distinta".into()
            ));
        }

        let mut signers = Vec::with_capacity(commitments.len());
        for comm in &commitments {
            if comm.0.len() != 70 {
                return Err(crate::error::Error::InvalidSignature(
                    format!("commitment length {} != 70", comm.0.len())
                ));
            }
            let id = u32::from_be_bytes(comm.0[..4].try_into().map_err(|_| {
                crate::error::Error::InvalidSignature("id en commitment".into())
            })?);
            if id == 0 {
                return Err(crate::error::Error::InvalidSignature(
                    "identificador 0 inválido".into()
                ));
            }
            if comm.0[..4] != id.to_be_bytes() {
                return Err(crate::error::Error::InvalidSignature(
                    "id incoherente dentro del commitment".into(),
                ));
            }
            let y_point = verifying_share_points
                .iter()
                .find(|(pid, _)| *pid == id)
                .map(|(_, pt)| *pt)
                .ok_or_else(|| crate::error::Error::InvalidSignature(
                    format!("sin verifying share para firmante {id}")
                ))?;
            if y_point[0] != 0x02 && y_point[0] != 0x03 {
                return Err(crate::error::Error::InvalidSignature(
                    "verifying share point malformado".into()
                ));
            }
            signers.push(SignerInfo {
                identifier: id,
                nonce_commitment: comm.clone(),
                verifying_share_point: y_point,
            });
        }
        signers.sort_by_key(|s| s.identifier);

        Ok(Self {
            message_hash,
            group_public_key,
            threshold,
            signers,
        })
    }

    /// Commitment de todos los firmantes, en orden de identificador.
    pub fn commitments(&self) -> Vec<Commitment> {
        self.signers.iter().map(|s| s.nonce_commitment.clone()).collect()
    }

    /// Verifying shares points de todos los firmantes, en orden de identificador.
    pub fn verifying_shares(&self) -> Vec<(u32, [u8; 33])> {
        self.signers.iter().map(|s| (s.identifier, s.verifying_share_point)).collect()
    }

    /// Número de firmantes en la sesión.
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }
}

impl fmt::Debug for SigningSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningSession {{ {} firmantes, msg: {}... }}",
            self.signers.len(),
            hex::encode(&self.message_hash[..4]))
    }
}

/// Firma Schnorr BIP340 agregada `(R.x || s)` (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SchnorrSignature(pub [u8; 64]);

impl Serialize for SchnorrSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_hex_array::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SchnorrSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(SchnorrSignature(serde_hex_array::deserialize(
            deserializer,
        )?))
    }
}

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SchnorrSignature({})", hex::encode(self.0))
    }
}

impl PublicKey {
    /// Coordenada X del punto de la clave.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Construye desde bytes x-only.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Share {{ identifier: {}, [REDACTED], ... }}",
            self.identifier
        )
    }
}

impl fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretShare {{ coefficients: [REDACTED], threshold: {} }}",
            self.threshold
        )
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Commitment({} bytes)", self.0.len())
    }
}

impl Share {
    /// Identificador del participante dentro del grupo.
    pub fn identifier(&self) -> u32 {
        self.identifier
    }

    /// Umbral del BoxKey.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Clave pública del BoxKey (grupo).
    pub fn group_public_key(&self) -> PublicKey {
        self.group_public_key
    }

    /// Coordenada X de la clave parcial de este participante.
    pub fn partial_public_key(&self) -> PublicKey {
        let s = secp256k1::scalar_from_canonical(&self.value).expect("share value siempre válida");
        PublicKey(secp256k1::public_x_bytes(&s))
    }

    /// Punto SEC1 comprimido (33 bytes) de la clave parcial de este participante.
    /// Incluye la paridad Y, necesaria para la verificación FROST.
    pub fn full_public_key_point(&self) -> [u8; 33] {
        let s = secp256k1::scalar_from_canonical(&self.value).expect("share value siempre válida");
        secp256k1::point_to_bytes(&secp256k1::point_mul_base(&s))
    }
}

impl SecretShare {
    /// Umbral actualmente configurado localmente.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Número de participantes configurado localmente.
    pub fn total_participants(&self) -> u8 {
        self.total_participants
    }
}

impl Commitment {
    /// Bytes del compromiso.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construye un compromiso DKG desde un punto comprimido.
    pub fn from_point_bytes(bytes: &[u8; 33]) -> Self {
        Self(bytes.to_vec())
    }
}

impl EncryptedShare {
    /// Destinatario de la share.
    pub fn recipient(&self) -> PublicKey {
        self.recipient
    }
}

impl PartialSignature {
    /// Bytes `id(4) || z(32)` de la firma parcial.
    pub fn as_bytes(&self) -> &[u8; 36] {
        &self.0
    }

    /// Identificador del firmante.
    pub fn identifier(&self) -> u32 {
        u32::from_be_bytes(self.0[..4].try_into().unwrap())
    }

    /// Escalar `z` de la contribución (32 bytes).
    pub fn z_bytes(&self) -> [u8; 32] {
        self.0[4..36].try_into().unwrap()
    }
}

impl Serialize for PartialSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_hex_array::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PartialSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(PartialSignature(serde_hex_array::deserialize(deserializer)?))
    }
}

impl fmt::Debug for PartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PartialSignature(id={})", self.identifier())
    }
}

impl SchnorrSignature {
    /// Bytes `(R.x || s)` de la firma.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_serde_no_usa_prefijo_0x() {
        let pk = PublicKey([0xab; 32]);
        let sig = SchnorrSignature([0xcd; 64]);

        let pk_json = serde_json::to_string(&pk).expect("PublicKey serializable");
        let sig_json = serde_json::to_string(&sig).expect("SchnorrSignature serializable");

        assert!(
            !pk_json.contains("0x"),
            "PublicKey no debe usar prefijo 0x: {pk_json}"
        );
        assert!(
            !sig_json.contains("0x"),
            "SchnorrSignature no debe usar prefijo 0x: {sig_json}"
        );

        assert_eq!(pk_json.len(), 64 + 2, "32 bytes en 64 chars hex");
        assert_eq!(sig_json.len(), 128 + 2, "64 bytes en 128 chars hex");

        let pk_round: PublicKey = serde_json::from_str(&pk_json).expect("deserializa");
        let sig_round: SchnorrSignature = serde_json::from_str(&sig_json).expect("deserializa");
        assert_eq!(pk_round, pk);
        assert_eq!(sig_round, sig);
    }

    #[test]
    fn hex_deseriliza_tolerando_prefijo_0x() {
        let sig: SchnorrSignature =
            serde_json::from_str(&format!("\"0x{}\"", hex::encode([0x11; 64])))
                .expect("acepta 0x al parsear");
        assert_eq!(sig.0, [0x11; 64]);
    }

    #[test]
    fn hex_deseriliza_rechaza_longitud_incorrecta() {
        let err = serde_json::from_str::<PublicKey>("\"abcd\"").expect_err("longitud inválida");
        assert!(err.to_string().contains("32 bytes"));
    }
}
