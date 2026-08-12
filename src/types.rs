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
use zeroize::Zeroizing;

use crate::secp256k1;

/// Serializa un array `[u8; N]` a JSON como hexadecimal.
///
/// `serde` no cubre arrays `> 32` (firma BIP340, 64 bytes): se codifican como
/// `0x...` para que el JSON sea compacto y legible.
mod serde_hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = String::from("0x");
        s.push_str(&hex::encode(bytes));
        serializer.serialize_str(&s)
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

/// Clave pública x-only BIP340 (32 bytes).
///
/// Es la representación pública de un punto de `secp256k1` (coordenada X),
/// usada para claves de participantes, del BoxKey y compromisos.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

/// Clave privada escalar (32 bytes).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretKey(pub [u8; 32]);

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
/// `identifier (4) || D || E` (70 bytes).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment(pub Vec<u8>);

/// Share cifrada end-to-end entre un emisor y un destinatario.
///
/// `ciphertext` incluye la clave efímera del emisor, el nonce y el payload
/// cifrado (AEAD). El coordinador (BS) nunca puede leer el contenido.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// Clave pública x-only del destinatario.
    pub recipient: PublicKey,
    /// `ephemeral_pubkey(33) || nonce(12) || tag(16) || ciphertext`.
    pub ciphertext: Vec<u8>,
}

/// Firma parcial FROST.
///
/// Contenido serializado:
/// - umbral (u8), nº de firmantes (u32 BE), clave pública del grupo (32),
/// - por firmante: identificador (u32 BE) || D (33) || E (33) || Y_i (33), y
/// - `z` del firmante (u32 BE identificador || 32 bytes escalar).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PartialSignature(pub Vec<u8>);

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
    /// Bytes de la firma parcial.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SchnorrSignature {
    /// Bytes `(R.x || s)` de la firma.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}
