//! Serialización canónica de los mensajes del protocolo (Anexo A — versionado).
//!
//! Toda comunicación externa (con el coordinador BS y entre participantes)
//! viaja en un [`Envelope`] que incluye `protocolVersion`, `cryptoSuite` y
//! `messageVersion` (ver `BZ.md Anexo A` y `rfc.md §7`).
//!
//! Los materiales secretos (`Share`, `SecretShare`, `SecretKey`) NUNCA se
//! serializan: solo existen DTOs públicos (claves, compromisos, firmas).
//!
//! Formato: JSON canónico (`serde_json`), con `kind` como etiqueta en
//! `MessageKind`.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::types::{Commitment, EncryptedShare, PartialSignature, PublicKey, SchnorrSignature};

/// `protocolVersion` de la capa BC (Anexo A).
pub const PROTOCOL_VERSION: u8 = 1;
/// `cryptoSuite` del motor criptográfico.
pub const CRYPTO_SUITE: &str = "secp256k1-bip340-frost";
/// `messageVersion` de los mensajes serializados.
pub const MESSAGE_VERSION: u8 = 1;
/// Versión del conector (BC) — aquí el propio crate.
pub const CONNECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Sobre de mensaje con los tres campos de versionado obligatorios.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol_version: u8,
    pub crypto_suite: String,
    pub message_version: u8,
    pub connector_version: String,
    #[serde(flatten)]
    pub kind: MessageKind,
}

/// Mensajes del protocolo entre los actores de la capa de firma distribuida.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageKind {
    /// Ronda 1 del DKG: compromisos de Feldman + PoK del coeficiente libre.
    DkgRound1 {
        sender: PublicKey,
        commitments: Vec<Commitment>,
        proof_of_knowledge: String,
    },
    /// Ronda 2 del DKG: shares cifradas para cada destinatario.
    DkgRound2 {
        sender: PublicKey,
        shares: Vec<EncryptedShare>,
    },
    /// Compromiso de nonces de una firma FROST.
    NonceCommitment {
        signer: PublicKey,
        commitment: Commitment,
    },
    /// Firma parcial de un round FROST.
    PartialSignature {
        sender: PublicKey,
        signature: PartialSignature,
    },
    /// Firma Schnorr agregada lista para broadcast.
    Aggregate {
        message_hash: String,
        signature: SchnorrSignature,
    },
    /// Mensaje de redistribución de un contribuyente hacia un nuevo grupo.
    ReshareDelivery {
        contributor: PublicKey,
        contributions: Vec<EncryptedShare>,
    },
}

impl Envelope {
    /// Construye un sobre con el versionado canónico de BC.
    pub fn new(kind: MessageKind) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            crypto_suite: CRYPTO_SUITE.to_string(),
            message_version: MESSAGE_VERSION,
            connector_version: CONNECTOR_VERSION.to_string(),
            kind,
        }
    }
}

/// Serializa un sobre a JSON compacto.
pub fn encode(envelope: &Envelope) -> Result<String, Error> {
    serde_json::to_string(envelope).map_err(|e| Error::Serialization(format!("encode json: {e}")))
}

/// Deserializa un sobre y valida los campos de versionado.
pub fn decode(raw: &str) -> Result<Envelope, Error> {
    let env: Envelope =
        serde_json::from_str(raw).map_err(|e| Error::Serialization(format!("decode json: {e}")))?;
    validate_versioning(&env)?;
    Ok(env)
}

/// Comprueba compatibilidad de versionado (Anexo A, §1).
pub fn validate_versioning(env: &Envelope) -> Result<(), Error> {
    if env.protocol_version != PROTOCOL_VERSION {
        return Err(Error::Serialization(format!(
            "protocol_version {} != {}",
            env.protocol_version, PROTOCOL_VERSION
        )));
    }
    if env.message_version != MESSAGE_VERSION {
        return Err(Error::Serialization(format!(
            "message_version {} != {}",
            env.message_version, MESSAGE_VERSION
        )));
    }
    if env.crypto_suite != CRYPTO_SUITE {
        return Err(Error::Serialization(format!(
            "crypto_suite '{}' != '{CRYPTO_SUITE}'",
            env.crypto_suite
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::{point_mul_base, point_x_bytes, scalar_random, scalar_to_bytes};
    use rand::rngs::OsRng;

    #[test]
    fn envelope_roundtrip_and_version_check() {
        let s = scalar_random(&mut OsRng);
        let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
        let env = Envelope::new(MessageKind::DkgRound1 {
            sender: pk,
            commitments: vec![Commitment(vec![0x02; 33])],
            proof_of_knowledge: hex::encode([0xab; 64]),
        });
        let encoded = encode(&env).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, env);

        assert!(validate_versioning(&decoded).is_ok());
        let mut bad = decoded;
        bad.protocol_version = 99;
        let raw = encode(&bad).unwrap();
        assert!(decode(&raw).is_err());
    }
}
