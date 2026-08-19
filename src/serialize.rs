//! Serialización canónica de los mensajes del protocolo (BZ-0010/0012/0013).
//!
//! Toda comunicación externa (con el coordinador BS y entre participantes)
//! viaja en un [`Envelope`] conforme a BZ-0012: `protocolVersion`,
//! `cryptoSuite`, `messageVersion` y `payloadVersion` como strings, más los
//! campos BC-scoped `connector` y `connectorVersion` (Anexo A).
//!
//! **Sin campos de dominio** (`boxId`, `sessionId`, `sender`, `recipient`,
//! `correlationId`, `timestamp`, `nonce`): el dominio (sesiones, routing,
//! anti-replay) es competencia exclusiva de BS según `dominio.md`. BC solo
//! emite/reconoce los DTOs criptográficos y sus envelopes autocontenidos.
//!
//! Los materiales secretos (`Share`, `SecretShare`, `SecretKey`) NUNCA se
//! serializan: solo existen DTOs públicos (claves, compromisos, firmas).
//!
//! Formato: JSON canónico (`serde_json`), claves ordenadas lexicográficamente
//! para checksum y firma (BZ-0010 §3.4).

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::schnorr::{schnorr_sign_bytes, verify_bip340};
use crate::types::{
    Commitment, EncryptedShare, PartialSignature, PublicKey, SchnorrSignature, SecretKey,
};

/// `protocolVersion` de la capa BC (BZ-0012 §4.1, SemVer MAJOR.MINOR).
pub const PROTOCOL_VERSION: &str = "1.0";
/// `cryptoSuite` del motor criptográfico (BZ-0005).
pub const CRYPTO_SUITE: &str = "secp256k1-bip340-frost";
/// `messageVersion` de los mensajes serializados.
pub const MESSAGE_VERSION: &str = "1";
/// `payloadVersion` semántico de los DTOs.
pub const PAYLOAD_VERSION: &str = "1";
/// Identificador del conector BC (Anexo A).
pub const CONNECTOR: &str = "boxkey-core";
/// Versión del conector (BC) — aquí el propio crate.
pub const CONNECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tipos de mensaje BZ-0013 que BC emite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// Ronda 1 del DKG: compromisos de Feldman + PoK del coeficiente libre.
    DkgCommitment,
    /// Ronda 2 del DKG: shares cifradas para cada destinatario.
    DkgShare,
    /// Compromiso de nonces de una firma FROST.
    NonceExchange,
    /// Firma parcial de un round FROST.
    PartialSignature,
    /// Firma Schnorr agregada lista para broadcast.
    AggregateSignature,
    /// Comunicar que el DKG finalizó y la clave pública está disponible.
    DkgComplete,
    /// Redistribución de contribuciones hacia un nuevo grupo.
    Reshare,
}

/// Sobre de mensaje conforme BZ-0012 (camelCase en el wire).
///
/// Los campos de routing del dominio (BZ-0012 §4.1) quedan fuera de BC:
/// los rellena BS en la capa de transporte. BC emite el envelope autocontenido
/// y firmable que BS inserta como payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    /// Versión del protocolo BZ, SemVer MAJOR.MINOR (BZ-0012 §4.1).
    pub protocol_version: String,
    /// Suite criptográfica (BZ-0005).
    pub crypto_suite: String,
    /// Versión del formato de este mensaje.
    pub message_version: String,
    /// Versión del payload semántico.
    pub payload_version: String,
    /// Conector emisor (Anexo A).
    pub connector: String,
    /// Versión del conector emisor (Anexo A).
    pub connector_version: String,
    /// Tipo de mensaje registrado en BZ-0013.
    pub message_type: MessageType,
    /// DTOs criptográficos.
    #[serde(flatten)]
    pub payload: MessageKind,
}

/// Mensajes del protocolo entre los actores de la capa de firma distribuida
/// (DTOs de BZ-0013, camelCase en el wire).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum MessageKind {
    /// `dkg_commitment` (BZ-0013 §5.1): compromisos de Feldman + PoK.
    DkgCommitment {
        sender: PublicKey,
        commitments: Vec<Commitment>,
        proof_of_knowledge: String,
    },
    /// `dkg_share` (BZ-0013 §5.2): shares cifradas para cada destinatario.
    DkgShare {
        sender: PublicKey,
        shares: Vec<EncryptedShare>,
    },
    /// `nonce_exchange` (BZ-0013 §6.2): compromiso de nonces (hiding + binding).
    NonceExchange {
        signer: PublicKey,
        commitment: Commitment,
    },
    /// `partial_signature` (BZ-0013 §6.3): firma parcial.
    PartialSignature {
        sender: PublicKey,
        signature: PartialSignature,
    },
    /// `aggregate_signature` (BZ-0013 §6.4): firma agregada final.
    AggregateSignature {
        message_hash: String,
        signature: SchnorrSignature,
    },
    /// `dkg_complete` (BZ-0013 §5.3): clave pública del grupo disponible.
    DkgComplete {
        public_key: PublicKey,
        threshold: u8,
        participants: u8,
    },
    /// `reshare` (BZ-0013 §8.2): contribuciones hacia un nuevo grupo.
    Reshare {
        contributor: PublicKey,
        contributions: Vec<EncryptedShare>,
    },
}

impl Envelope {
    /// Construye un sobre con el versionado canónico de BC.
    pub fn new(payload: MessageKind) -> Self {
        let message_type = match &payload {
            MessageKind::DkgCommitment { .. } => MessageType::DkgCommitment,
            MessageKind::DkgShare { .. } => MessageType::DkgShare,
            MessageKind::NonceExchange { .. } => MessageType::NonceExchange,
            MessageKind::PartialSignature { .. } => MessageType::PartialSignature,
            MessageKind::AggregateSignature { .. } => MessageType::AggregateSignature,
            MessageKind::DkgComplete { .. } => MessageType::DkgComplete,
            MessageKind::Reshare { .. } => MessageType::Reshare,
        };
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            crypto_suite: CRYPTO_SUITE.to_string(),
            message_version: MESSAGE_VERSION.to_string(),
            payload_version: PAYLOAD_VERSION.to_string(),
            connector: CONNECTOR.to_string(),
            connector_version: CONNECTOR_VERSION.to_string(),
            message_type,
            payload,
        }
    }

    /// Serializa el sobre a JSON compacto (camelCase, hex sin prefijo).
    pub fn encode(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::Serialization(format!("encode json: {e}")))
    }

    /// Deserializa un sobre y valida los campos de versionado (BZ-0012 W3/W4).
    pub fn decode(raw: &str) -> Result<Envelope, Error> {
        let env: Envelope = serde_json::from_str(raw)
            .map_err(|e| Error::Serialization(format!("decode json: {e}")))?;
        validate_versioning(&env)?;
        Ok(env)
    }

    /// Comprueba compatibilidad de versionado (BZ-0012 §9).
    ///
    /// - `protocolVersion` no soportada → `PRO_0002`.
    /// - `cryptoSuite` no soportada → `PRO_0003`.
    /// - `messageVersion` no soportada → `PRO_0005`.
    pub fn validate(&self) -> Result<(), Error> {
        validate_versioning(self)
    }

    /// Checksum SHA-256 del canonical encoding del envelope (BZ-0012 §6.1).
    pub fn checksum(&self) -> Result<String, Error> {
        use sha2::{Digest, Sha256};
        let canon = canonical_json(&self.to_json()?);
        let digest = Sha256::digest(canon.as_bytes());
        Ok(hex::encode(digest))
    }

    /// Firma Schnorr BIP340 del canonical encoding (BZ-0012 §6.2).
    ///
    /// El canonical encoding se reduce a SHA-256 (32 bytes) antes de firmar,
    /// conforme a la entrada de mensaje de BIP340.
    pub fn sign(&self, key: &SecretKey) -> Result<String, Error> {
        use sha2::{Digest, Sha256};
        let canon = canonical_json(&self.to_json()?);
        let digest = Sha256::digest(canon.as_bytes());
        let sig = schnorr_sign_bytes(&key.0, &digest.into())?;
        Ok(hex::encode(sig))
    }

    /// Verifica la firma BIP340 del emisor (BZ-0012 §6.2).
    pub fn verify(&self, pubkey: &PublicKey, signature: &str) -> Result<(), Error> {
        use sha2::{Digest, Sha256};
        let canon = canonical_json(&self.to_json()?);
        let digest = Sha256::digest(canon.as_bytes());
        let sig = hex::decode(signature)
            .map_err(|e| Error::Serialization(format!("firma no es hex: {e}")))?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| Error::InvalidEnvelopeSignature)?;
        verify_bip340(&sig, &pubkey.0, &digest.into()).map_err(|_| Error::InvalidEnvelopeSignature)
    }

    fn to_json(&self) -> Result<serde_json::Value, Error> {
        let raw = self
            .encode()
            .map_err(|e| Error::Serialization(format!("canonical json: {e}")))?;
        serde_json::from_str(&raw).map_err(|e| Error::Serialization(format!("canonical json: {e}")))
    }
}

/// Canonical encoding conforme BZ-0010 §3.4: claves ordenadas lexicográficamente
/// por codepoint UTF-8 (recursivo), sin espacios, hex minúsculas sin `0x`.
pub fn canonical_json(value: &serde_json::Value) -> String {
    fn canon(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => {
                format!("\"{}\"", s)
            }
            serde_json::Value::Array(items) => {
                let inner: Vec<String> = items.iter().map(canon).collect();
                format!("[{}]", inner.join(","))
            }
            serde_json::Value::Object(map) => {
                let mut entries: Vec<(String, String)> =
                    map.iter().map(|(k, v)| (k.clone(), canon(v))).collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                let inner: Vec<String> = entries
                    .iter()
                    .map(|(k, v)| format!("\"{k}\":{v}"))
                    .collect();
                format!("{{{}}}", inner.join(","))
            }
        }
    }
    canon(value)
}

/// Comprueba compatibilidad de versionado (BZ-0012 §9, Anexo A).
pub fn validate_versioning(env: &Envelope) -> Result<(), Error> {
    if env.protocol_version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedProtocolVersion {
            version: env.protocol_version.clone(),
        });
    }
    if env.message_version != MESSAGE_VERSION {
        return Err(Error::InvalidMessageVersion {
            version: env.message_version.clone(),
        });
    }
    if env.crypto_suite != CRYPTO_SUITE {
        return Err(Error::UnsupportedCryptoSuite {
            suite: env.crypto_suite.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::{point_mul_base, point_x_bytes, scalar_random};
    use rand::rngs::OsRng;

    #[test]
    fn envelope_roundtrip_and_version_check() {
        let s = scalar_random(&mut OsRng);
        let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
        let env = Envelope::new(MessageKind::DkgCommitment {
            sender: pk,
            commitments: vec![Commitment(vec![0x02; 33])],
            proof_of_knowledge: hex::encode([0xab; 64]),
        });
        let encoded = env.encode().unwrap();
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);

        assert!(decoded.validate().is_ok());
        let mut bad = decoded;
        bad.protocol_version = "99.0".to_string();
        let raw = bad.encode().unwrap();
        assert!(Envelope::decode(&raw).is_err());
        assert_eq!(bad.validate().unwrap_err().code(), "PRO_0002");
    }

    #[test]
    fn wire_uses_camel_case_and_string_versions() {
        let s = scalar_random(&mut OsRng);
        let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
        let env = Envelope::new(MessageKind::DkgCommitment {
            sender: pk,
            commitments: vec![Commitment(vec![0x02; 33])],
            proof_of_knowledge: hex::encode([0xab; 64]),
        });
        let encoded = env.encode().unwrap();
        assert!(encoded.contains("\"protocolVersion\":\"1.0\""), "{encoded}");
        assert!(
            encoded.contains("\"cryptoSuite\":\"secp256k1-bip340-frost\""),
            "{encoded}"
        );
        assert!(
            encoded.contains("\"messageType\":\"dkg_commitment\""),
            "{encoded}"
        );
        assert!(
            encoded.contains("\"connector\":\"boxkey-core\""),
            "{encoded}"
        );
        assert!(!encoded.contains("protocol_version"), "{encoded}");
        assert!(!encoded.contains("0x"), "{encoded}");
    }

    #[test]
    fn canonical_json_orders_keys() {
        let v: serde_json::Value = serde_json::json!({
            "b": 2,
            "a": {"d": 4, "c": 3},
            "z": [1, 2]
        });
        assert_eq!(
            canonical_json(&v),
            "{\"a\":{\"c\":3,\"d\":4},\"b\":2,\"z\":[1,2]}"
        );
    }

    #[test]
    fn checksum_changes_with_payload() {
        let s = scalar_random(&mut OsRng);
        let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
        let env = Envelope::new(MessageKind::DkgComplete {
            public_key: pk,
            threshold: 2,
            participants: 3,
        });
        let c1 = env.checksum().unwrap();
        let mut tampered = env.clone();
        tampered.payload_version = "2".to_string();
        let c2 = tampered.checksum().unwrap();
        assert_ne!(c1, c2);
        assert_eq!(c1.len(), 64, "checksum es SHA-256 hex (64 chars)");
    }

    #[test]
    fn signature_verifies_and_rejects_tampering() {
        use crate::secp256k1::{scalar_to_bytes, secret_key_random};
        let sk = secret_key_random();
        let pk = PublicKey(point_x_bytes(&point_mul_base(&sk)));
        let env = Envelope::new(MessageKind::DkgShare {
            sender: pk,
            shares: vec![EncryptedShare {
                recipient: pk,
                ciphertext: vec![0x33; 64],
            }],
        });
        let sig = env.sign(&SecretKey(scalar_to_bytes(&sk))).unwrap();
        assert!(env.verify(&pk, &sig).is_ok());

        let mut tampered = env.clone();
        tampered.message_version = "2".to_string();
        assert!(tampered.verify(&pk, &sig).is_err());
        assert!(env.verify(&pk, "deadbeef").is_err());
    }

    #[test]
    fn message_kind_type_tag_matches_header() {
        let s = scalar_random(&mut OsRng);
        let pk = PublicKey(point_x_bytes(&point_mul_base(&s)));
        let env = Envelope::new(MessageKind::NonceExchange {
            signer: pk,
            commitment: Commitment(vec![0x02; 70]),
        });
        let encoded = env.encode().unwrap();
        assert!(encoded.contains("\"type\":\"nonceExchange\""), "{encoded}");
        let v: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(v["messageType"], "nonce_exchange");
        assert_eq!(v["type"], "nonceExchange");
    }
}
