//! Tipos de error unificados de BoxKey Core (BC).
//!
//! Los variantes `InvalidCommitment`, `InvalidShare`, `InvalidSignature`,
//! `InvalidProofOfKnowledge`, `ThresholdNotMet`, `NonceReuse` y
//! `VerificationFailed` provienen literalmente de `contratos.md §2`.
//! El resto amplía la cobertura (serialización, claves, aritmética) manteniendo
//! compatibilidad con la interfaz pública definida en la especificación BZ.

use thiserror::Error;

/// Error unificado de todas las operaciones criptográficas de BC.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// Un compromiso es inválido (punto fuera de la curva, índice 0, etc.).
    #[error("compromiso inválido: {0}")]
    InvalidCommitment(#[from] InvalidCommitment),

    /// Una share es inválida (valor fuera de rango, inconsistencia Feldman, etc.).
    #[error("share inválida: {0}")]
    InvalidShare(String),

    /// Una firma (parcial o agregada) es inválida.
    #[error("firma inválida: {0}")]
    InvalidSignature(String),

    /// La prueba de conocimiento del coeficiente libre no verifica.
    #[error("proof of knowledge inválido")]
    InvalidProofOfKnowledge,

    /// No se alcanzó el umbral de participantes/shares.
    #[error("umbral no alcanzado: se requieren {required}, se recibieron {received}")]
    ThresholdNotMet { required: usize, received: usize },

    /// Se detectó reutilización de nonce.
    #[error("reutilización de nonce detectada")]
    NonceReuse,

    /// Una verificación criptográfica falló.
    #[error("verificación fallida")]
    VerificationFailed,

    /// Clave pública inválida.
    #[error("clave pública inválida: {0}")]
    InvalidPublicKey(String),

    /// Clave secreta inválida.
    #[error("clave secreta inválida: {0}")]
    InvalidSecretKey(String),

    /// Escalar fuera del dominio de la curva.
    #[error("escalar inválido: {0}")]
    InvalidScalar(String),

    /// Error de serialización canónica.
    #[error("error de serialización: {0}")]
    Serialization(String),

    /// Error criptográfico general.
    #[error("error criptográfico: {0}")]
    Crypto(String),

    /// Inconsistencia entre entidades del grupo (claves públicas, shares, etc.).
    #[error("inconsistencia de grupo: {0}")]
    InconsistentGroup(String),

    /// La `protocolVersion` del envelope/mensaje no es soportada por BC (BZ-0011 PRO_0002).
    #[error("versión de protocolo no soportada: {version}")]
    UnsupportedProtocolVersion { version: String },

    /// El `cryptoSuite` no está registrado en BZ-0005 o no es soportado (BZ-0011 PRO_0003).
    #[error("crypto suite no soportada: {suite}")]
    UnsupportedCryptoSuite { suite: String },

    /// El `messageVersion` no es compatible con el formato actual (BZ-0011 PRO_0005).
    #[error("versión de mensaje no soportada: {version}")]
    InvalidMessageVersion { version: String },

    /// El checksum canónico del payload no coincide (BZ-0011 SER_0010).
    #[error("checksum canónico no coincide")]
    ChecksumMismatch,

    /// La firma del envelope no verifica (posible manipulación, BZ-0011 TRN_0004).
    #[error("firma de envelope inválida")]
    InvalidEnvelopeSignature,
}

/// Razón concreta de un [`Error::InvalidCommitment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCommitment(pub String);

impl core::fmt::Display for InvalidCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::error::Error for InvalidCommitment {}

impl Error {
    /// Construye un [`Error::InvalidSignature`].
    pub fn invalid_signature(reason: impl Into<String>) -> Self {
        Self::InvalidSignature(reason.into())
    }

    /// Código normativo BZ-0011 asociado a la variante.
    ///
    /// Las variantes cuyo origen no mapea a un código específico del registry
    /// (claves, escalares, fallo criptográfico no clasificado) devuelven el
    /// código genérico de BC `SRV_0009` (`INTERNAL_SERVER_ERROR`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion { .. } => "PRO_0002",
            Self::UnsupportedCryptoSuite { .. } => "PRO_0003",
            Self::InvalidMessageVersion { .. } => "PRO_0005",
            Self::ChecksumMismatch => "SER_0010",
            Self::InvalidEnvelopeSignature => "TRN_0004",
            Self::InvalidCommitment(_) => "DKG_0002",
            Self::InvalidProofOfKnowledge => "DKG_0003",
            Self::InvalidShare(_) => "DKG_0004",
            Self::InconsistentGroup(_) => "DKG_0006",
            Self::NonceReuse => "FRS_0001",
            Self::InvalidSignature(_) => "FRS_0002",
            Self::ThresholdNotMet { .. } => "FRS_0003",
            Self::VerificationFailed => "FRS_0005",
            Self::Serialization(_) => "SER_0006",
            Self::InvalidPublicKey(_) => "SER_0003",
            Self::InvalidSecretKey(_) | Self::InvalidScalar(_) | Self::Crypto(_) => "SRV_0009",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codigos_bz0011_para_variantes_protocolo() {
        assert_eq!(
            Error::UnsupportedProtocolVersion {
                version: "1.0".into()
            }
            .code(),
            "PRO_0002"
        );
        assert_eq!(
            Error::UnsupportedCryptoSuite {
                suite: "BZ-0005-v2".into()
            }
            .code(),
            "PRO_0003"
        );
        assert_eq!(
            Error::InvalidMessageVersion {
                version: "1.0".into()
            }
            .code(),
            "PRO_0005"
        );
    }

    #[test]
    fn codigos_bz0011_para_variantes_serializacion() {
        assert_eq!(Error::ChecksumMismatch.code(), "SER_0010");
        assert_eq!(Error::Serialization("x".into()).code(), "SER_0006");
        assert_eq!(Error::InvalidPublicKey("corta".into()).code(), "SER_0003");
    }

    #[test]
    fn codigos_bz0011_para_variantes_envelope() {
        assert_eq!(Error::InvalidEnvelopeSignature.code(), "TRN_0004");
    }

    #[test]
    fn codigos_bz0011_para_variantes_dkg() {
        assert_eq!(
            Error::InvalidCommitment(InvalidCommitment("punto fuera de la curva".into())).code(),
            "DKG_0002"
        );
        assert_eq!(Error::InvalidProofOfKnowledge.code(), "DKG_0003");
        assert_eq!(
            Error::InvalidShare("fuera de rango".into()).code(),
            "DKG_0004"
        );
        assert_eq!(
            Error::InconsistentGroup("participante malicioso".into()).code(),
            "DKG_0006"
        );
    }

    #[test]
    fn codigos_bz0011_para_variantes_frost() {
        assert_eq!(Error::NonceReuse.code(), "FRS_0001");
        assert_eq!(
            Error::InvalidSignature("parcial no verifica".into()).code(),
            "FRS_0002"
        );
        assert_eq!(
            Error::ThresholdNotMet {
                required: 2,
                received: 1
            }
            .code(),
            "FRS_0003"
        );
        assert_eq!(Error::VerificationFailed.code(), "FRS_0005");
    }

    #[test]
    fn codigo_generico_para_variantes_restantes() {
        assert_eq!(Error::InvalidSecretKey("x".into()).code(), "SRV_0009");
        assert_eq!(Error::InvalidScalar("x".into()).code(), "SRV_0009");
        assert_eq!(Error::Crypto("x".into()).code(), "SRV_0009");
    }
}
