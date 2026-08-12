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
}
