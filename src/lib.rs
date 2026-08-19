//! BoxKey Core (BC) — biblioteca criptográfica central del protocolo BoxKey.
//!
//! Capa de firma distribuida (t-de-n) sin custodio: ningún participante posee
//! la clave privada completa del BoxKey; la clave pública emerge solo vía DKG
//! y las firmas se completan cooperativamente con FROST.
//!
//! Módulos:
//! - [`api`] — capa conforme a `contratos.md §2` (interfaz pública primaria).
//! - [`dkg`] — generación distribuida de claves (Feldman VSS + ECDH).
//! - [`frost`] — firma Schnorr distribuida (RFC 9591) sobre `secp256k1`.
//! - [`schnorr`] — Schnorr BIP340 (motor `k256` + oráculo `secp256k1`).
//! - [`secp256k1`] — aritmética de curva (primitivos internos).
//! - [`reshare`] — redistribución de un BoxKey a un nuevo grupo.
//! - [`serialize`] — envelopes BC-scoped (BZ-0012/0013).
//! - [`types`] y [`error`] — tipos públicos y errores unificados.
//!
//! La interfaz pública primaria es [`api::BoxKeyCore`] (trait) y
//! [`api::BoxKeyCoreImpl`]. El motor avanzado (DKG/FROST/reshare) queda
//! expuesto para integraciones que requieran control fino.

pub mod api;
pub mod dkg;
pub mod error;
pub mod frost;
pub mod reshare;
pub mod schnorr;
pub mod secp256k1;
pub mod serialize;
pub mod types;

pub use api::{BoxKeyCore, BoxKeyCoreImpl, DEFAULT_NONCE_MSG};
pub use dkg::{
    combine_shares, compute_commitments, derive_partial_public_key, derive_public_key,
    encrypt_payload, generate_participant_key, generate_proof_of_knowledge, generate_secret,
    generate_shares, run_dkg, secret_from_share, secret_with_threshold, verify_and_decrypt_share,
    verify_commitments, verify_share,
};
pub use error::{Error, InvalidCommitment};
pub use frost::{
    aggregate_signatures, generate_nonces, sign_partial, verify_partial, verify_schnorr,
    SignerInfo, SigningRound,
};
pub use reshare::{
    combine_redistributed_shares, redistribute_one, verify_and_decrypt_redistributed,
    verify_redistributed_share,
};
pub use serialize::{canonical_json, validate_versioning, Envelope, MessageKind, MessageType};
pub use types::{
    Commitment, EncryptedShare, PartialSignature, PublicKey, SchnorrSignature, SecretKey,
    SecretShare, Share,
};
