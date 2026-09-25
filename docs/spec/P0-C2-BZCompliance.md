# P0-C2 BZ Compliance

**Proyecto:** BoxKey Core (BC)
**Protocolo:** BoxKey Protocol (BZ)

---

## Resumen

| BZ | Estado | Notas |
|---|---|---|
| BZ-0000 Glossary | PASS | Todos los tipos definidos: BoxKey, KeyShare, Commitment, Nonce, PartialSignature, AggregateSignature, SigningSession |
| BZ-0005 Crypto Suites | PASS | Suite `secp256k1-bip340-frost` implementada vía frost-core 3.0 + k256 |
| BZ-0010 Serialization | PASS | JSON canónico, hex minúsculas sin `0x`, camelCase, claves ordenadas |
| BZ-0011 Error Registry | PASS | Códigos PRO_0002, PRO_0003, PRO_0005, DKG_0002-4, DKG_0006, FRS_0001-3, FRS_0005, SER_0003, SER_0006, SER_0010, TRN_0004 |
| BZ-0012 Wire Protocol | PASS | Envelope con protocolVersion, cryptoSuite, messageVersion, payloadVersion, connector, messageType + payload |
| BZ-0013 Message Registry | PASS | MessageKind cubre DkgCommitment, DkgShare, NonceExchange, PartialSignature, AggregateSignature, DkgComplete, Reshare |

---

## BZ-0000 Glossary — PASS

| Término | Implementación | Estado |
|---|---|---|
| BoxKey | `PublicKey` (32 bytes x-only) | ✓ |
| KeyShare | `Share` (identifier, value, threshold, group_public_key) | ✓ |
| SecretShare | `SecretShare` (coefficients, threshold, total_participants) | ✓ |
| Commitment | `Commitment` (DKG: 33 bytes, FROST: 70 bytes) | ✓ |
| Nonce | `NonceHandle` (hiding + binding encapsulado) | ✓ |
| PartialSignature | `PartialSignature([u8; 36])` = id\|z | ✓ |
| AggregateSignature | `SchnorrSignature([u8; 64])` = R\|s | ✓ |
| SigningSession | `SigningSession` con message_hash, group_public_key, threshold, signers | ✓ |

## BZ-0005 Crypto Suites — PASS

| Requisito | Implementación | Estado |
|---|---|---|
| Curva secp256k1 | `k256` | ✓ |
| Schnorr BIP340 | `k256::schnorr` | ✓ |
| FROST RFC 9591 | `frost-core` 3.0 + `frost-secp256k1-tr` 3.0 | ✓ |
| DKG Gennaro | `dkg.rs` (Feldman VSS + PoK Schnorr + ECDH AEAD) | ✓ |
| Formato firma 64 bytes | `SchnorrSignature([u8; 64])` | ✓ |
| Clave x-only 32 bytes | `PublicKey([u8; 32])` | ✓ |
| Nonces hiding + binding | `frost-core::round1::commit` | ✓ |
| Challenge tag BIP0340/challenge | `k256::schnorr::verify_raw` | ✓ |

## BZ-0010 Serialization — PASS

| Requisito | Implementación | Estado |
|---|---|---|
| JSON canónico | `serialize.rs::canonical_json` | ✓ |
| Hex minúsculas sin `0x` | `serde_hex_array`, `serde_hex_vec` | ✓ |
| Tolerancia `0x` en entrada | `strip_prefix("0x")` | ✓ |
| Claves ordenadas lexicográficamente | `canonical_json` ordena | ✓ |
| camelCase en wire | `#[serde(rename_all = "camelCase")]` | ✓ |

## BZ-0011 Error Registry — PASS

| Código | Variante Error | Estado |
|---|---|---|
| PRO_0002 | `UnsupportedProtocolVersion` | ✓ |
| PRO_0003 | `UnsupportedCryptoSuite` | ✓ |
| PRO_0005 | `InvalidMessageVersion` | ✓ |
| DKG_0002 | `InvalidCommitment` | ✓ |
| DKG_0003 | `InvalidProofOfKnowledge` | ✓ |
| DKG_0004 | `InvalidShare` | ✓ |
| DKG_0006 | `InconsistentGroup` | ✓ |
| FRS_0001 | `NonceReuse` | ✓ |
| FRS_0002 | `InvalidSignature` | ✓ |
| FRS_0003 | `ThresholdNotMet` | ✓ |
| FRS_0005 | `VerificationFailed` | ✓ |
| SER_0003 | `InvalidPublicKey` | ✓ |
| SER_0006 | `Serialization` | ✓ |
| SER_0010 | `ChecksumMismatch` | ✓ |
| TRN_0004 | `InvalidEnvelopeSignature` | ✓ |

## BZ-0012 Wire Protocol — PASS

| Requisito | Implementación | Estado |
|---|---|---|
| Envelope con versionado | `Envelope` struct | ✓ |
| protocolVersion | `PROTOCOL_VERSION = "1.0"` | ✓ |
| cryptoSuite | `CRYPTO_SUITE = "secp256k1-bip340-frost"` | ✓ |
| messageVersion | `MESSAGE_VERSION = "1"` | ✓ |
| payloadVersion | `PAYLOAD_VERSION = "1"` | ✓ |
| connector | `CONNECTOR = "boxkey-core"` | ✓ |
| connectorVersion | `CONNECTOR_VERSION = env!("CARGO_PKG_VERSION")` | ✓ |
| Checksum SHA-256 | `Envelope::checksum()` | ✓ |
| Firma Schnorr | `Envelope::sign()`, `Envelope::verify()` | ✓ |
| Validación versionado | `validate_versioning()` | ✓ |

## BZ-0013 Message Registry — PASS

| messageType | MessageKind variant | Estado |
|---|---|---|
| dkg_commitment | `DkgCommitment` | ✓ |
| dkg_share | `DkgShare` | ✓ |
| dkg_complete | `DkgComplete` | ✓ |
| nonce_exchange | `NonceExchange` | ✓ |
| partial_signature | `PartialSignature` | ✓ |
| aggregate_signature | `AggregateSignature` | ✓ |
| reshare | `Reshare` | ✓ |

## Discrepancias

No hay discrepancias no resueltas entre BZ y la implementación actual de BC P0.