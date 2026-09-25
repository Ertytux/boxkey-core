# P0-C3 BZ Compliance

**Proyecto:** BoxKey Core (BC)
**Fase:** Fase 1 / P0-C3

---

## Summary

| Norma | Estado | Evidencia |
|---|---|---|
| BZ-0000 Glossary | PASS | NonceHandle, SigningSession, PartialSignature(id\|\|z), todos conformes |
| BZ-0005 Crypto Suites | PASS | `secp256k1-bip340-frost` via frost-core 3.0 + k256 |
| BZ-0010 Serialization | PASS | JSON canónico, hex sin prefijo, camelCase |
| BZ-0011 Error Registry | PASS | Códigos PRO, DKG, FRS, SER, TRN mapeados |
| BZ-0012 Wire Protocol | PASS | Envelope con versionado, checksum, firma |
| BZ-0013 Message Registry | PASS | MessageKind cubre DKG, Nonce, Partial, Aggregate, Reshare |

## BZ-0000 Glossary — PASS

| Término | Implementación |
|---|---|
| BoxKey | `PublicKey` (32 bytes x-only) |
| KeyShare | `Share` (identifier, value, threshold, group_public_key) |
| Nonce | `NonceHandle` (hiding + binding encapsulado, lifecycle) |
| PartialSignature | `PartialSignature([u8; 36])` = id\|\|z |
| AggregateSignature | `SchnorrSignature([u8; 64])` = R\|\|s |
| SigningSession | `SigningSession` con message_hash, group_public_key, threshold, signers |

## BZ-0005 Crypto Suites — PASS

| Requisito | Implementación |
|---|---|
| Curva secp256k1 | `k256` |
| Schnorr BIP340 | `k256::schnorr` |
| FROST RFC 9591 | `frost-core` 3.0 + `frost-secp256k1-tr` 3.0 |
| DKG | `dkg.rs` (Feldman VSS + PoK + ECDH AEAD) |
| Nonces hiding + binding | `frost-core::round1::commit` |

## BZ-0011 Error Registry — PASS

| Código | Variante |
|---|---|
| PRO_0002 | `UnsupportedProtocolVersion` |
| PRO_0003 | `UnsupportedCryptoSuite` |
| PRO_0005 | `InvalidMessageVersion` |
| DKG_0002 | `InvalidCommitment` |
| DKG_0003 | `InvalidProofOfKnowledge` |
| DKG_0004 | `InvalidShare` |
| DKG_0006 | `InconsistentGroup` |
| FRS_0001 | `NonceReuse` |
| FRS_0002 | `InvalidSignature` |
| FRS_0003 | `ThresholdNotMet` |
| FRS_0005 | `VerificationFailed` |
| SER_0003 | `InvalidPublicKey` |
| SER_0006 | `Serialization` |
| SER_0010 | `ChecksumMismatch` |
| TRN_0004 | `InvalidEnvelopeSignature` |

## BZ-0012 Wire Protocol — PASS

Envelope con `protocolVersion`, `cryptoSuite`, `messageVersion`, `payloadVersion`, `connector`, `connectorVersion`. Sin cambios en P0-C3.

## BZ-0013 Message Registry — PASS

`MessageKind` cubre DkgCommitment, DkgShare, NonceExchange, PartialSignature, AggregateSignature, DkgComplete, Reshare. Sin cambios en P0-C3.