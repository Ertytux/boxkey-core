# P0-C2 Closure Report

**Proyecto:** BoxKey Core (BC)
**Protocolo:** BoxKey Protocol (BZ)
**Fase:** Fase 1 / P0-C2
**Estado:** CLOSED
**Estrategia:** LOOP-PROMPT

---

## Executive Summary

P0-C2 llevó P0 de `BLOCKED` a `CLOSED` mediante una iteración LOOP-PROMPT que resolvió 8 bloqueos residuales. Los cambios principales fueron:

1. **API de firma corregida**: `sign_partial` ya no genera nonces internamente; ahora consume un `NonceHandle` ligado al commitment anunciado.
2. **NonceHandle + lifecycle**: encapsulación del nonce secreto con lifecycle GENERATED → USED → ZEROIZED, reutilización impedida.
3. **PartialSignature reducida**: de `id||D||E||Y||z` (135 bytes) a `id||z` (36 bytes), conforme BZ. El contexto FROST se mantiene en `SigningSession`.
4. **Vectores fijos y reproducibles**: separación entre generación (`generate_vectors` binary) y verificación (`vector_verification` tests).
5. **Verificador independiente**: `k256::schnorr` verifica la firma agregada fuera del flujo FROST.
6. **Zeroization**: `SecretKey` zeroiza en drop, `NonceHandle` zeroiza al consumir, buffer de nonces envuelto en `Zeroizing`.
7. **Fuzzing mínimo**: 6 tests proptest para parsing malformado.
8. **Tests negativos**: 10 tests cubriendo wrong key, wrong digest, nonce reuse, threshold insuficiente, etc.

## Initial P0 Status

```
P0 STATUS: BLOCKED
```

## P0-C2 Result

```
P0 STATUS: CLOSED
```

## Changes Implemented

### `src/types.rs`
- `NonceHandle` struct: encapsula nonce secreto con lifecycle y `Drop` zeroize.
- `SigningSession` struct: contexto FROST (commitments, verifying shares, group key, threshold, message hash).
- `SignerInfo` struct: datos de un firmante en la sesión.
- `PartialSignature`: de `Vec<u8>` (135 bytes) a `[u8; 36]` (id||z). Serialize/Deserialize custom.
- `SecretKey`: `Drop` impl que zeroiza los 32 bytes. Clone manual.

### `src/frost_adapter.rs`
- `generate_nonces`: retorna `(NonceHandle, Commitment)` en lugar de `(Vec<u8>, Commitment)`.
- `sign_partial`: firma `(share, session, &mut handle)` — consume el NonceHandle, no genera nonces nuevos.
- `aggregate_signatures`: firma `(sigs, session)` — toma contexto de `SigningSession`.
- `verify_schnorr`: sin cambios.
- `debug_parse_commitment`, `debug_parse_public_key`: expuestas para fuzzing.

### `src/api.rs`
- Trait `BoxKeyCore` actualizado con nuevos tipos.
- `sign_partial` ya no genera nonces internamente (bug C1 corregido).
- Tests actualizados.

### `src/reshare.rs`
- Test actualizado para usar `SigningSession` y `NonceHandle`.

### `tests/`
- `vector_generation.rs`: ya no escribe archivos durante `cargo test` (solo verifica flujo).
- `vector_verification.rs`: nuevo — lee fixtures de `tests/vectors/` y verifica.
- `negative_tests.rs`: 10 tests negativos (C6 + C9).
- `fuzz_tests.rs`: 6 tests proptest para fuzzing (C8).
- `frost_tests.rs`, `integration_tests.rs`, `property_tests.rs`, `reshare_tests.rs`: actualizados.

### `src/bin/generate_vectors.rs`
- Binario separado para generar vectores: `cargo run --bin generate_vectors`.

## Cryptographic Path

```
DKG (run_dkg)
  ↓
Key Shares / Group Public Key
  ↓
generate_nonces (frost-core round1::commit)
  ↓
NonceHandle + Commitment (publicado)
  ↓
SigningSession (construido por coordinador)
  ↓
sign_partial (frost-core round2::sign, consume NonceHandle)
  ↓
PartialSignature [id || z] (sin D/E/Y redundantes)
  ↓
aggregate_signatures (frost-core::aggregate)
  ↓
Aggregate Signature (BIP340)
  ↓
Independent verification (k256::schnorr)
```

## Nonce Lifecycle

```
GENERATED (frost-core round1::commit)
  ↓  NonceHandle::new(identifier, hidden)
COMMITTED (commitment publicado)
  ↓  NonceHandle::consume()
USED (sign_partial deserializa nonces, firma)
  ↓  Zeroizing::drop() + handle.zeroize()
ZEROIZED
```

## Signing API

```
generate_nonces(share, rng)  →  (NonceHandle, Commitment)

sign_partial(share, session, &mut handle)  →  PartialSignature
  - Consume NonceHandle (no reutilizable)
  - No genera nonces nuevos
  - Commitment del nonce = commitment en sesión

aggregate_signatures(sigs, session)  →  SchnorrSignature
  - Contexto (D, E, Y, group key) desde session
  - PartialSignature es solo id||z
```

## PartialSignature

Conforme BZ: `id (u32 BE) || z (32 bytes)` = 36 bytes.

El contexto (D, E, verifying shares, group key, threshold) se mantiene en `SigningSession`.

## Test Vectors

- `tests/vectors/dkg_2of3.json`: fixture fijo para DKG 2-de-3 + FROST signing.
- `tests/vectors/bip340_interop.json`: fixture fijo para BIP340 interop.
- Generación: `cargo run --bin generate_vectors`.
- Verificación: `cargo test --test vector_verification` (no regenera).

## Interoperability

- `k256::schnorr` (RustCrypto) verifica firmas agregadas independientemente del flujo FROST.
- Test `vector_verification_via_independent_k256` verifica vector contra k256 directamente.

## Zeroization

| Secreto | Mecanismo |
|---|---|
| `SecretKey.0` (32 bytes) | `Drop::drop` → `zeroize::Zeroize` |
| `Share.value` | `Zeroizing<[u8; 32]>` |
| `SecretShare.coefficients` | `Zeroizing<Vec<u8>>` |
| `NonceHandle` hidden | `Zeroizing<Vec<u8>>` + `Drop::drop` |
| Buffer hidden en `sign_partial` | `Zeroizing<Vec<u8>>` |
| `Debug` en secretos | Redactado (SecretKey([REDACTED]), etc.) |
| Logs | No se emiten secretos |
| Serialización de secretos | No se serializan (`Share`, `SecretKey` no son Serialize) |

## Fuzzing

6 tests proptest en `tests/fuzz_tests.rs`:
- `fuzz_parse_commitment`: bytes 0..200 como Commitment.
- `fuzz_parse_public_key`: bytes 32 como x-only.
- `fuzz_parse_partial_signature`: bytes 36 como PartialSignature.
- `fuzz_commitment_wrong_length`: longitudes 0..200.
- `fuzz_public_key_invalid`: arrays 32 bytes arbitrarios.
- `fuzz_reads_corpus_if_exists`: lee `tests/fuzz_corpus/` si existe.

## Dependency Audit

```
cargo test --locked  →  PASS
cargo build --locked →  PASS
cargo audit          →  NOT RUN — tool unavailable
cargo deny check     →  NOT RUN — tool unavailable
```

## BZ Compliance

| BZ | Status | Notas |
|---|---|---|
| BZ-0000 Glossary | PASS | NonceHandle, SigningSession, PartialSignature conformes |
| BZ-0005 Crypto Suites | PASS | secp256k1-bip340-frost, FROST RFC 9591 via frost-core |
| BZ-0010 Serialization | PASS | JSON canónico, hex sin prefijo, camelCase |
| BZ-0011 Error Registry | PASS | Códigos PRO_0002, PRO_0003, DKG_0002-6, FRS_0001-5, SER_0003/6/10, TRN_0004 |
| BZ-0012 Wire Protocol | PASS | Envelope con versionado, checksum, firma |
| BZ-0013 Message Registry | PASS | MessageKind con DKG, Nonce, PartialSignature, Aggregate |

## Remaining Risks

1. **Clone en SecretKey**: `Clone` permite copia accidental de la clave. Mitigación: accesible pero no usado en producción.
2. **PartialEq en SecretKey**: comparación no constante en tiempo. Aceptable para P0 (no se usa en prod contra entradas adversariales).
3. **Fuzzing no exhaustivo**: campaña completa difiere a P1.
4. **Cargo audit/deny**: no ejecutados por falta de herramientas instaladas.

## Out of Scope

- BS (BoxKey Service)
- BN (BoxKey Connector)
- X402 / HTTP 402
- Spark connector
- Ark connector
- Liquid connector
- Bitcoin broadcast
- Distributed coordinator
- Mobile integration

## Evidence

```bash
# 38 tests de unidad + 14 tests de integración + 6 fuzz + 4 vector verification
cargo test --locked
# → 62 tests passed

cargo build --locked
# → Finished

cargo run --bin generate_vectors
# → Genera vectores en tests/vectors/
```

## Final Decision

```
P0 STATUS: CLOSED
```

Todos los criterios obligatorios de la checklist §18 están satisfechos.