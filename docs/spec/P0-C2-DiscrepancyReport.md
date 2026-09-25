# P0-C2 Discrepancy Report

**Proyecto:** BoxKey Core (BC)
**Protocolo:** BoxKey Protocol (BZ)

---

## Resumen

Esta fase (P0-C2) resolvió las discrepancias detectadas en P0. No se generó `BZ-Change-Request.md` porque ninguna discrepancia requirió modificación normativa de BZ.

## Discrepancias detectadas y resueltas

### D-1: `PartialSignature` transportaba datos redundantes

**BZ:** `PartialSignature` = `id || z` (BZ-0000, BZ-0013).

**Implementación previa:** `PartialSignature` transportaba `id || D || E || Y || z` (135 bytes), reconstruyendo el contexto FROST desde datos redundantes de cada firma.

**Resolución:** `PartialSignature` ahora es `[u8; 36]` = `id(4) || z(32)`. El contexto (D, E, Y, group key, threshold, message hash) se mantiene en `SigningSession`.

**Tipo de solución:** A — solución compatible con BZ.

### D-2: `sign_partial` generaba un nonce nuevo

**BZ:** El nonce firmado debe coincidir con el commitment anunciado (RFC 9591 §4).

**Implementación previa:** `BoxKeyCore::sign_partial` generaba nonces nuevos internamente (`api.rs`), ignorando el commitment de `generate_nonces`.

**Resolución:** `sign_partial` ahora consume el `NonceHandle` generado por `generate_nonces`. Es imposible firmar con un nonce distinto al comprometido.

**Tipo de solución:** A — solución compatible con BZ.

### D-3: Nonce expuesto como `Vec<u8>`

**BZ-0000:** Nonce es secreto, MUST destruirse tras uso, MUST NOT reutilizarse.

**Implementación previa:** `generate_nonces` retornaba `(Vec<u8>, Commitment)` exponiendo el secreto como bytes planos, sin lifecycle.

**Resolución:** `NonceHandle` encapsula el secreto con `Zeroizing`, `consume()` (uso único) y `Drop` que zeroiza.

**Tipo de solución:** A — solución compatible con BZ.

### D-4: `SecretKey` sin zeroization

**BZ-0000:** KeyShare/SecretKey son secretos, MUST cifrarse en reposo.

**Implementación previa:** `SecretKey(pub [u8; 32])` sin `Drop` zeroize.

**Resolución:** `Drop::drop` zeroiza los 32 bytes.

**Tipo de solución:** A — solución compatible con BZ.

### D-5: Vectores regenerados por `cargo test`

**BZ-0010:** Los vectores de prueba deben ser reproducibles.

**Implementación previa:** `tests/vector_generation.rs` escribía `tests/vectors/*.json` durante `cargo test` usando OsRng (no reproducible).

**Resolución:** Separación:
- `src/bin/generate_vectors.rs` (binario opcional)
- `tests/vector_verification.rs` (solo lee fixtures)

**Tipo de solución:** A — solución compatible con BZ.

### D-6: Sin verificador independiente

**BZ:** No se especifica explícitamente, pero el protocolo requiere verificación criptográfica robusta.

**Implementación previa:** BC generaba y verificaba sus propios vectores (mismo path de código).

**Resolución:** `tests/vector_verification.rs::vector_verification_via_independent_k256` verifica el vector contra `k256::schnorr` directamente.

**Tipo de solución:** A — solución compatible con BZ.

---

## Discrepancias no resueltas

Ninguna.

## Estado de BZ

No se modificó ningún documento BZ durante P0-C2. No se emitió `BZ-Change-Request.md`.