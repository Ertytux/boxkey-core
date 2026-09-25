# P0-C3 Test Evidence

**Proyecto:** BoxKey Core (BC)
**Fase:** Fase 1 / P0-C3

---

## Environment

| Atributo | Valor |
|---|---|
| Rust version | `rustc 1.83.0` |
| Cargo version | `cargo 1.83.0` |
| Target | `x86_64-unknown-linux-gnu` |
| Lock state | `Cargo.lock` versionado |

## Commands

```
$ cargo test --locked
→ 59 tests passed, 0 failed

$ cargo build --locked
→ Finished (7 dead-code warnings, same as P0-C2)

$ cargo build --locked --manifest-path pyo3/Cargo.toml
→ Finished

$ maturin develop --release
→ Installed boxkey-py-1.0.0
```

## PyO3

| Comando | Resultado |
|---|---|
| `cargo build --locked --manifest-path pyo3/Cargo.toml` | PASS |
| `maturin develop --release` | PASS |

## Test suites

### Core Rust (27 lib tests + 32 integration = 59 total)

| Test file | Tests | Coverage |
|---|---|---|
| `lib target` | 27 | unitarios, DKG, FROST, serialización, errores |
| `dkg_tests.rs` | 2 | DKG negativo |
| `frost_tests.rs` | 2 | FROST signing |
| `fuzz_tests.rs` | 6 | fuzzing proptest |
| `integration_tests.rs` | 2 | flujo completo + envelope |
| `negative_tests.rs` | 11 | C6, C9 + wrong_share_nonce_handle |
| `property_tests.rs` | 2 | proptest |
| `reshare_tests.rs` | 1 | resharing |
| `vector_generation.rs` | 2 | flow check (no escribe) |
| `vector_verification.rs` | 4 | fixtures fijos |

### Tests negativos (C9 + C5)

| Test | Escenario | Resultado |
|---|---|---|
| `wrong_group_public_key_rechazado` | Firma grupo A, verifica grupo B | PASS |
| `wrong_participant_id_rechazado` | ID en commitment no coincide | PASS |
| `insufficient_threshold_rechazado` | 1 firma para threshold 2 | PASS |
| `nonce_reuse_detectado` | Misma firma aportada dos veces | PASS |
| `invalid_bip340_signature_rechazada` | Firma agregada manipulada | PASS |
| `nonce_handle_consumido_no_reutilizable` | Handle consumido, segundo uso falla | PASS |
| `missing_signer_rechazado` | 2 firmas de 3 en sesión | PASS |
| `correct_digest_verifica` | C6: digest correcto | PASS |
| `wrong_digest_rechazado` | C6: digest incorrecto | PASS |
| `double_hash_detectado` | C6: double-hashing | PASS |
| `wrong_share_nonce_handle_is_rejected` | Share(A) + Handle(B) → reject | PASS |

### Vectores fijos

| Vector | Ubicación | Formato | Verificación |
|---|---|---|---|
| DKG 2-of-3 + FROST | `tests/vectors/dkg_2of3.json` | JSON fixture | `vector_verification.rs` |
| BIP340 Interop | `tests/vectors/bip340_interop.json` | JSON fixture | `vector_verification.rs` |
| Generación | `cargo run --bin generate_vectors` | Binary | manual |

### Interoperabilidad

```
FROST partial signatures
  ↓ frost-core::aggregate
Aggregate signature (BIP340)
  ↓ k256::schnorr::VerifyingKey::verify_raw
VALID
```

## Security checks

| Herramienta | Resultado |
|---|---|
| `cargo audit` | PASS (1 warning: atomic-polyfill unmaintained, dependencia transitiva de frost-core v3) |
| `cargo deny check` | advisories: FAILED (atomic-polyfill), bans: ok, licenses: ok, sources: ok |