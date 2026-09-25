# P0-C2 Test Evidence

**Proyecto:** BoxKey Core (BC)

---

## Resumen de tests

```
cargo test --locked
→ 62 tests passed, 0 failed
```

## Test suites

### Unit tests (lib target: 27 tests)

| Test | Cobertura | Resultado |
|---|---|---|
| `api::tests::single_signer_frost_round_via_trait` | C1, C2, C3 | PASS |
| `api::tests::nonce_reuse_rejected_via_trait` | C2, C9 | PASS |
| `api::tests::two_of_three_via_trait` | C1, C3 | PASS |
| `api::tests::full_dkg_flow_via_trait` | DKG | PASS |
| `api::tests::compute_commitments_fixes_threshold` | DKG | PASS |
| `api::tests::reshare_via_trait_preserves_group_key` | Resharing | PASS |
| `error::tests::codigos_bz0011_*` (6 tests) | C11 | PASS |
| `schnorr::tests::bip340_*` (2 tests) | BIP340 | PASS |
| `serialize::tests::*` (5 tests) | BZ-0010 | PASS |
| `types::tests::hex_serde_*` (3 tests) | BZ-0010 | PASS |
| `dkg::tests::*` (3 tests) | DKG, C9 | PASS |
| `reshare::tests::resharing_preserves_group_key_and_signs` | Resharing | PASS |

### External tests (10 test files, 35 tests)

| Test file | Tests | Cobertura |
|---|---|---|
| `dkg_tests.rs` | 2 | DKG negativo |
| `frost_tests.rs` | 2 | C1, C3, C9 |
| `integration_tests.rs` | 2 | C1, C3, C11 |
| `negative_tests.rs` | 10 | C6, C9 |
| `property_tests.rs` | 2 | C9, proptest |
| `reshare_tests.rs` | 1 | Resharing |
| `vector_generation.rs` | 2 | C4 (flow check) |
| `vector_verification.rs` | 4 | C4, C5 |
| `fuzz_tests.rs` | 6 | C8 |
| `dkg_tests.rs` | 2 | DKG |

## Vectores fijos

| Vector | Ubicación | Formato | Verificación |
|---|---|---|---|
| DKG 2-of-3 + FROST | `tests/vectors/dkg_2of3.json` | JSON fixture | `vector_verification.rs` |
| BIP340 Interop | `tests/vectors/bip340_interop.json` | JSON fixture | `vector_verification.rs` |
| Generación | `cargo run --bin generate_vectors` | Binary | Manual |

## Fuzzing

6 tests proptest en `tests/fuzz_tests.rs`:
- `fuzz_parse_commitment`
- `fuzz_parse_public_key`
- `fuzz_parse_partial_signature`
- `fuzz_commitment_wrong_length`
- `fuzz_public_key_invalid`
- `fuzz_reads_corpus_if_exists`

## Tests negativos (C9)

| Test | Escenario |
|---|---|
| `wrong_group_public_key_rechazado` | Firma grupo A, verifica grupo B |
| `wrong_participant_id_rechazado` | ID en commitment no coincide |
| `insufficient_threshold_rechazado` | 1 firma para threshold 2 |
| `nonce_reuse_detectado` | Misma firma aportada dos veces |
| `invalid_bip340_signature_rechazada` | Firma agregada manipulada |
| `nonce_handle_consumido_no_reutilizable` | Handle consumido, segundo uso falla |
| `missing_signer_rechazado` | 2 firmas de 3 en sesión |
| `correct_digest_verifica` | C6: digest correcto |
| `wrong_digest_rechazado` | C6: digest incorrecto |
| `double_hash_detectado` | C6: double-hashing |

## Evidencia de compilación

```bash
$ cargo build --locked
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.50s
```

**Nota:** `cargo audit` y `cargo deny check` no están disponibles en el entorno de ejecución. Resultado documentado como "NOT RUN — tool unavailable".