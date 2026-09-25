# P0-C2 Security Review

**Proyecto:** BoxKey Core (BC)
**Protocolo:** BoxKey Protocol (BZ)

---

## 1. Zeroization audit

### Secretos propiedad de BC

| Secreto | Tipo | Zeroizado | Mecanismo | Verificado |
|---|---|---|---|---|
| `SecretKey.0` | `[u8; 32]` | ✓ | `Drop::drop` → `Zeroize` | Test manual |
| `Share.value` | `Zeroizing<[u8; 32]>` | ✓ | `Zeroizing` drop | Estructural |
| `SecretShare.coefficients` | `Zeroizing<Vec<u8>>` | ✓ | `Zeroizing` drop | Estructural |
| `NonceHandle.hidden` | `Zeroizing<Vec<u8>>` | ✓ | `Drop::drop` + `consume()` | Test `nonce_handle_consumido_no_reutilizable` |
| Buffer hidden en `sign_partial` | `Zeroizing<Vec<u8>>` | ✓ | `Zeroizing` scope | Estructural |
| DKG coefficients temporales | `Fs` (k256) | Parcial | Dependencia externa (k256 no garantiza zeroize) | Documentado |

### No atribuido a BC

- Memoria de `frost-core` (`SigningNonces`, `KeyPackage`): BC no garantiza zeroización de dependencias externas.
- Memoria de `k256` (escalares temporales): BC no garantiza zeroización.

## 2. Debug y logs

| Tipo | Estado | Evidencia |
|---|---|---|
| `SecretKey::Debug` | REDACTED | `SecretKey([REDACTED])` |
| `Share::Debug` | REDACTED | `Share { identifier: ..., [REDACTED], ... }` |
| `SecretShare::Debug` | REDACTED | `SecretShare { coefficients: [REDACTED], ... }` |
| `NonceHandle::Debug` | REDACTED | `NonceHandle({ id: ..., state: ... })` |
| `PartialSignature::Debug` | Solo id | `PartialSignature(id=...)` |
| `Commitment::Debug` | Solo longitud | `Commitment(N bytes)` |
| Logs | No se emiten secretos | Ninguna macro `log!` o `println!` en producción |

## 3. Serialización de secretos

- `SecretKey` no implementa `Serialize`/`Deserialize`.
- `Share` no implementa `Serialize`/`Deserialize`.
- `SecretShare` no implementa `Serialize`/`Deserialize`.
- `NonceHandle` no implementa `Serialize`/`Deserialize`.
- `PartialSignature` (id\|z) implementa `Serialize`/`Deserialize` — necesario para el wire protocol (BZ-0013). `z` es la firma parcial, no un secreto a largo plazo.

## 4. Nonce lifecycle

```
GENERATED → COMMITTED → USED → ZEROIZED
```

- `NonceHandle::consume()` extrae el secreto y zeroiza el buffer interno.
- Segundo `consume()` retorna `None`.
- `sign_partial` consume el handle: no puede generar nonces nuevos.
- `Drop::drop` zeroiza si no se consumió.

## 5. Reutilización de nonce

- `NonceHandle::consume()` previene reutilización vía runtime.
- `aggregate_signatures` rechaza firmas con id duplicado (error `NonceReuse`).
- Tests: `nonce_reuse_rejected_via_trait`, `nonce_reuse_detectado`.

## 6. SecretKey Clone

`SecretKey` implementa `Clone` (necesario para el trait `BoxKeyCore` que retorna `(SecretKey, PublicKey)`). Esto permite copia accidental de la clave. No se usa `Clone` en producción, pero es un riesgo residual. Mitigación:
- `Clone` es manual, no derivado.
- `Drop` zeroiza ambos clones al salir de scope.

## 7. Riesgos conocidos

1. **k256 no zeroiza escalares temporales**: BC no puede garantizar la limpieza de memoria de dependencias externas.
2. **`Clone` en `SecretKey`**: riesgo de copia accidental. No explotado en producción.
3. **`PartialEq` en `SecretKey`**: comparación no constante en tiempo. Aceptable para P0 (no adversarial).
4. **FROST nonces en frost-core**: `frost-core` maneja los nonces internamente; BC no controla su zeroización después de pasarlos a `round2::sign`. Sin embargo, el buffer original (`Zeroizing<Vec<u8>>`) se zeroiza al salir de scope.

## 8. Recomendaciones para P1

1. Evaluar uso de `SecretKey::clone()` y eliminar si es posible.
2. Agregar `Zeroize` derive a tipos con secretos en frost-core.
3. Campaña de fuzzing exhaustiva.
4. Integrar `cargo audit` en CI.