# P0-C3 Security Review

**Proyecto:** BoxKey Core (BC)
**Fase:** Fase 1 / P0-C3

---

## 1. Nonce uniqueness

`NonceHandle::consume()` garantiza consumo único. Segundo consumo retorna `None`.
Test: `nonce_handle_consumido_no_reutilizable`.

## 2. Nonce lifecycle

```
GENERATED (frost-core round1::commit)
  ↓ NonceHandle::new(identifier, hidden)
COMMITTED (commitment publicado)
  ↓ NonceHandle::consume()
USED (sign_partial deserializa nonces, firma)
  ↓ Zeroizing::drop() + handle.zeroize()
ZEROIZED
```

## 3. Share/nonce association

Añadido en P0-C3: `sign_partial` verifica `handle.identifier() == share.identifier()` antes de consumir.
Test: `wrong_share_nonce_handle_is_rejected`.

Si la asociación es incorrecta, el handle NO se consume (error antes de `consume()`).

## 4. Nonce reuse

- `NonceHandle::consume()` previene reutilización del mismo handle.
- `aggregate_signatures` rechaza firmas con id duplicado (`NonceReuse`).
- Handle consumido rechaza segunda firma determinísticamente.

## 5. Secret exposure

| Tipo | Estado |
|---|---|
| `NonceHandle` Python API | Sin `to_bytes()` ni acceso al secreto |
| `NonceHandle::Debug` | Redactado (id + state, no secreto) |
| `SecretKey::Debug` | `[REDACTED]` |
| `SecretKey.__repr__` (Python) | `SecretKey([REDACTED])` |
| `Share::Debug` | `[REDACTED]` |
| `NonceHandle` Python `__repr__` | `NonceHandle(id=..., consumed=...)` |

## 6. Zeroization

| Secreto | Mecanismo |
|---|---|
| `SecretKey.0` | `Drop::drop` → `zeroize::Zeroize` |
| `Share.value` | `Zeroizing<[u8; 32]>` |
| `SecretShare.coefficients` | `Zeroizing<Vec<u8>>` |
| `NonceHandle` hidden | `Zeroizing<Vec<u8>>` + `Drop::drop` |
| Buffer en `sign_partial` | `Zeroizing<Vec<u8>>` scope |

## 7. PyO3 exposure

La clase `NonceHandle` en Python no expone el nonce como `bytes`.
Solo se consume internamente por `sign_partial`. No hay método `to_bytes()`.

## 8. Serialization exposure

`SecretKey`, `Share`, `SecretShare`, `NonceHandle` no implementan `Serialize`.

## 9. Logging/debug exposure

No hay macros `log!` o `println!` en producción que emitan secretos.

## 10. FROST implementation

Production path usa exclusivamente `frost-core` 3.0 + `frost-secp256k1-tr` 3.0.
`reference/frost.rs` no es importado.

## 11. BIP340 verification

Verificación independiente vía `k256::schnorr::VerifyingKey::verify_raw`.

## 12. Error handling

Errores clasificados con códigos BZ-0011. Sin fugas de secretos en mensajes de error.