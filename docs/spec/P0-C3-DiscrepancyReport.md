# P0-C3 Discrepancy Report

**Proyecto:** BoxKey Core (BC)
**Fase:** Fase 1 / P0-C3

---

## 1. ¿Se modificó BZ?

NO. BZ permanece sin cambios durante P0-C3.

## 2. ¿Se modificó la CryptoSuite?

NO. `secp256k1-bip340-frost` sin cambios.

## 3. ¿Se modificó la serialización normativa?

NO. JSON canónico, hex sin prefijo, camelCase.

## 4. ¿Se modificó `PartialSignature`?

NO. Se mantiene `id || z` (36 bytes).

## 5. ¿Se modificó el protocolo de mensajes?

NO. Envelope BZ-0012 y MessageKind BZ-0013 sin cambios.

## 6. ¿Se modificó DKG?

NO.

## 7. ¿Se modificó FROST?

NO. `frost-core` 3.0 + `frost-secp256k1-tr` 3.0.

## 8. ¿Se modificó solamente la integración PyO3?

SÍ. Es el cambio principal de P0-C3:
- `generate_nonces` retorna `(NonceHandle, Commitment)` en vez de `(Vec<u8>, Vec<u8>)`
- `sign_partial` recibe `(share, session, handle)` en vez de `(share, message_hash, commitments)`
- `aggregate_signatures` recibe `(sigs, session)` en vez de `(sigs, pubkey, message_hash)`
- Nuevas clases: `NonceHandle`, `SigningSession`, `SignerInfo`
- `NonceHandle` no expone el secreto como `bytes` en Python

Además:
- Validación explícita `handle.identifier() == share.identifier()` en `frost_adapter.rs`
- Test `wrong_share_nonce_handle_is_rejected`
- README.md sincronizado con API actual
- pyo3/README.md sincronizado con API actual

## 9. ¿Qué discrepancias permanecen?

Ninguna. Todas las detectadas en P0-C2-Analitic fueron resueltas:

| Discrepancia | Resolución |
|---|---|
| PyO3 con API antigua | PyO3 actualizado a NonceHandle + SigningSession |
| README contradictorio | README reescrito con API actual (`frost_adapter`, `NonceHandle`, `SigningSession`) |
| pyo3/README desactualizado | pyo3/README actualizado con nuevo flujo Python |
| Asociación nonce/share no validada | Validación explícita en `sign_partial` |
| ADR inconsistente | ADR-0001 ya correcto desde P0-C2 |

## Resultado

```
BZ CHANGES: NONE
CRYPTO SUITE CHANGES: NONE
WIRE PROTOCOL CHANGES: NONE
PYO3 CORRECTED: YES
DOCUMENTATION SYNCHRONIZED: YES
NONCE/SHARE ASSOCIATION VERIFIED: YES
DISCREPANCIES REMAINING: NONE
```