# ADR-0001: FROST propio (RFC 9591) sobre secp256k1

- **Fecha**: 2026-08-19
- **Estado**: Aceptado
- **Alcance**: `boxkey-core` (BC)

## Contexto

El protocolo BoxKey (BZ) requiere firma distributed threshold (t-de-n) sobre
`secp256k1` con verificación BIP340. En el mercado existen crates como
`frost-core`/`frost-secp256k1-tr` (ecosistema Zcash/Redjubjub). La Fase 1.0
auditó la opción de adoptarlos.

## Decisión

Implementar FROST (RFC 9591) propio sobre la aritmética de `k256`
(RustCrypto), con verificación cruzada contra el oráculo externo
`rust-secp256k1` (BIP340). No se migra a `frost-secp256k1-tr`.

## Justificación

1. **Formato y transporte propios**: `frost-core` impone formatos de share y
   serialización (campos, bit encoding) incompatibles con la especificación BZ
   (BZ-0010 serialización hex/canonical, BZ-0013 DTOs). Adoptarlo obligaría a
   capas de conversión que erosionan la trazabilidad con la spec.
2. **DKG propio requerido**: el protocolo usa Feldman VSS + PoK Schnorr + cifrado
   ECDH AEAD (share cifrada end-to-end). `frost-secp256k1-tr` trae su propio
   esquema DKG (RedJubJub) que no soporta el transporte cifrado ni la PoK
   Schnorr de BZ. Mantener el DKG propio es necesario para la autocustodia
   absoluta (el coordinador nunca ve secretos).
3. **Disciplina de dependencias**: BC debe usar solo criptografía estándar y
   auditada; `frost-*` acopla el proyecto al ecosistema Zcash (Redjubjub,
   rand_chacha, zkcrypto). `k256` es RustCrypto (implementación de referencia
   auditada de secp256k1).
4. **Convención BIP340 integrada**: la normalización even-y se aplica en
   DKG/reshare/firma como convención nativa del protocolo. Con `frost-*` esa
   normalización quedaría fuera del control de BC.

## Consecuencias

- Mantenimiento del motor criptográfico como responsabilidad propia (mitigado
  por la verificación cruzada externa que actúa como red de seguridad).
- El motor propio se conserva y se expone como "API avanzada"; la capa
  conforme a `contratos.md §2` (trait `BoxKeyCore`) delega en él.

## Referencias

- RFC 9591 (FROST)
- BIP340 (Schnorr sobre secp256k1)
- BZ-0010 (serialización), BZ-0013 (DTOs)
- `boxkey-protocol/contratos.md §2` (interfaz pública BC)