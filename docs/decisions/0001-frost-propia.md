# ADR-0001: Migración a frost-core (RFC 9591) desde FROST propio

- **Fecha**: 2026-08-19 (original), 2026-09-04 (actualización P0-C2)
- **Estado**: Reemplazado
- **Alcance**: `boxkey-core` (BC)

## Contexto original

El protocolo BoxKey (BZ) requiere firma distributed threshold (t-de-n) sobre
`secp256k1` con verificación BIP340. En el mercado existen crates como
`frost-core`/`frost-secp256k1-tr` (ecosistema Zcash/Redjubjub).

## Decisión original (Agosto 2026)

Implementar FROST propio sobre la aritmética de `k256` (RustCrypto), con
verificación cruzada contra `rust-secp256k1`. La justificación incluía:
formato propio incompatible con frost-core, DKG propio requerido, y
disciplina de dependencias.

## Decisión actual (P0-C2, Septiembre 2026)

**Migrar a `frost-core` 3.0 + `frost-secp256k1-tr` 3.0** para la capa de
firma FROST. El DKG (Gennaro/Feldman VSS) y el cifrado ECDH AEAD se
mantienen propios en `dkg.rs`.

## Justificación del cambio

1. **frost-core 3.0 maduró**: la versión 3.0 corrigió múltiples issues de
   seguridad y compatibilidad. La API de serialización (`serialize`/`deserialize`)
   es ahora estable y permite integrar BZ-0010.
2. **Cobertura de auditoría**: `frost-core` cuenta con auditoría criptográfica
   independiente (Zcash Foundation). BC no puede replicar ese nivel de
   escrutinio con un motor propio.
3. **BIP340 nativo en `frost-secp256k1-tr`**: el ciphersuite
   `Secp256K1Sha256TR` implementa la normalización even-y BIP340 de forma
   nativa, eliminando la necesidad de la capa de adaptación manual.
4. **Mantenimiento reducido**: delegar round1/round2/aggregate a frost-core
   reduce el código criptográfico en BC a ~220 líneas de adapter.
5. **El FROST propio se retiene como referencia**: `reference/frost.rs` se
   conserva como especificación ejecutable, no importada por el production
   path.

## Consecuencias

- El motor propio (`reference/frost.rs`) queda fuera del production path.
- `frost_adapter.rs` adapta entre los tipos de BC y los tipos de frost-core.
- Las pruebas de integración verifican que el adapter produce resultados
  correctos y verificables.
- El DKG propio y el cifrado ECDH se mantienen sin cambios.

## Referencias

- RFC 9591 (FROST)
- BIP340 (Schnorr sobre secp256k1)
- BZ-0010 (serialización), BZ-0013 (DTOs)
- `frost-core` 3.0, `frost-secp256k1-tr` 3.0
- `reference/frost.rs` (implementación de referencia, no producción)