# BoxKey Core (BC)

Biblioteca criptográfica central del protocolo [BoxKey](https://github.com/Ertytux/boxkey-protocol) (BZ). Implementa firma distribuida threshold (t-de-n) sobre `secp256k1`: ningún participante posee la clave privada completa; la clave pública emerge solo vía DKG y las firmas se completan cooperativamente con FROST (RFC 9591).

## Estructura

| Módulo | Descripción |
|---|---|
| `secp256k1` | Aritmética de curva sobre `k256` (RustCrypto): escalares, puntos, ECDH, tagged hash BIP340 |
| `schnorr` | Firma y verificación BIP340 (múltiples motores) |
| `dkg` | Generación Distribuida de Claves (Feldman VSS + PoK sobre Schnorr + cifrado ECDH) |
| `frost` | Firma distribuida FROST (RFC 9591) adaptada a BIP340 |
| `reshare` | Redistribución de un BoxKey a un nuevo conjunto de participantes |
| `serialize` | Mensajes versionados (Anexo A) en JSON canónico |
| `types` | Tipos públicos: `PublicKey`, `Share`, `Commitment`, `PartialSignature`, `SchnorrSignature`... |
| `error` | Errores unificados del protocolo |

## Uso

```rust
use boxkey_core::dkg;
use boxkey_core::frost;

// DKG 2-de-3
let (shares, _) = dkg::run_dkg(3, 2);
let group = shares[0].group_public_key();

// FROST
let msg = [0x42u8; 32];
let signers = &shares[..2];
let (hidden, comm) = frost::generate_nonces(&signers[0], &msg).unwrap();
let round = frost::SigningRound::new(/* ... */).unwrap();
let sig = frost::sign_partial(&round, &signers[0], &hidden).unwrap();
frost::verify_partial(&sig, &signers[0].partial_public_key(), &msg).unwrap();

// Agregar
let agg = frost::aggregate_signatures(&[sig], &group, &msg).unwrap();
frost::verify_schnorr(&agg, &group, &msg).unwrap();
```

## Demo

```bash
cargo run --example dkg_frost_demo
```

## Pruebas

```bash
cargo test
```

## Benchmarks

```bash
cargo bench
```

## Dependencias

- `k256` 0.13 (RustCrypto) — motor aritmético de `secp256k1`
- `secp256k1` 0.31 — oráculo de verificación externa
- `chacha20poly1305` 0.10 — cifrado AEAD para transporte de shares
- `sha2` 0.10, `zeroize`, `serde`, `serde_json`, `thiserror`, `hex`

## Licencia

MIT