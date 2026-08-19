# BoxKey Core (BC)

Biblioteca criptográfica central del protocolo [BoxKey](https://github.com/Ertytux/boxkey-protocol) (BZ). Implementa firma distribuida threshold (t-de-n) sobre `secp256k1`: ningún participante posee la clave privada completa; la clave pública emerge solo vía DKG y las firmas se completan cooperativamente con FROST (RFC 9591).

## Estructura

| Módulo | Descripción |
|---|---|
| `api` | Capa conforme a `contratos.md §2` (trait `BoxKeyCore`) — interfaz pública primaria |
| `secp256k1` | Aritmética de curva sobre `k256` (RustCrypto): escalares, puntos, ECDH, tagged hash BIP340 |
| `schnorr` | Firma y verificación BIP340 (múltiples motores) |
| `dkg` | Generación Distribuida de Claves (Feldman VSS + PoK sobre Schnorr + cifrado ECDH) |
| `frost` | Firma distribuida FROST (RFC 9591) adaptada a BIP340 |
| `reshare` | Redistribución de un BoxKey a un nuevo conjunto de participantes |
| `serialize` | Envelopes BC-scoped versionados (BZ-0012/0013) en JSON canónico |
| `types` | Tipos públicos: `PublicKey`, `Share`, `Commitment`, `PartialSignature`, `SchnorrSignature`... |
| `error` | Errores unificados del protocolo con códigos BZ-0011 (`Error::code()`) |

La interfaz pública primaria es el trait `api::BoxKeyCore` (firmas 1:1 con
`contratos.md §2`); el motor avanzado (DKG/FROST/reshare) queda expuesto para
integraciones con control fino. La decisión de mantener FROST propio está en
`docs/decisions/0001-frost-propia.md`.

## Uso — capa conforme (`BoxKeyCore`)

```rust
use boxkey_core::{BoxKeyCore, BoxKeyCoreImpl};

// DKG 2-de-3 vía el trait
let secret = <BoxKeyCoreImpl as BoxKeyCore>::generate_secret();
let commitments = <BoxKeyCoreImpl as BoxKeyCore>::compute_commitments(&secret, 2, 3);
// ... verificar_commitments, generate_shares, verify_and_decrypt_share,
//     derive_public_key, sign_partial, aggregate_signatures, verify_schnorr
```

## Uso — API avanzada

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

## Bindings Python (pyo3)

Los bindings están en `pyo3/` (clase `BoxKey` + pyclasses de tipos). Para
compilar e instalar:

```bash
python -m pip install maturin
cd pyo3
maturin develop        # instala el módulo `boxkey` en el entorno actual
# o: maturin build --release
```

Ver `pyo3/README.md` para el ejemplo completo (Fase1.0 §5.8).

## Pruebas

```bash
cargo test
```

## Benchmarks

```bash
cargo bench            # firma FROST y DKG (dkg_bench + signing_bench)
```

## Dependencias

- `k256` 0.13 (RustCrypto) — motor aritmético de `secp256k1`
- `secp256k1` 0.31 — oráculo de verificación externa (BIP340)
- `chacha20poly1305` 0.10 — cifrado AEAD para transporte de shares
- `sha2` 0.10, `zeroize`, `serde`, `serde_json`, `thiserror`, `hex`

## Licencia

MIT