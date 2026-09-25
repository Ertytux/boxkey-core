# BoxKey Core (BC)

Biblioteca criptográfica central del protocolo [BoxKey](https://github.com/Ertytux/boxkey-protocol) (BZ). Implementa firma distribuida threshold (t-de-n) sobre `secp256k1`: ningún participante posee la clave privada completa; la clave pública emerge solo vía DKG y las firmas se completan cooperativamente con FROST (RFC 9591).

## Estructura

| Módulo | Descripción |
|---|---|
| `api` | Capa conforme a `contratos.md §2` (trait `BoxKeyCore`) — interfaz pública primaria |
| `secp256k1` | Aritmética de curva sobre `k256` (RustCrypto): escalares, puntos, ECDH, tagged hash BIP340 |
| `schnorr` | Firma y verificación BIP340 (`k256::schnorr`) |
| `dkg` | Generación Distribuida de Claves (Feldman VSS + PoK sobre Schnorr + cifrado ECDH) |
| `frost_adapter` | Adaptador a `frost-core` 3.0 + `frost-secp256k1-tr` (RFC 9591) |
| `reshare` | Redistribución de un BoxKey a un nuevo conjunto de participantes |
| `serialize` | Envelopes BC-scoped versionados (BZ-0012/0013) en JSON canónico |
| `types` | Tipos públicos: `PublicKey`, `Share`, `Commitment`, `NonceHandle`, `SigningSession`, `PartialSignature`, `SchnorrSignature`... |
| `error` | Errores unificados del protocolo con códigos BZ-0011 (`Error::code()`) |

La interfaz pública primaria es el trait `api::BoxKeyCore` (firmas 1:1 con
`contratos.md §2`). El motor FROST delega en `frost-core` 3.0 + `frost-secp256k1-tr`;
el DKG (Gennaro/Feldman VSS) y el cifrado ECDH se mantienen propios en `dkg.rs`.

## Uso

```rust
use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use boxkey_core::{NonceHandle, SigningSession, PublicKey, SchnorrSignature};

// DKG 2-de-3
let (shares, _) = dkg::run_dkg(3, 2);
let group_key = shares[0].group_public_key();

// Cada firmante genera nonces (NonceHandle + Commitment)
let mut rng = rand::rngs::OsRng;
let signers = &shares[..2];
let (mut h1, c1) = frost_adapter::generate_nonces(&signers[0], &mut rng).unwrap();
let (mut h2, c2) = frost_adapter::generate_nonces(&signers[1], &mut rng).unwrap();

// El coordinador construye la sesión
let msg = [0x42u8; 32];
let vk1 = signers[0].full_public_key_point();
let vk2 = signers[1].full_public_key_point();
let session = SigningSession::new(
    msg, group_key, 2,
    vec![c1, c2],
    vec![(signers[0].identifier(), vk1), (signers[1].identifier(), vk2)],
).expect("sesión");

// Firmas parciales (consumen el NonceHandle)
let sig1 = frost_adapter::sign_partial(&signers[0], &session, &mut h1).unwrap();
let sig2 = frost_adapter::sign_partial(&signers[1], &session, &mut h2).unwrap();

// Agregación → Schnorr BIP340
let agg = frost_adapter::aggregate_signatures(&[sig1, sig2], &session).unwrap();

// Verificación independiente vía k256::schnorr
frost_adapter::verify_schnorr(&agg, &group_key, &msg).unwrap();
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

Ver `pyo3/README.md` para el ejemplo completo.

## Pruebas

```bash
cargo test --locked
```

## Benchmarks

```bash
cargo bench            # firma FROST y DKG (dkg_bench + signing_bench)
```

## Dependencias

- `frost-core` 3.0 + `frost-secp256k1-tr` 3.0 — FROST RFC 9591
- `k256` 0.13 (RustCrypto) — motor aritmético de `secp256k1` + BIP340
- `chacha20poly1305` 0.10 — cifrado AEAD para transporte de shares
- `sha2` 0.10, `zeroize`, `serde`, `serde_json`, `thiserror`, `hex`

## Licencia

MIT