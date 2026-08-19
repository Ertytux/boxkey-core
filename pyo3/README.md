# boxkey-py — Bindings Python de boxkey-core (PyO3)

Bindings Python de `boxkey-core` mediante PyO3. Exponen la clase `BoxKey`
(1:1 con el trait `BoxKeyCore` de `contratos.md §2`) y funciones de módulo
para DKG y generación de claves.

## Build y regeneración (maturin)

Requisitos: `maturin` instalado y un entorno Python activo.

```bash
python -m pip install maturin
maturin develop           # compila e instala en el entorno actual
maturin build --release   # genera un wheel en target/wheels/
```

Para regenerar tras cambios en `boxkey-core`, basta re-ejecutar el mismo
comando (maturin detecta la dependencia por ruta).

## Ejemplo (Fase1.0 §5.8)

```python
from boxkey import BoxKey

bk = BoxKey()
secret = bk.generate_secret()
commitments = bk.compute_commitments(secret, threshold=2, total_participants=3)
```

Flujo completo 1-de-1 (firma Schnorr BIP340):

```python
from boxkey import BoxKey

bk = BoxKey()
r = bk.run_dkg(1, 1)                     # o boxkey.run_dkg(1, 1)
share = r.shares[0]
group = share.group_public_key
msg = bytes(32)

hidden, comm = bk.generate_nonces(share)
sig = bk.sign_partial(share, msg, [boxkey.Commitment.from_bytes(comm)])
assert bk.verify_partial(sig, share.partial_public_key, msg)
agg = bk.aggregate_signatures([sig], group, msg)
assert bk.verify_schnorr(agg, group, msg)
```

## Notas

- `BoxKey` y el resto de pyclasses replican las desviaciones del trait
  `BoxKeyCore` (ver `src/api.rs` en `boxkey-core`): `verify_partial` del trait
  es fiable solo en rounds de un firmante o para el primer bloque del round;
  la firma multi-firmante se hace con la API avanzada de Rust.
- `SecretKey.__repr__` nunca imprime el secreto (`[REDACTED]`).
- Los tipos se serializan como hex sin prefijo `0x` (BZ-0010 §2).