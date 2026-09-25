# boxkey-py — Bindings Python de boxkey-core (PyO3)

Bindings Python de `boxkey-core` mediante PyO3. Exponen la clase `BoxKey`
(1:1 con el trait `BoxKeyCore`) y funciones de módulo para DKG.

## Build (maturin)

```bash
python -m pip install maturin
maturin develop           # compila e instala en el entorno actual
maturin build --release   # genera un wheel en target/wheels/
```

## Ejemplo

```python
from boxkey import BoxKey, run_dkg

# DKG 2-de-3
result = run_dkg(3, 2)
share0 = result.shares[0]
share1 = result.shares[1]
group_pk = share0.group_public_key
msg = b'\x42' * 32

# Cada firmante genera nonces
bk = BoxKey()
handle0, comm0 = bk.generate_nonces(share0)
handle1, comm1 = bk.generate_nonces(share1)

# El coordinador construye la sesión
vk0 = share0.full_public_key_point
vk1 = share1.full_public_key_point
session = bk.SigningSession.new(
    msg, group_pk, 2,
    [comm0, comm1],
    [(share0.identifier, vk0), (share1.identifier, vk1)],
)

# Firmas parciales (cada handle se consume al firmar)
sig0 = bk.sign_partial(share0, session, handle0)
sig1 = bk.sign_partial(share1, session, handle1)

# Agregación → Schnorr BIP340
agg = bk.aggregate_signatures([sig0, sig1], session)

# Verificación independiente
assert bk.verify_schnorr(agg, group_pk, msg)
```

## Notas

- `NonceHandle` encapsula el secreto: no expone `to_bytes()`.
- `NonceHandle` se consume al firmar; reutilizar un handle consumido produce error.
- `SecretKey.__repr__` nunca imprime el secreto (`[REDACTED]`).
- Los tipos se serializan como hex sin prefijo `0x` (BZ-0010 §2).