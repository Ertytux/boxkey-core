//! Bench de DKG (BZ/Fase1.0 §6). Mide el tiempo de generación de un BoxKey
//! para distintos `(n, t)`: (3,2), (4,3), (5,3), (7,4).

use boxkey_core::dkg;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_dkg(c: &mut Criterion) {
    for (n, t) in [(3u8, 2u8), (4, 3), (5, 3), (7, 4)] {
        c.bench_function(&format!("dkg_{n}_of_{t}"), |b| {
            b.iter(|| {
                let (shares, _keys) = dkg::run_dkg(n, t);
                std::hint::black_box(shares[0].group_public_key());
            })
        });
    }
}

criterion_group!(benches, bench_dkg);
criterion_main!(benches);
