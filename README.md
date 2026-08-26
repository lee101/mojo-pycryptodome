# mojo-pycryptodome

`mojo-pycryptodome` is a standalone Mojo port of the compute-heavy core of a
focused [PyCryptodome](https://www.pycryptodome.org/) subset. It provides
PyCryptodome-shaped Python modules backed by one native Mojo shared library.
The separate `mojopycryptodome` namespace lets an application import this port
and upstream `Crypto` in the same process.

This repository currently covers:

- AES-128, AES-192, and AES-256 in ECB, CBC, and CTR modes
- ChaCha20 with 8- and 12-byte nonces, plus XChaCha20 with 24-byte nonces
- SHA-224, SHA-256, SHA-384, and SHA-512
- HMAC with each covered SHA-2 digest
- incremental cipher calls, ChaCha20 `seek()`, hash/HMAC `update()` and
  `copy()`, caller-provided output buffers, and generated IVs/nonces

It does not cover AES authenticated modes (GCM, EAX, CCM, SIV, OCB), CFB, OFB,
OpenPGP mode, Poly1305, SHA-3, legacy ciphers, public-key cryptography, random
number generation, certificates, or the rest of PyCryptodome. Unsupported AES
modes fail explicitly.

The code is correctness-tested but has not received a cryptographic security
audit. AES-NI is used on supported x86-64 CPUs. The portable AES fallback uses
table lookups and is not constant-time. Do not use this release where timing
side channels or unreviewed cryptographic code would put secrets at risk.

## Install

Install [Pixi](https://pixi.sh/), then create the pinned environment and build
the shared library:

```sh
pixi install
pixi run build
```

All development commands run inside that environment:

```sh
pixi run test
pixi run bench
```

## Usage

The module layout and covered call signatures mirror PyCryptodome, with
`mojopycryptodome` in place of `Crypto`:

```python
from mojopycryptodome.Cipher import AES, ChaCha20
from mojopycryptodome.Hash import HMAC, SHA256

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
iv = bytes(16)
plaintext = b"one AES block!!!"

ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(plaintext)
assert AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext) == plaintext

stream = ChaCha20.new(key=bytes(32), nonce=bytes(12))
encrypted = stream.encrypt(b"arbitrary length")

digest = SHA256.new(b"message").hexdigest()
tag = HMAC.new(key, b"message", SHA256).digest()
assert len(digest) == 64 and len(tag) == 32 and encrypted != b"arbitrary length"
```

The same code is checked in at `examples/basic.py`. Run it from the checkout,
after building, with:

```sh
pixi run python examples/basic.py
```

## Correctness

The test suite checks published NIST AES and SHA-2 vectors, RFC 8439 ChaCha20,
RFC 4231 HMAC, padding boundaries, streaming behavior, counter endianness and
wrap detection, output buffers, validation errors, and randomized parity
against the real upstream `pycryptodome` package. The current suite contains
209 passing tests.

Hash and HMAC objects preserve the upstream incremental API, but this first
release retains update data in Python and performs the hash in Mojo when a
digest is requested. Cipher streams process each call immediately.

## Benchmarks

These are real end-to-end results from `pixi run bench`. Each row includes
Python object construction, allocation, and the ctypes boundary. Speedup is
PyCryptodome time divided by Mojo time, so a value below `1.00x` means this port
is slower.

Machine: Intel(R) Xeon(R) CPU E5-2697 v4 @ 2.30GHz;
Linux 6.8.0-136-generic x86_64, glibc 2.39.

| Primitive | Mojo time | Mojo throughput | PyCryptodome time | Speedup |
|---|---:|---:|---:|---:|
| AES-128-CTR, 4 MiB | 9.50 ms | 421.08 MiB/s | 7.87 ms | 0.83x |
| AES-256-CBC, 4 MiB | 11.43 ms | 349.93 MiB/s | 12.64 ms | 1.11x |
| ChaCha20, 4 MiB | 13.10 ms | 305.46 MiB/s | 15.82 ms | 1.21x |
| SHA-256, 16 MiB | 87.57 ms | 182.72 MiB/s | 94.66 ms | 1.08x |
| SHA-512, 16 MiB | 56.32 ms | 284.11 MiB/s | 66.55 ms | 1.18x |
| HMAC-SHA256, 8 MiB | 45.75 ms | 174.87 MiB/s | 47.95 ms | 1.05x |
| ChaCha20 GPU, 4 MiB | 4.83 ms | 828.59 MiB/s | 15.74 ms | 3.26x |

AES uses guarded AES-NI intrinsics on supported x86-64 hosts and retains a
tested software fallback, selectable with
`MOJOPYCRYPTODOME_DISABLE_AESNI=1`. ChaCha20 and SHA-2 use compile-time-unrolled
rounds; XOR loops use native-width SIMD with scalar remainder handling. Large
round and substitution tables stay in static read-only storage instead of
being materialized for each block. Immutable one-shot hash inputs remain
zero-copy through NumPy and the C ABI.

Large aligned CTR calls split independent counter ranges across eight CPU
workers at a 512 KiB threshold; smaller and partial-position calls remain
serial. CBC encryption keeps its required block dependency but performs the
XOR, AES-NI rounds, output write, and chaining-state update directly in SIMD
registers.

ChaCha20 accepts an explicit `device="gpu"` argument. CPU remains the default.
The GPU path is limited to aligned stream positions, refuses total device
allocations of 2 GiB or more, and requires at least 4000 MiB of free device
memory. If any condition, allocation, launch, or device discovery fails, it
silently runs the CPU implementation. Device buffers are scoped to one call.

## How it works

`src/crypto.mojo` is one compilation unit. The build emits
`dist/libmojo-pycryptodome.so`, and the Python package calls its non-parametric
C ABI exports with `ctypes`. Buffers cross the ABI as integer addresses and
lengths. Python and NumPy own every input, output, IV, and scratch allocation;
Mojo retains no pointer and exposes no allocator.

The build enables the x86 AES target feature so AES-NI functions can be
emitted. Python checks the host CPU before selecting those functions; CPUs
without AES-NI use the portable software rounds.

The external representation is always a contiguous byte buffer. AES maps each
16-byte block to its standard column-major state, ChaCha20 loads and stores
32-bit little-endian words, and SHA-2 parses big-endian message words. CTR
counter prefix, suffix, width, and endianness remain explicit so
`Crypto.Util.Counter.new()` dictionaries work unchanged.
