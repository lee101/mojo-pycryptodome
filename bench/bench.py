"""End-to-end benchmarks against upstream PyCryptodome."""

from __future__ import annotations

import platform
import time
from pathlib import Path

import numpy as np
from Crypto.Cipher import AES as ReferenceAES
from Crypto.Cipher import ChaCha20 as ReferenceChaCha20
from Crypto.Hash import HMAC as ReferenceHMAC
from Crypto.Hash import SHA256 as ReferenceSHA256
from Crypto.Hash import SHA512 as ReferenceSHA512

from mojopycryptodome.Cipher import AES, ChaCha20
from mojopycryptodome.Hash import HMAC, SHA256, SHA512
from mojopycryptodome import _lib


def best_time(function, repetitions=3):
    best = float("inf")
    result = None
    for _ in range(repetitions):
        start = time.perf_counter()
        result = function()
        best = min(best, time.perf_counter() - start)
    return best, result


def cpu_name():
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown CPU"


def main():
    rng = np.random.default_rng(2026)
    cipher_data = rng.integers(
        0, 256, size=4 * 1024 * 1024, dtype=np.uint8
    ).tobytes()
    hash_data = rng.integers(
        0, 256, size=16 * 1024 * 1024, dtype=np.uint8
    ).tobytes()
    hmac_data = hash_data[: 8 * 1024 * 1024]
    aes128_key = bytes(range(16))
    aes256_key = bytes(range(32))
    iv = bytes(range(16))
    nonce8 = bytes(range(8))
    nonce12 = bytes(range(12))

    cases = [
        (
            "AES-128-CTR, 4 MiB",
            len(cipher_data),
            lambda: AES.new(
                aes128_key, AES.MODE_CTR, nonce=nonce8
            ).encrypt(cipher_data),
            lambda: ReferenceAES.new(
                aes128_key, ReferenceAES.MODE_CTR, nonce=nonce8
            ).encrypt(cipher_data),
        ),
        (
            "AES-256-CBC, 4 MiB",
            len(cipher_data),
            lambda: AES.new(
                aes256_key, AES.MODE_CBC, iv=iv
            ).encrypt(cipher_data),
            lambda: ReferenceAES.new(
                aes256_key, ReferenceAES.MODE_CBC, iv=iv
            ).encrypt(cipher_data),
        ),
        (
            "ChaCha20, 4 MiB",
            len(cipher_data),
            lambda: ChaCha20.new(
                key=aes256_key, nonce=nonce12
            ).encrypt(cipher_data),
            lambda: ReferenceChaCha20.new(
                key=aes256_key, nonce=nonce12
            ).encrypt(cipher_data),
        ),
        (
            "SHA-256, 16 MiB",
            len(hash_data),
            lambda: SHA256.new(hash_data).digest(),
            lambda: ReferenceSHA256.new(hash_data).digest(),
        ),
        (
            "SHA-512, 16 MiB",
            len(hash_data),
            lambda: SHA512.new(hash_data).digest(),
            lambda: ReferenceSHA512.new(hash_data).digest(),
        ),
        (
            "HMAC-SHA256, 8 MiB",
            len(hmac_data),
            lambda: HMAC.new(aes256_key, hmac_data, SHA256).digest(),
            lambda: ReferenceHMAC.new(
                aes256_key, hmac_data, ReferenceSHA256
            ).digest(),
        ),
    ]

    gpu_function = lambda: ChaCha20.new(
        key=aes256_key, nonce=nonce12, device="gpu"
    ).encrypt(cipher_data)
    gpu_function()
    if _lib._LAST_GPU_USED:
        cases.append(
            (
                "ChaCha20 GPU, 4 MiB",
                len(cipher_data),
                gpu_function,
                lambda: ReferenceChaCha20.new(
                    key=aes256_key, nonce=nonce12
                ).encrypt(cipher_data),
            )
        )
    else:
        print("GPU benchmark skipped: unavailable or under 4000 MiB free.")
        print()

    rows = []
    for name, size, mojo_function, reference_function in cases:
        mojo_expected = mojo_function()
        reference_expected = reference_function()
        if mojo_expected != reference_expected:
            raise RuntimeError(f"benchmark parity check failed for {name}")
        mojo_seconds, _ = best_time(mojo_function)
        reference_seconds, _ = best_time(reference_function)
        mib = size / (1024 * 1024)
        rows.append(
            (
                name,
                mojo_seconds * 1000,
                mib / mojo_seconds,
                reference_seconds * 1000,
                reference_seconds / mojo_seconds,
            )
        )

    print(f"Machine: {cpu_name()}; {platform.platform()}")
    print()
    print(
        "| Primitive | Mojo time | Mojo throughput | "
        "PyCryptodome time | Speedup |"
    )
    print("|---|---:|---:|---:|---:|")
    for name, mojo_ms, throughput, reference_ms, speedup in rows:
        print(
            f"| {name} | {mojo_ms:.2f} ms | {throughput:.2f} MiB/s | "
            f"{reference_ms:.2f} ms | {speedup:.2f}x |"
        )


if __name__ == "__main__":
    main()
