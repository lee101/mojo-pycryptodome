"""ctypes bridge to the compiled Mojo cryptographic kernels."""

from __future__ import annotations

import ctypes
import os
import platform
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
LIB_PATH = ROOT / "dist" / "libmojo-pycryptodome.so"

I64 = ctypes.c_int64
U64 = ctypes.c_uint64
_lib: ctypes.CDLL | None = None
_LAST_GPU_USED = False
_empty = np.empty(1, dtype=np.uint8)

# AES-CTR is compute bound: ten AES rounds of work per 16-byte block, several
# times the 2 flops/byte above which chunking pays.  Mojo 1.2.0 cannot capture
# these pointers into a parallel body, so the stream is split here and each
# chunk is one ctypes call into mpc_aes_ctr_range.  ctypes releases the GIL for
# the foreign call, so the workers really do run concurrently.
#
# Measured on a 36-core Xeon, best of 25, three passes, serial against eight
# workers: 1 MiB 0.87-1.26x, 2 MiB 0.89-0.91x, 4 MiB 1.08-1.14x,
# 8 MiB 0.94-1.44x, 16 MiB 0.92-1.34x, 32 MiB 1.44-1.83x, 64 MiB 1.84-2.36x.
# Below 4 MiB a single call takes under 6 ms and the hand-off costs more than
# it saves, so the threshold is 4 MiB.  The pool is shared: building a
# ThreadPoolExecutor per call measured 13.4 ms at 1 MiB against 2.7 ms for the
# serial kernel.
AES_CTR_PARALLEL_THRESHOLD = 4 * 1024 * 1024
AES_CTR_MIN_CHUNK = 512 * 1024
AES_CTR_MAX_WORKERS = 8

_aes_ctr_pool: ThreadPoolExecutor | None = None


def _aes_ctr_executor() -> ThreadPoolExecutor:
    global _aes_ctr_pool
    if _aes_ctr_pool is None:
        _aes_ctr_pool = ThreadPoolExecutor(
            max_workers=AES_CTR_MAX_WORKERS, thread_name_prefix="mojo-aes-ctr"
        )
    return _aes_ctr_pool


def _aes_ctr_chunks(size: int) -> list[tuple[int, int]]:
    """Split [0, size) into whole AES blocks, one range per worker."""
    parts = min(AES_CTR_MAX_WORKERS, max(1, size // AES_CTR_MIN_CHUNK))
    step = -(-size // parts)
    step = -(-step // 16) * 16
    return [(i * step, min((i + 1) * step, size)) for i in range(-(-size // step))]


def _cpu_has_aesni() -> bool:
    if os.environ.get("MOJOPYCRYPTODOME_DISABLE_AESNI"):
        return False
    if platform.machine().lower() not in ("x86_64", "amd64"):
        return False
    try:
        fields = Path("/proc/cpuinfo").read_text().splitlines()
    except OSError:
        return False
    return any(
        line.startswith("flags") and "aes" in line.split(":", 1)[1].split()
        for line in fields
    )


_USE_AESNI = _cpu_has_aesni()


def lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        if not LIB_PATH.exists():
            raise RuntimeError("Mojo library is missing; run `pixi run build`")
        loaded = ctypes.CDLL(str(LIB_PATH))
        loaded.mpc_aes_ecb.argtypes = [I64, I64, I64, I64, I64, I64, I64]
        loaded.mpc_aes_ecb.restype = I64
        loaded.mpc_aes_cbc.argtypes = [
            I64, I64, I64, I64, I64, I64, I64, I64
        ]
        loaded.mpc_aes_cbc.restype = I64
        loaded.mpc_aes_ctr.argtypes = [
            I64, I64, I64, I64, I64, I64, I64, I64, I64, I64, I64
        ]
        loaded.mpc_aes_ctr.restype = I64
        loaded.mpc_aes_ctr_range.argtypes = [
            I64, I64, I64, I64, I64, I64, I64, I64, I64, I64, I64
        ]
        loaded.mpc_aes_ctr_range.restype = I64
        loaded.mpc_chacha20.argtypes = [
            I64, I64, I64, I64, I64, I64, I64, U64
        ]
        loaded.mpc_chacha20.restype = I64
        loaded.mpc_chacha20_gpu.argtypes = [
            I64, I64, I64, I64, I64, I64, I64, U64
        ]
        loaded.mpc_chacha20_gpu.restype = I64
        loaded.mpc_sha256.argtypes = [I64, I64, I64, I64]
        loaded.mpc_sha256.restype = I64
        loaded.mpc_sha512.argtypes = [I64, I64, I64, I64]
        loaded.mpc_sha512.restype = I64
        _lib = loaded
    return _lib


def _input(data: object) -> tuple[np.ndarray, int]:
    try:
        view = memoryview(data)
    except TypeError as exc:
        raise TypeError("object supporting the buffer API required") from exc
    if not view.c_contiguous:
        view = memoryview(view.tobytes())
    try:
        byte_view = view.cast("B")
    except TypeError:
        byte_view = memoryview(view.tobytes())
    size = byte_view.nbytes
    if size == 0:
        return _empty, 0
    return np.frombuffer(byte_view, dtype=np.uint8), size


def _bytes(data: object, name: str) -> bytes:
    try:
        return memoryview(data).tobytes()
    except TypeError as exc:
        raise TypeError(f"{name} must be bytes-like") from exc


def _destination(size: int, output: object | None) -> tuple[np.ndarray, bool]:
    if output is None:
        return np.empty(max(size, 1), dtype=np.uint8), True
    try:
        view = memoryview(output)
    except TypeError as exc:
        raise TypeError("output must be a writable bytes-like object") from exc
    if view.readonly or not view.c_contiguous:
        raise TypeError("output must be a writable contiguous buffer")
    try:
        byte_view = view.cast("B")
    except TypeError as exc:
        raise TypeError("output must expose a byte-addressable buffer") from exc
    if byte_view.nbytes != size:
        raise ValueError(
            f"output must have the same length as the input ({size} bytes)"
        )
    if size == 0:
        return _empty, False
    return np.frombuffer(byte_view, dtype=np.uint8), False


def _finish(destination: np.ndarray, size: int, owned: bool):
    return destination[:size].tobytes() if owned else None


def aes_ecb(data: object, key: bytes, decrypt: bool, output: object | None):
    source, size = _input(data)
    key_array, _ = _input(key)
    destination, owned = _destination(size, output)
    status = lib().mpc_aes_ecb(
        source.ctypes.data,
        destination.ctypes.data,
        size,
        key_array.ctypes.data,
        len(key),
        int(decrypt),
        int(_USE_AESNI),
    )
    if status:
        raise ValueError("data must be aligned to the AES block boundary")
    return _finish(destination, size, owned)


def aes_cbc(
    data: object,
    key: bytes,
    iv: bytearray,
    decrypt: bool,
    output: object | None,
):
    source, size = _input(data)
    key_array, _ = _input(key)
    iv_array, _ = _input(iv)
    destination, owned = _destination(size, output)
    status = lib().mpc_aes_cbc(
        source.ctypes.data,
        destination.ctypes.data,
        size,
        key_array.ctypes.data,
        len(key),
        iv_array.ctypes.data,
        int(decrypt),
        int(_USE_AESNI),
    )
    if status:
        raise ValueError("data must be aligned to the AES block boundary")
    return _finish(destination, size, owned)


def aes_ctr(
    data: object,
    key: bytes,
    counter_block: bytes,
    skip: int,
    counter_offset: int,
    counter_length: int,
    little_endian: bool,
    output: object | None,
):
    source, size = _input(data)
    key_array, _ = _input(key)
    counter_array, _ = _input(counter_block)
    destination, owned = _destination(size, output)
    shared = (
        key_array.ctypes.data,
        len(key),
        counter_array.ctypes.data,
        counter_offset,
        counter_length,
        int(little_endian),
        int(_USE_AESNI),
    )
    if skip == 0 and size >= AES_CTR_PARALLEL_THRESHOLD:
        ranges = _aes_ctr_chunks(size)
        if len(ranges) > 1:
            kernel = lib().mpc_aes_ctr_range
            src_addr = source.ctypes.data
            dst_addr = destination.ctypes.data

            def run(bounds: tuple[int, int]) -> None:
                if kernel(src_addr, dst_addr, bounds[0], bounds[1], *shared):
                    raise ValueError("invalid AES key")

            list(_aes_ctr_executor().map(run, ranges))
            return _finish(destination, size, owned)
    status = lib().mpc_aes_ctr(
        source.ctypes.data,
        destination.ctypes.data,
        size,
        *shared[:3],
        skip,
        *shared[3:],
    )
    if status:
        raise ValueError("invalid AES key")
    return _finish(destination, size, owned)


def chacha20(
    data: object,
    key: bytes,
    nonce: bytes,
    position: int,
    output: object | None,
    device: str = "cpu",
):
    global _LAST_GPU_USED
    source, size = _input(data)
    key_array, _ = _input(key)
    nonce_array, _ = _input(nonce)
    destination, owned = _destination(size, output)
    arguments = (
        source.ctypes.data,
        destination.ctypes.data,
        size,
        key_array.ctypes.data,
        len(key),
        nonce_array.ctypes.data,
        len(nonce),
        position,
    )
    _LAST_GPU_USED = device == "gpu" and lib().mpc_chacha20_gpu(*arguments) == 1
    if _LAST_GPU_USED:
        status = 0
    else:
        status = lib().mpc_chacha20(*arguments)
    if status:
        raise ValueError("nonce must be 8, 12, or 24 bytes")
    return _finish(destination, size, owned)


def sha2(data: object, bits: int) -> bytes:
    source, size = _input(data)
    digest_size = bits // 8
    destination = np.empty(digest_size, dtype=np.uint8)
    if bits in (224, 256):
        status = lib().mpc_sha256(
            source.ctypes.data,
            size,
            destination.ctypes.data,
            int(bits == 224),
        )
    elif bits in (384, 512):
        status = lib().mpc_sha512(
            source.ctypes.data,
            size,
            destination.ctypes.data,
            int(bits == 384),
        )
    else:
        raise ValueError("unsupported SHA-2 digest size")
    if status:
        raise RuntimeError("SHA-2 kernel rejected its buffers")
    return destination.tobytes()
