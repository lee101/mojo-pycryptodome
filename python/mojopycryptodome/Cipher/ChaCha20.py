"""PyCryptodome-compatible ChaCha20 and XChaCha20 API."""

from __future__ import annotations

import os

from .. import _lib

block_size = 1
key_size = 32


class ChaCha20Cipher:
    block_size = 1

    def __init__(self, key: bytes, nonce: bytes, device: str):
        self._key = key
        self.nonce = nonce
        self._device = device
        self._position = 0
        self._direction = None

    def _crypt(self, data, output, direction):
        if self._direction not in (None, direction):
            raise TypeError(
                "Cipher object can only be used for " + self._direction + "ion"
            )
        try:
            size = memoryview(data).nbytes
        except TypeError as exc:
            raise TypeError("object supporting the buffer API required") from exc
        if len(self.nonce) in (12, 24) and self._position + size > (1 << 32) * 64:
            raise ValueError("ChaCha20 counter would wrap")
        result = _lib.chacha20(
            data, self._key, self.nonce, self._position, output, self._device
        )
        self._direction = direction
        self._position += size
        return result

    def encrypt(self, plaintext, output=None):
        return self._crypt(plaintext, output, "encrypt")

    def decrypt(self, ciphertext, output=None):
        return self._crypt(ciphertext, output, "decrypt")

    def seek(self, position):
        position = int(position)
        if position < 0:
            raise ValueError("position must be non-negative")
        if len(self.nonce) in (12, 24) and position >= (1 << 32) * 64:
            raise ValueError("position is outside the ChaCha20 stream")
        self._position = position


def new(**kwargs):
    try:
        key = _lib._bytes(kwargs.pop("key"), "key")
    except KeyError as exc:
        raise TypeError("Missing parameter 'key'") from exc
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long")
    nonce_value = kwargs.pop("nonce", None)
    nonce = os.urandom(8) if nonce_value is None else _lib._bytes(
        nonce_value, "nonce"
    )
    if len(nonce) not in (8, 12, 24):
        raise ValueError("Nonce must be 8, 12 or 24 bytes long")
    device = kwargs.pop("device", "cpu")
    if device not in ("cpu", "gpu"):
        raise ValueError("device must be 'cpu' or 'gpu'")
    if kwargs:
        raise TypeError("Unknown parameters: " + ", ".join(sorted(kwargs)))
    return ChaCha20Cipher(key, nonce, device)
