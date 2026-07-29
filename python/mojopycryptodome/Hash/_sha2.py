"""Shared SHA-2 hash object implementation."""

from __future__ import annotations

from .. import _lib


class SHA2Hash:
    def __init__(self, bits: int, data: object = b""):
        self._bits = bits
        self._data: bytes | bytearray = b""
        self.update(data)

    @property
    def digest_size(self) -> int:
        return self._bits // 8

    @property
    def block_size(self) -> int:
        return 64 if self._bits <= 256 else 128

    def update(self, data):
        try:
            view = memoryview(data)
        except TypeError as exc:
            raise TypeError("object supporting the buffer API required") from exc
        if not view.c_contiguous:
            view = memoryview(view.tobytes())
        try:
            view = view.cast("B")
        except TypeError:
            view = memoryview(view.tobytes())
        if not self._data and isinstance(data, bytes):
            self._data = data
            return
        if not isinstance(self._data, bytearray):
            self._data = bytearray(self._data)
        self._data.extend(view)

    def digest(self) -> bytes:
        return _lib.sha2(self._data, self._bits)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self):
        duplicate = SHA2Hash(self._bits)
        duplicate._data = (
            self._data.copy()
            if isinstance(self._data, bytearray)
            else self._data
        )
        return duplicate

    def new(self, data=b""):
        return SHA2Hash(self._bits, data)
