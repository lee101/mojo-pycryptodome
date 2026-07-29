"""PyCryptodome-compatible HMAC over the covered SHA-2 modules."""

from __future__ import annotations

import hmac as _stdlib_hmac

from . import SHA224, SHA256, SHA384, SHA512

_MODULES = {
    "sha224": SHA224,
    "sha256": SHA256,
    "sha384": SHA384,
    "sha512": SHA512,
}


def _module(digestmod):
    if isinstance(digestmod, str):
        name = digestmod.lower().replace("-", "")
        if name in _MODULES:
            return _MODULES[name]
    if digestmod in _MODULES.values():
        return digestmod
    name = getattr(digestmod, "__name__", "").rsplit(".", 1)[-1].lower()
    if name in _MODULES:
        return _MODULES[name]
    raise ValueError("digestmod must be SHA224, SHA256, SHA384, or SHA512")


class HMAC:
    def __init__(self, key, msg=b"", digestmod=None):
        if digestmod is None:
            raise ValueError("digestmod is required for this SHA-2-only port")
        self._digestmod = _module(digestmod)
        try:
            key_view = memoryview(key)
        except TypeError as exc:
            raise TypeError("key must be bytes-like") from exc
        self._key = key if isinstance(key, bytes) else key_view.tobytes()
        self._data: bytes | bytearray = b""
        self.update(msg)

    @property
    def digest_size(self):
        return self._digestmod.digest_size

    def update(self, msg):
        try:
            view = memoryview(msg)
        except TypeError as exc:
            raise TypeError("msg must be bytes-like") from exc
        if not view.c_contiguous:
            view = memoryview(view.tobytes())
        try:
            view = view.cast("B")
        except TypeError:
            view = memoryview(view.tobytes())
        if not self._data and isinstance(msg, bytes):
            self._data = msg
            return
        if not isinstance(self._data, bytearray):
            self._data = bytearray(self._data)
        self._data.extend(view)

    def digest(self):
        block_size = self._digestmod.block_size
        key = self._key
        if len(key) > block_size:
            key = self._digestmod.new(key).digest()
        key = key.ljust(block_size, b"\0")
        inner = bytes(value ^ 0x36 for value in key)
        outer = bytes(value ^ 0x5C for value in key)
        inner_digest = self._digestmod.new(inner + self._data).digest()
        return self._digestmod.new(outer + inner_digest).digest()

    def hexdigest(self):
        return self.digest().hex()

    def verify(self, mac_tag):
        try:
            tag = memoryview(mac_tag).tobytes()
        except TypeError as exc:
            raise TypeError("mac_tag must be bytes-like") from exc
        if not _stdlib_hmac.compare_digest(self.digest(), tag):
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        try:
            tag = bytes.fromhex(hex_mac_tag)
        except (TypeError, ValueError) as exc:
            raise ValueError("MAC check failed") from exc
        self.verify(tag)

    def copy(self):
        duplicate = HMAC(self._key, digestmod=self._digestmod)
        duplicate._data = (
            self._data.copy()
            if isinstance(self._data, bytearray)
            else self._data
        )
        return duplicate

    def new(self, key, msg=b"", digestmod=None):
        return HMAC(key, msg, digestmod or self._digestmod)


def new(key, msg=b"", digestmod=None):
    return HMAC(key, msg, digestmod)
