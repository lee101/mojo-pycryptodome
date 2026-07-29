"""PyCryptodome-compatible AES API for ECB, CBC, and CTR modes."""

from __future__ import annotations

import os

from .. import _lib

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_OPENPGP = 7
MODE_CCM = 8
MODE_EAX = 9
MODE_SIV = 10
MODE_GCM = 11
MODE_OCB = 12

block_size = 16
key_size = (16, 24, 32)


def _key(value: object) -> bytes:
    key = _lib._bytes(value, "key")
    if len(key) not in key_size:
        raise ValueError(
            f"Incorrect AES key length ({len(key)} bytes); expected 16, 24, or 32"
        )
    return key


class _EcbMode:
    block_size = 16

    def __init__(self, key: bytes):
        self._key = key

    def encrypt(self, plaintext, output=None):
        return _lib.aes_ecb(plaintext, self._key, False, output)

    def decrypt(self, ciphertext, output=None):
        return _lib.aes_ecb(ciphertext, self._key, True, output)


class _CbcMode:
    block_size = 16

    def __init__(self, key: bytes, iv: bytes):
        self._key = key
        self.iv = iv
        self.IV = iv
        self._next_iv = bytearray(iv)
        self._direction = None

    def _check_direction(self, direction):
        if self._direction not in (None, direction):
            raise TypeError(
                f"{direction}() cannot be called after {self._direction}()"
            )

    def encrypt(self, plaintext, output=None):
        self._check_direction("encrypt")
        result = _lib.aes_cbc(
            plaintext, self._key, self._next_iv, False, output
        )
        self._direction = "encrypt"
        return result

    def decrypt(self, ciphertext, output=None):
        self._check_direction("decrypt")
        result = _lib.aes_cbc(
            ciphertext, self._key, self._next_iv, True, output
        )
        self._direction = "decrypt"
        return result


class _CtrMode:
    block_size = 16

    def __init__(
        self,
        key: bytes,
        prefix: bytes,
        suffix: bytes,
        counter_length: int,
        initial_value: int,
        little_endian: bool,
        nonce: bytes | None,
    ):
        self._key = key
        self._prefix = prefix
        self._suffix = suffix
        self._counter_length = counter_length
        self._initial_value = initial_value
        self._little_endian = little_endian
        self._position = 0
        self._direction = None
        if nonce is not None:
            self.nonce = nonce

    def _counter_block(self) -> tuple[bytes, int]:
        block_index, skip = divmod(self._position, 16)
        modulus = 1 << (8 * self._counter_length)
        value = self._initial_value + block_index
        if value >= modulus:
            raise OverflowError("The counter has wrapped around in CTR mode")
        order = "little" if self._little_endian else "big"
        encoded = value.to_bytes(self._counter_length, order)
        return self._prefix + encoded + self._suffix, skip

    def _crypt(self, data, output, direction):
        if self._direction not in (None, direction):
            raise TypeError(
                f"{direction}() cannot be called after {self._direction}()"
            )
        try:
            size = memoryview(data).nbytes
        except TypeError as exc:
            raise TypeError("object supporting the buffer API required") from exc
        modulus = 1 << (8 * self._counter_length)
        if size and self._initial_value + (self._position + size - 1) // 16 >= modulus:
            raise OverflowError("The counter has wrapped around in CTR mode")
        block, skip = self._counter_block()
        result = _lib.aes_ctr(
            data,
            self._key,
            block,
            skip,
            len(self._prefix),
            self._counter_length,
            self._little_endian,
            output,
        )
        self._direction = direction
        self._position += size
        return result

    def encrypt(self, plaintext, output=None):
        return self._crypt(plaintext, output, "encrypt")

    def decrypt(self, ciphertext, output=None):
        return self._crypt(ciphertext, output, "decrypt")


def new(key, mode, *args, **kwargs):
    key_bytes = _key(key)
    if mode == MODE_ECB:
        if args or kwargs:
            raise TypeError("ECB mode does not use an IV or nonce")
        return _EcbMode(key_bytes)

    if mode == MODE_CBC:
        iv = args[0] if args else kwargs.pop("iv", kwargs.pop("IV", None))
        if len(args) > 1 or kwargs:
            raise TypeError("unknown parameters for CBC mode")
        if iv is None:
            iv_bytes = os.urandom(16)
        else:
            iv_bytes = _lib._bytes(iv, "iv")
        if len(iv_bytes) != 16:
            raise ValueError("Incorrect IV length (it must be 16 bytes long)")
        return _CbcMode(key_bytes, iv_bytes)

    if mode == MODE_CTR:
        if args:
            raise TypeError("CTR parameters must be passed by keyword")
        counter = kwargs.pop("counter", None)
        if counter is not None:
            if kwargs:
                raise TypeError("counter cannot be combined with other CTR parameters")
            if not isinstance(counter, dict):
                raise TypeError("counter must be created with Crypto.Util.Counter.new")
            prefix = bytes(counter.get("prefix", b""))
            suffix = bytes(counter.get("suffix", b""))
            counter_length = int(counter["counter_len"])
            initial_value = int(counter.get("initial_value", 1))
            little_endian = bool(counter.get("little_endian", False))
            nonce = None
        else:
            nonce_value = kwargs.pop("nonce", None)
            nonce = (
                os.urandom(8)
                if nonce_value is None
                else _lib._bytes(nonce_value, "nonce")
            )
            if len(nonce) > 15:
                raise ValueError("Nonce is too long")
            counter_length = 16 - len(nonce)
            initial = kwargs.pop("initial_value", 0)
            if isinstance(initial, int):
                initial_value = initial
            else:
                initial_bytes = _lib._bytes(initial, "initial_value")
                if len(initial_bytes) != counter_length:
                    raise ValueError("Incorrect length for counter byte string")
                initial_value = int.from_bytes(initial_bytes, "big")
            prefix, suffix, little_endian = nonce, b"", False
            if kwargs:
                raise TypeError("unknown parameters for CTR mode")
        if len(prefix) + counter_length + len(suffix) != 16:
            raise ValueError("Size of the counter block must match block size")
        if initial_value < 0 or initial_value >= 1 << (8 * counter_length):
            raise ValueError("Initial counter value is too large")
        return _CtrMode(
            key_bytes,
            prefix,
            suffix,
            counter_length,
            initial_value,
            little_endian,
            nonce,
        )

    raise ValueError(
        "Mode not supported by mojo-pycryptodome; use ECB, CBC, or CTR"
    )
