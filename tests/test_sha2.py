from __future__ import annotations

import hashlib
import os
from array import array

import pytest
from Crypto.Hash import SHA224 as RefSHA224
from Crypto.Hash import SHA256 as RefSHA256
from Crypto.Hash import SHA384 as RefSHA384
from Crypto.Hash import SHA512 as RefSHA512

from mojopycryptodome.Hash import SHA224, SHA256, SHA384, SHA512

MODULES = [
    (SHA224, RefSHA224, hashlib.sha224),
    (SHA256, RefSHA256, hashlib.sha256),
    (SHA384, RefSHA384, hashlib.sha384),
    (SHA512, RefSHA512, hashlib.sha512),
]


@pytest.mark.parametrize(
    ("module", "expected"),
    [
        (
            SHA224,
            "23097d223405d8228642a477bda255b32aadbce4"
            "bda0b3f7e36c9da7",
        ),
        (
            SHA256,
            "ba7816bf8f01cfea414140de5dae2223b00361a3"
            "96177a9cb410ff61f20015ad",
        ),
        (
            SHA384,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab"
            "0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca1"
            "34c825a7",
        ),
        (
            SHA512,
            "ddaf35a193617abacc417349ae20413112e6fa4e"
            "89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23"
            "a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ],
)
def test_nist_abc_vectors(module, expected):
    assert module.new(b"abc").hexdigest() == expected


@pytest.mark.parametrize(
    ("module", "_reference", "hashlib_constructor"), MODULES
)
@pytest.mark.parametrize(
    "size", [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 4097]
)
def test_hashlib_parity_at_padding_boundaries(
    module, _reference, hashlib_constructor, size
):
    data = os.urandom(size)
    assert module.new(data).digest() == hashlib_constructor(data).digest()


@pytest.mark.parametrize(("module", "reference", "_hashlib"), MODULES)
def test_incremental_update_and_upstream_parity(module, reference, _hashlib):
    data = os.urandom(5003)
    got = module.new()
    expected = reference.new()
    for start, end in [(0, 1), (1, 64), (64, 1000), (1000, len(data))]:
        assert got.update(data[start:end]) is None
        expected.update(data[start:end])
    assert got.digest() == expected.digest()
    assert got.hexdigest() == expected.hexdigest()


@pytest.mark.parametrize(("module", "_reference", "_hashlib"), MODULES)
def test_copy_and_new_are_independent(module, _reference, _hashlib):
    original = module.new(b"prefix")
    duplicate = original.copy()
    original.update(b"-a")
    duplicate.update(b"-b")
    assert original.digest() == module.new(b"prefix-a").digest()
    assert duplicate.digest() == module.new(b"prefix-b").digest()
    assert original.new(b"fresh").digest() == module.new(b"fresh").digest()


@pytest.mark.parametrize(("module", "_reference", "_hashlib"), MODULES)
def test_module_and_object_sizes(module, _reference, _hashlib):
    digest = module.new()
    assert digest.digest_size == module.digest_size
    assert digest.block_size == module.block_size
    assert len(digest.digest()) == module.digest_size


def test_sha512_truncate_is_explicitly_rejected():
    with pytest.raises(ValueError):
        SHA512.new(truncate="256")


def test_mutable_update_is_snapshotted():
    data = bytearray(b"mutable input")
    digest = SHA256.new(data)
    data[:] = b"x" * len(data)
    assert digest.digest() == hashlib.sha256(b"mutable input").digest()


def test_noncontiguous_and_typed_buffers_hash_raw_bytes():
    backing = bytearray(range(32))
    noncontiguous = memoryview(backing)[::2]
    typed = array("I", [0x01020304, 0xA0B0C0D0])
    assert SHA256.new(noncontiguous).digest() == hashlib.sha256(
        noncontiguous.tobytes()
    ).digest()
    assert SHA256.new(typed).digest() == hashlib.sha256(
        memoryview(typed).tobytes()
    ).digest()
