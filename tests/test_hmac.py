from __future__ import annotations

import hashlib
import hmac
import os

import pytest
from Crypto.Hash import HMAC as ReferenceHMAC
from Crypto.Hash import SHA224 as RefSHA224
from Crypto.Hash import SHA256 as RefSHA256
from Crypto.Hash import SHA384 as RefSHA384
from Crypto.Hash import SHA512 as RefSHA512

from mojopycryptodome.Hash import HMAC, SHA224, SHA256, SHA384, SHA512

MODULES = [
    (SHA224, RefSHA224, hashlib.sha224),
    (SHA256, RefSHA256, hashlib.sha256),
    (SHA384, RefSHA384, hashlib.sha384),
    (SHA512, RefSHA512, hashlib.sha512),
]


def test_rfc4231_sha256_vector():
    key = bytes.fromhex("0b" * 20)
    expected = bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )
    assert HMAC.new(key, b"Hi There", SHA256).digest() == expected


def test_rfc4231_sha512_vector():
    key = bytes.fromhex("0b" * 20)
    expected = bytes.fromhex(
        "87aa7cdea5ef619d4ff0b4241a1d6cb0"
        "2379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4"
        "be9d914eeb61f1702e696c203a126854"
    )
    assert HMAC.new(key, b"Hi There", SHA512).digest() == expected


@pytest.mark.parametrize(("module", "reference", "constructor"), MODULES)
@pytest.mark.parametrize("key_size", [0, 1, 63, 64, 65, 128, 129, 300])
def test_upstream_and_stdlib_parity(module, reference, constructor, key_size):
    key, message = os.urandom(key_size), os.urandom(1003)
    got = HMAC.new(key, message, module).digest()
    assert got == ReferenceHMAC.new(key, message, reference).digest()
    assert got == hmac.digest(key, message, constructor)


@pytest.mark.parametrize(("module", "_reference", "_constructor"), MODULES)
def test_incremental_copy_and_new(module, _reference, _constructor):
    key = os.urandom(100)
    original = HMAC.new(key, digestmod=module)
    original.update(b"prefix")
    duplicate = original.copy()
    original.update(b"-a")
    duplicate.update(b"-b")
    assert original.digest() == HMAC.new(key, b"prefix-a", module).digest()
    assert duplicate.digest() == HMAC.new(key, b"prefix-b", module).digest()
    assert original.new(key, b"fresh").digest() == HMAC.new(
        key, b"fresh", module
    ).digest()


def test_verify_and_hexverify():
    mac = HMAC.new(b"key", b"message", SHA256)
    mac.verify(mac.digest())
    mac.hexverify(mac.hexdigest())
    with pytest.raises(ValueError):
        mac.verify(bytes(mac.digest_size))
    with pytest.raises(ValueError):
        mac.hexverify("not hex")


@pytest.mark.parametrize("digestmod", [SHA256, "sha256", "SHA-256"])
def test_digest_module_name_forms(digestmod):
    assert HMAC.new(b"k", b"m", digestmod).digest() == hmac.digest(
        b"k", b"m", "sha256"
    )


def test_missing_or_unsupported_digest_is_rejected():
    with pytest.raises(ValueError):
        HMAC.new(b"k", b"m")
    with pytest.raises(ValueError):
        HMAC.new(b"k", b"m", "md5")


def test_noncontiguous_message_buffer_hashes_raw_bytes():
    message = memoryview(bytearray(range(32)))[::2]
    assert HMAC.new(b"k", message, SHA256).digest() == hmac.digest(
        b"k", message.tobytes(), hashlib.sha256
    )
