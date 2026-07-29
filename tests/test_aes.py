from __future__ import annotations

import os

import pytest
from Crypto.Cipher import AES as ReferenceAES
from Crypto.Util import Counter

from mojopycryptodome import _lib
from mojopycryptodome.Cipher import AES


@pytest.mark.parametrize(
    ("key", "ciphertext"),
    [
        (
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ],
)
def test_nist_ecb_vectors(key, ciphertext):
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    assert cipher.encrypt(plaintext) == bytes.fromhex(ciphertext)
    assert AES.new(bytes.fromhex(key), AES.MODE_ECB).decrypt(
        bytes.fromhex(ciphertext)
    ) == plaintext


def test_nist_cbc_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    ciphertext = bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    )
    assert AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext) == ciphertext
    assert AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext) == plaintext


def test_nist_ctr_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    initial = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    ciphertext = bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    )
    counter = Counter.new(128, initial_value=int.from_bytes(initial, "big"))
    assert AES.new(key, AES.MODE_CTR, counter=counter).encrypt(
        plaintext
    ) == ciphertext


@pytest.mark.parametrize("key_length", [16, 24, 32])
@pytest.mark.parametrize("blocks", [0, 1, 7, 257])
def test_ecb_randomized_upstream_parity(key_length, blocks):
    key = os.urandom(key_length)
    data = os.urandom(blocks * 16)
    got = AES.new(key, AES.MODE_ECB).encrypt(data)
    expected = ReferenceAES.new(key, ReferenceAES.MODE_ECB).encrypt(data)
    assert got == expected
    assert AES.new(key, AES.MODE_ECB).decrypt(got) == data


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_cbc_randomized_upstream_parity_and_chunking(key_length):
    key, iv, data = os.urandom(key_length), os.urandom(16), os.urandom(16 * 19)
    expected = ReferenceAES.new(
        key, ReferenceAES.MODE_CBC, iv=iv
    ).encrypt(data)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    got = cipher.encrypt(data[: 16 * 3]) + cipher.encrypt(data[16 * 3 :])
    assert got == expected
    decryptor = AES.new(key, AES.MODE_CBC, iv=iv)
    assert decryptor.decrypt(got[:80]) + decryptor.decrypt(got[80:]) == data


def test_ctr_randomized_upstream_parity_across_partial_calls():
    key, nonce, data = os.urandom(32), os.urandom(7), os.urandom(1003)
    reference = ReferenceAES.new(
        key, ReferenceAES.MODE_CTR, nonce=nonce, initial_value=19
    )
    expected = reference.encrypt(data)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=19)
    got = (
        cipher.encrypt(data[:5])
        + cipher.encrypt(data[5:71])
        + cipher.encrypt(data[71:])
    )
    assert got == expected
    assert AES.new(
        key, AES.MODE_CTR, nonce=nonce, initial_value=19
    ).decrypt(expected) == data


def test_ctr_little_endian_prefix_suffix_counter_parity():
    key, data = os.urandom(16), os.urandom(517)
    params = dict(
        prefix=b"pre!",
        suffix=b"tail",
        initial_value=0x0102030405060708,
        little_endian=True,
    )
    got_counter = Counter.new(64, **params)
    ref_counter = Counter.new(64, **params)
    got = AES.new(key, AES.MODE_CTR, counter=got_counter).encrypt(data)
    expected = ReferenceAES.new(
        key, ReferenceAES.MODE_CTR, counter=ref_counter
    ).encrypt(data)
    assert got == expected


@pytest.mark.parametrize("mode", [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CTR])
def test_output_buffer_semantics(mode):
    key, iv, nonce = os.urandom(16), os.urandom(16), os.urandom(8)
    data = os.urandom(64)
    kwargs = {"iv": iv} if mode == AES.MODE_CBC else (
        {"nonce": nonce} if mode == AES.MODE_CTR else {}
    )
    expected = AES.new(key, mode, **kwargs).encrypt(data)
    destination = bytearray(len(data))
    result = AES.new(key, mode, **kwargs).encrypt(data, output=destination)
    assert result is None
    assert bytes(destination) == expected


def test_in_place_output_is_supported():
    key = os.urandom(16)
    data = bytearray(os.urandom(64))
    expected = AES.new(key, AES.MODE_ECB).encrypt(data)
    assert AES.new(key, AES.MODE_ECB).encrypt(data, output=data) is None
    assert bytes(data) == expected


@pytest.mark.parametrize("mode", [AES.MODE_CBC, AES.MODE_CTR])
def test_stateful_modes_support_in_place_output(mode):
    key, iv, nonce = os.urandom(16), os.urandom(16), os.urandom(8)
    kwargs = {"iv": iv} if mode == AES.MODE_CBC else {"nonce": nonce}
    data = bytearray(os.urandom(64))
    expected = AES.new(key, mode, **kwargs).encrypt(data)
    assert AES.new(key, mode, **kwargs).encrypt(data, output=data) is None
    assert bytes(data) == expected


def test_noncontiguous_and_typed_input_buffers_are_bytes():
    key = os.urandom(16)
    backing = bytearray(os.urandom(128))
    noncontiguous = memoryview(backing)[::2]
    assert AES.new(key, AES.MODE_ECB).encrypt(noncontiguous) == AES.new(
        key, AES.MODE_ECB
    ).encrypt(noncontiguous.tobytes())


def test_noncontiguous_output_is_rejected():
    output = memoryview(bytearray(32))[::2]
    with pytest.raises(TypeError):
        AES.new(bytes(16), AES.MODE_ECB).encrypt(bytes(16), output=output)


@pytest.mark.parametrize("length", [1, 15, 17, 31])
def test_block_modes_reject_unaligned_data(length):
    key = b"k" * 16
    with pytest.raises(ValueError):
        AES.new(key, AES.MODE_ECB).encrypt(b"x" * length)
    with pytest.raises(ValueError):
        AES.new(key, AES.MODE_CBC, iv=b"i" * 16).encrypt(b"x" * length)


@pytest.mark.parametrize("length", [0, 1, 15, 17, 31, 33])
def test_invalid_key_lengths(length):
    with pytest.raises(ValueError):
        AES.new(b"k" * length, AES.MODE_ECB)


def test_invalid_iv_nonce_mode_and_output_are_rejected():
    key = b"k" * 16
    with pytest.raises(ValueError):
        AES.new(key, AES.MODE_CBC, iv=b"short")
    with pytest.raises(ValueError):
        AES.new(key, AES.MODE_CTR, nonce=b"x" * 16)
    with pytest.raises(ValueError):
        AES.new(key, AES.MODE_GCM)
    with pytest.raises(ValueError):
        AES.new(key, AES.MODE_ECB).encrypt(b"x" * 16, output=bytearray(15))


def test_generated_iv_and_nonce_are_exposed():
    cbc = AES.new(b"k" * 16, AES.MODE_CBC)
    ctr = AES.new(b"k" * 16, AES.MODE_CTR)
    assert len(cbc.iv) == 16 and cbc.IV == cbc.iv
    assert len(ctr.nonce) == 8


@pytest.mark.parametrize(
    ("mode", "kwargs"),
    [
        (AES.MODE_CBC, {"iv": b"i" * 16}),
        (AES.MODE_CTR, {"nonce": b"n" * 8}),
    ],
)
def test_stateful_modes_reject_direction_changes(mode, kwargs):
    cipher = AES.new(b"k" * 16, mode, **kwargs)
    cipher.encrypt(b"x" * 16)
    with pytest.raises(TypeError):
        cipher.decrypt(b"x" * 16)


@pytest.mark.parametrize(
    ("mode", "kwargs"),
    [
        (AES.MODE_CBC, {"iv": b"i" * 16}),
        (AES.MODE_CTR, {"nonce": b"n" * 8}),
    ],
)
def test_failed_call_does_not_select_direction(mode, kwargs):
    cipher = AES.new(b"k" * 16, mode, **kwargs)
    with pytest.raises(ValueError):
        cipher.encrypt(b"x" * 16, output=bytearray(15))
    assert cipher.decrypt(b"x" * 16) is not None


def test_ctr_rejects_counter_wrap():
    counter = Counter.new(
        8, prefix=b"p" * 15, initial_value=255
    )
    cipher = AES.new(b"k" * 16, AES.MODE_CTR, counter=counter)
    cipher.encrypt(bytes(16))
    with pytest.raises(OverflowError):
        cipher.encrypt(b"x")


def test_aesni_and_software_fallback_match(monkeypatch):
    if not _lib._cpu_has_aesni():
        pytest.skip("AES-NI is unavailable on this CPU")
    key, iv, nonce, data = (
        bytes(range(32)),
        bytes(range(16)),
        bytes(range(8)),
        bytes(range(64)),
    )
    for mode, kwargs in [
        (AES.MODE_ECB, {}),
        (AES.MODE_CBC, {"iv": iv}),
        (AES.MODE_CTR, {"nonce": nonce}),
    ]:
        monkeypatch.setattr(_lib, "_USE_AESNI", False)
        software = AES.new(key, mode, **kwargs).encrypt(data)
        software_plaintext = AES.new(key, mode, **kwargs).decrypt(software)
        monkeypatch.setattr(_lib, "_USE_AESNI", True)
        accelerated = AES.new(key, mode, **kwargs).encrypt(data)
        accelerated_plaintext = AES.new(key, mode, **kwargs).decrypt(accelerated)
        assert accelerated == software
        assert software_plaintext == accelerated_plaintext == data
