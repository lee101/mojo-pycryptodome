from __future__ import annotations

import os

import pytest
from Crypto.Cipher import ChaCha20 as ReferenceChaCha20

from mojopycryptodome.Cipher import ChaCha20


def test_rfc8439_block_vector_at_counter_one():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(64)
    assert cipher.encrypt(bytes(64)) == expected


@pytest.mark.parametrize("nonce_length", [8, 12, 24])
@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1025])
def test_randomized_upstream_parity(nonce_length, size):
    key, nonce, data = (
        os.urandom(32),
        os.urandom(nonce_length),
        os.urandom(size),
    )
    got = ChaCha20.new(key=key, nonce=nonce).encrypt(data)
    expected = ReferenceChaCha20.new(key=key, nonce=nonce).encrypt(data)
    assert got == expected
    assert ChaCha20.new(key=key, nonce=nonce).decrypt(got) == data


@pytest.mark.parametrize("nonce_length", [8, 12, 24])
def test_chunking_and_seek_match_upstream(nonce_length):
    key, nonce, data = os.urandom(32), os.urandom(nonce_length), os.urandom(731)
    reference = ReferenceChaCha20.new(key=key, nonce=nonce)
    expected = reference.encrypt(data)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    got = (
        cipher.encrypt(data[:3])
        + cipher.encrypt(data[3:129])
        + cipher.encrypt(data[129:])
    )
    assert got == expected
    cipher.seek(117)
    reference.seek(117)
    assert cipher.encrypt(data[:333]) == reference.encrypt(data[:333])


def test_output_and_in_place_semantics():
    key, nonce, data = os.urandom(32), os.urandom(12), os.urandom(257)
    expected = ChaCha20.new(key=key, nonce=nonce).encrypt(data)
    destination = bytearray(len(data))
    assert (
        ChaCha20.new(key=key, nonce=nonce).encrypt(data, output=destination)
        is None
    )
    assert bytes(destination) == expected
    in_place = bytearray(data)
    assert (
        ChaCha20.new(key=key, nonce=nonce).encrypt(
            in_place, output=in_place
        )
        is None
    )
    assert bytes(in_place) == expected


def test_generated_nonce_is_exposed():
    cipher = ChaCha20.new(key=b"k" * 32)
    assert len(cipher.nonce) == 8


def test_explicit_gpu_path_or_silent_cpu_fallback_matches_upstream():
    key, nonce = bytes(range(32)), bytes(range(12))
    data = bytes((index * 17 + 3) & 0xFF for index in range(1024 * 1024 + 37))
    got = ChaCha20.new(key=key, nonce=nonce, device="gpu").encrypt(data)
    expected = ReferenceChaCha20.new(key=key, nonce=nonce).encrypt(data)
    assert got == expected


def test_gpu_request_with_unaligned_stream_position_falls_back():
    key, nonce = bytes(range(32)), bytes(range(12))
    data = bytes(index & 0xFF for index in range(257))
    cipher = ChaCha20.new(key=key, nonce=nonce, device="gpu")
    reference = ReferenceChaCha20.new(key=key, nonce=nonce)
    cipher.seek(5)
    reference.seek(5)
    assert cipher.encrypt(data) == reference.encrypt(data)


def test_invalid_device_is_rejected():
    with pytest.raises(ValueError, match="device"):
        ChaCha20.new(key=bytes(32), nonce=bytes(12), device="tpu")


@pytest.mark.parametrize("key_length", [0, 16, 31, 33])
def test_invalid_key_length(key_length):
    with pytest.raises(ValueError):
        ChaCha20.new(key=b"k" * key_length)


@pytest.mark.parametrize("nonce_length", [0, 7, 9, 16, 23, 25])
def test_invalid_nonce_length(nonce_length):
    with pytest.raises(ValueError):
        ChaCha20.new(key=b"k" * 32, nonce=b"n" * nonce_length)


def test_invalid_seek_and_output_are_rejected():
    cipher = ChaCha20.new(key=b"k" * 32, nonce=b"n" * 12)
    with pytest.raises(ValueError):
        cipher.seek(-1)
    with pytest.raises(ValueError):
        cipher.encrypt(b"x", output=bytearray(2))


def test_failed_call_does_not_select_direction():
    cipher = ChaCha20.new(key=b"k" * 32, nonce=b"n" * 12)
    with pytest.raises(ValueError):
        cipher.encrypt(b"x", output=bytearray(2))
    assert cipher.decrypt(b"x")


def test_direction_change_is_rejected():
    cipher = ChaCha20.new(key=b"k" * 32, nonce=b"n" * 12)
    cipher.encrypt(b"x")
    with pytest.raises(TypeError):
        cipher.decrypt(b"x")


@pytest.mark.parametrize("size", [3, 4, 31, 32, 33, 36, 63])
def test_simd_width_and_scalar_tail_parity(size):
    key, nonce, data = bytes(range(32)), bytes(range(12)), bytes(range(size))
    cipher = ChaCha20.new(key=key, nonce=nonce)
    reference = ReferenceChaCha20.new(key=key, nonce=nonce)
    cipher.seek(5)
    reference.seek(5)
    assert cipher.encrypt(data) == reference.encrypt(data)
