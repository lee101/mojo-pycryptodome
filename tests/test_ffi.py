from __future__ import annotations

from mojopycryptodome import _lib


def test_native_exports_reject_invalid_addresses_and_lengths():
    native = _lib.lib()
    assert native.mpc_aes_ecb(0, 0, -1, 0, 16, 0, 0) != 0
    assert native.mpc_aes_cbc(0, 0, 16, 0, 16, 0, 0, 0) != 0
    assert native.mpc_aes_ctr(0, 0, 1, 0, 16, 0, 0, 0, 16, 0, 0) != 0
    assert native.mpc_chacha20(0, 0, 1, 0, 32, 0, 12, 0) != 0
    assert native.mpc_sha256(0, -1, 0, 0) != 0
    assert native.mpc_sha512(0, 1, 0, 0) != 0
