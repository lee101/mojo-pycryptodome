"""SHA-256."""

from ._sha2 import SHA2Hash

digest_size = 32
block_size = 64
oid = "2.16.840.1.101.3.4.2.1"


def new(data=b""):
    return SHA2Hash(256, data)
