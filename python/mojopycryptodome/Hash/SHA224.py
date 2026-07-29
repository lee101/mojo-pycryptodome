"""SHA-224."""

from ._sha2 import SHA2Hash

digest_size = 28
block_size = 64
oid = "2.16.840.1.101.3.4.2.4"


def new(data=b""):
    return SHA2Hash(224, data)
