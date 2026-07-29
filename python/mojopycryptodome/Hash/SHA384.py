"""SHA-384."""

from ._sha2 import SHA2Hash

digest_size = 48
block_size = 128
oid = "2.16.840.1.101.3.4.2.2"


def new(data=b""):
    return SHA2Hash(384, data)
