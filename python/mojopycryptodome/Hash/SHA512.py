"""SHA-512."""

from ._sha2 import SHA2Hash

digest_size = 64
block_size = 128
oid = "2.16.840.1.101.3.4.2.3"


def new(data=b"", truncate=None):
    if truncate is not None:
        raise ValueError("SHA-512/224 and SHA-512/256 are outside this port's scope")
    return SHA2Hash(512, data)
