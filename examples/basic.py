from mojopycryptodome.Cipher import AES, ChaCha20
from mojopycryptodome.Hash import HMAC, SHA256

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
iv = bytes(16)
plaintext = b"one AES block!!!"

ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(plaintext)
assert AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext) == plaintext

stream = ChaCha20.new(key=bytes(32), nonce=bytes(12))
encrypted = stream.encrypt(b"arbitrary length")

digest = SHA256.new(b"message").hexdigest()
tag = HMAC.new(key, b"message", SHA256).digest()
assert len(digest) == 64
assert len(tag) == 32
assert encrypted != b"arbitrary length"
