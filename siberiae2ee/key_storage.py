"""
Зашифрованное хранение приватного ключа на основе ГОСТ.
PBKDF2-HMAC-Стрибог-512 с последующим шифрованием Кузнечик-MGM.
"""
from .hash import Streebog
from .cipher import Kuznechik
from .mgm import mgm_encrypt, mgm_decrypt
import os, struct

BLOCK_SIZE = 64  # для Стрибог-512

def hmac_streebog(key: bytes, msg: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = Streebog.hash(key, 512)
    key = key.ljust(BLOCK_SIZE, b'\x00')
    o_key_pad = bytes(x ^ 0x5c for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return Streebog.hash(o_key_pad + Streebog.hash(i_key_pad + msg, 512), 512)

def pbkdf2_streebog(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    hlen = 64
    num_blocks = (dklen + hlen - 1) // hlen
    result = b''
    for block in range(1, num_blocks + 1):
        U = hmac_streebog(password, salt + struct.pack(">I", block))
        T = U
        for _ in range(iterations - 1):
            U = hmac_streebog(password, U)
            T = bytes(a ^ b for a, b in zip(T, U))
        result += T
    return result[:dklen]

def encrypt_private_key(private_key_bytes: bytes, password: str) -> bytes:
    salt = os.urandom(32)
    kek = pbkdf2_streebog(password.encode('utf-8'), salt, 200000, 32)
    nonce = os.urandom(16)
    ct, tag = mgm_encrypt(kek, nonce, private_key_bytes)
    # salt(32) + nonce(16) + tag(16) + ct
    return salt + nonce + tag + ct

def decrypt_private_key(encrypted_blob: bytes, password: str) -> bytes:
    salt = encrypted_blob[:32]
    nonce = encrypted_blob[32:48]
    tag = encrypted_blob[48:64]
    ct = encrypted_blob[64:]
    kek = pbkdf2_streebog(password.encode('utf-8'), salt, 200000, 32)
    return mgm_decrypt(kek, nonce, ct, tag)