"""
Режим аутентифицированного шифрования MGM (ГОСТ Р 34.13-2015).
Использует Кузнечик и Стрибог-256.
"""
from .cipher import Kuznechik
from .hash import Streebog

def inc128(x: bytes) -> bytes:
    n = int.from_bytes(x, 'little') + 1
    return n.to_bytes(16, 'little')

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def mgm_encrypt(key, nonce, plaintext, associated_data=b''):
    cipher = Kuznechik(key)
    pad_len = (-len(plaintext)) % 16
    padded = plaintext + b'\x00' * pad_len
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]

    Y = cipher.encrypt(nonce)
    ctr = Y
    C = []
    for block in blocks:
        ctr = inc128(ctr)
        C.append(xor(block, cipher.encrypt(ctr)))
    ciphertext = b''.join(C)[:len(plaintext)]

    # Аутентификация
    hasher = Streebog(256)
    hasher.update(associated_data + b'\x00'*((-len(associated_data))%16))
    hasher.update(ciphertext + b'\x00'*((-len(ciphertext))%16))
    token = hasher.digest()
    tag = xor(token, Y)
    return ciphertext, tag

def mgm_decrypt(key, nonce, ciphertext, tag, associated_data=b''):
    cipher = Kuznechik(key)
    Y = cipher.encrypt(nonce)
    hasher = Streebog(256)
    hasher.update(associated_data + b'\x00'*((-len(associated_data))%16))
    hasher.update(ciphertext + b'\x00'*((-len(ciphertext))%16))
    expected_tag = xor(hasher.digest(), Y)
    if tag != expected_tag:
        raise ValueError("Invalid tag")

    pad_len = (-len(ciphertext)) % 16
    padded_ct = ciphertext + b'\x00' * pad_len
    blocks = [padded_ct[i:i+16] for i in range(0, len(padded_ct), 16)]
    ctr = Y
    P = []
    for block in blocks:
        ctr = inc128(ctr)
        P.append(xor(block, cipher.encrypt(ctr)))
    plaintext = b''.join(P)[:len(ciphertext)]
    return plaintext