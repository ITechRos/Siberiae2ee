"""
Протокол сквозного шифрования «Сибирь».
- Эфемерный ECDH (ГОСТ Р 34.10-2012)
- KDF на Стрибог-256
- MGM-шифрование с подтверждением ключа
- Бинарная сериализация пакетов
"""
import struct, secrets
from .ec import generate_keypair, ecdh, ECPoint
from .hash import Streebog
from .mgm import mgm_encrypt, mgm_decrypt

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    h = Streebog(256)
    h.update(salt + shared_secret)
    return h.digest()

class SiberiaUser:
    def __init__(self):
        self.priv, self.pub = generate_keypair()
        self.pub_bytes = self.pub.x.to_bytes(32, 'big') + self.pub.y.to_bytes(32, 'big')

    def clear(self):
        if self.priv is not None:
            mask = secrets.token_bytes(32)
            self.priv ^= int.from_bytes(mask, 'big')
            self.priv = None

    def encrypt_for(self, recipient_pub_bytes: bytes, plaintext: bytes) -> bytes:
        # Генерируем одноразовый эфемерный ключ (PFS)
        eph_priv, eph_pub = generate_keypair()
        rx = int.from_bytes(recipient_pub_bytes[:32], 'big')
        ry = int.from_bytes(recipient_pub_bytes[32:], 'big')
        recipient_pub = ECPoint(rx, ry)
        shared = ecdh(eph_priv, recipient_pub)
        salt = secrets.token_bytes(16)
        key = derive_key(shared, salt)

        # Подтверждение ключа
        confirm = Streebog(256)
        confirm.update(b"CONFIRM" + self.pub_bytes)
        confirm.update(key)
        confirm_tag = confirm.digest()[:8]

        nonce = secrets.token_bytes(16)
        ct, tag = mgm_encrypt(key, nonce, plaintext)

        # Упаковка в бинарный формат
        pub = eph_pub.x.to_bytes(32, 'big') + eph_pub.y.to_bytes(32, 'big')
        # Формат: версия(1B) | pub(64B) | salt(16B) | nonce(16B) | длина ct(2B big) | ct | tag(16B) | confirm(8B)
        header = struct.pack(">B", 1)
        body = pub + salt + nonce + struct.pack(">H", len(ct)) + ct + tag + confirm_tag
        return header + body

    def decrypt_from(self, sender_pub_bytes: bytes, package: bytes) -> bytes:
        # Распаковка
        pos = 0
        version = package[pos]; pos += 1
        if version != 1:
            raise ValueError("Unknown packet version")
        pub = package[pos:pos+64]; pos += 64
        salt = package[pos:pos+16]; pos += 16
        nonce = package[pos:pos+16]; pos += 16
        ct_len = struct.unpack(">H", package[pos:pos+2])[0]; pos += 2
        ct = package[pos:pos+ct_len]; pos += ct_len
        tag = package[pos:pos+16]; pos += 16
        confirm_tag = package[pos:pos+8]; pos += 8

        # Восстанавливаем ephemeral публичный ключ отправителя
        sx = int.from_bytes(sender_pub_bytes[:32], 'big')
        sy = int.from_bytes(sender_pub_bytes[32:], 'big')
        sender_pub = ECPoint(sx, sy)

        shared = ecdh(self.priv, sender_pub)
        key = derive_key(shared, salt)

        # Проверяем подтверждение
        expected_confirm = Streebog(256)
        expected_confirm.update(b"CONFIRM" + sender_pub_bytes)
        expected_confirm.update(key)
        if expected_confirm.digest()[:8] != confirm_tag:
            raise ValueError("Key confirmation failed")

        plain = mgm_decrypt(key, nonce, ct, tag)
        return plain