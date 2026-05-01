"""
Эллиптическая кривая ГОСТ Р 34.10-2012 (256 бит, параметры A).
Генерация ключевых пар и вычисление общего секрета ECDH.
"""
import secrets

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
a = 0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335
b = 0x295F9BAE7428ED9ACC20F1E1DAEBD3F1189C1DF25D4BA794B35A8BD7A6829C83
q = 0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67
Gx = 0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28
Gy = 0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADBE3C46E73

def modinv(a, m):
    return pow(a, -1, m)

class ECPoint:
    def __init__(self, x, y):
        self.x = x % p
        self.y = y % p
        self.is_inf = False

    @staticmethod
    def inf():
        pt = ECPoint(0, 0)
        pt.is_inf = True
        return pt

    def __eq__(self, other):
        if self.is_inf and other.is_inf:
            return True
        return not self.is_inf and not other.is_inf and self.x == other.x and self.y == other.y

    def __add__(self, other):
        if self.is_inf: return other
        if other.is_inf: return self
        if self.x == other.x and (self.y + other.y) % p == 0:
            return ECPoint.inf()
        if self == other:
            lam = (3 * self.x * self.x + a) * modinv(2 * self.y, p) % p
        else:
            lam = (other.y - self.y) * modinv(other.x - self.x, p) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)

    def __mul__(self, scalar):
        result = ECPoint.inf()
        addend = self
        while scalar:
            if scalar & 1:
                result += addend
            addend += addend
            scalar >>= 1
        return result

G = ECPoint(Gx, Gy)

def generate_keypair():
    priv = int.from_bytes(secrets.token_bytes(32), 'big') % q
    pub = G * priv
    return priv, pub

def ecdh(priv, pub):
    shared = pub * priv
    return shared.x.to_bytes(32, 'big')