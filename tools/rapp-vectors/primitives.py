#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Standard-library cryptographic primitives for the RAPP vector generator.

Deterministic CBOR (RFC 8949 section 4.2.1), HKDF (RFC 5869), X25519
(RFC 7748), ChaCha20-Poly1305 (RFC 8439), the Noise handshakes RAPP uses
(Noise Protocol Framework revision 34) and Ristretto255 (RFC 9496). Nothing
here imports the engine under test; selftest() checks each primitive against
the published values before any corpus is derived.
"""
import hashlib
import hmac
import struct

# ---------------------------------------------------------------- CBOR (RFC 8949 4.2.1)

# RFC 8949 section 3: argument widths and the simple values of major type 7.
ONE_BYTE_ARGUMENT_LIMIT = 1 << 8
TWO_BYTE_ARGUMENT_LIMIT = 1 << 16
FOUR_BYTE_ARGUMENT_LIMIT = 1 << 32
MAJOR_SIMPLE = 7
SIMPLE_FALSE, SIMPLE_TRUE, SIMPLE_NULL = 20, 21, 22
SIMPLE_VALUES = {SIMPLE_FALSE: False, SIMPLE_TRUE: True, SIMPLE_NULL: None}
# The low five bits of an initial byte: an argument below 24 is inline, and
# 24 to 27 announce a 1-, 2-, 4- or 8-byte argument.
ARGUMENT_MASK = 31
INLINE_ARGUMENT_LIMIT = 24
ARGUMENT_WIDTHS = {24: 1, 25: 2, 26: 4, 27: 8}


def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < ONE_BYTE_ARGUMENT_LIMIT:
        return bytes([(major << 5) | 24, n])
    if n < TWO_BYTE_ARGUMENT_LIMIT:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < FOUR_BYTE_ARGUMENT_LIMIT:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor(v):
    if v is False:
        return _head(MAJOR_SIMPLE, SIMPLE_FALSE)
    if v is True:
        return _head(MAJOR_SIMPLE, SIMPLE_TRUE)
    if v is None:
        return _head(MAJOR_SIMPLE, SIMPLE_NULL)
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def cbor_decode(b):
    """The value of one deterministic CBOR item that fills `b` exactly."""
    value, rest = _cbor_item(bytes(b))
    if rest:
        raise ValueError("trailing bytes")
    return value


def _cbor_item(b):
    major, info = b[0] >> 5, b[0] & ARGUMENT_MASK
    b = b[1:]
    if info < INLINE_ARGUMENT_LIMIT:
        n = info
    elif info in ARGUMENT_WIDTHS:
        width = ARGUMENT_WIDTHS[info]
        if len(b) < width:
            raise ValueError("truncated argument")
        n, b = int.from_bytes(b[:width], "big"), b[width:]
    else:
        raise ValueError("indefinite or reserved argument")
    if major == 0:
        return n, b
    if major == 1:
        return -1 - n, b
    if major in (2, 3) and len(b) < n:
        raise ValueError("truncated string")
    if major == 2:
        return b[:n], b[n:]
    if major == 3:
        return b[:n].decode("utf-8"), b[n:]
    if major == 4:
        items = []
        for _ in range(n):
            item, b = _cbor_item(b)
            items.append(item)
        return items, b
    if major == 5:
        entries = {}
        for _ in range(n):
            key, b = _cbor_item(b)
            entries[key], b = _cbor_item(b)
        return entries, b
    if major == MAJOR_SIMPLE and n in SIMPLE_VALUES:
        return SIMPLE_VALUES[n], b
    raise ValueError("unsupported item")


# ---------------------------------------------------------------- hashes, HKDF


def sha256(b):
    return hashlib.sha256(b).digest()


def sha512(b):
    return hashlib.sha512(b).digest()


def hmac256(k, m):
    return hmac.new(k, m, hashlib.sha256).digest()


def hmac512(k, m):
    return hmac.new(k, m, hashlib.sha512).digest()


def hkdf256(salt, ikm, info, length=32):
    prk = hmac256(salt, ikm)
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac256(prk, block + info + bytes([i]))
        out += block
        i += 1
    return out[:length]


# ---------------------------------------------------------------- X25519 (RFC 7748)

P = 2**255 - 19


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(bytes(k), "little")
    u = bytearray(u)
    u[31] &= 127
    x1 = int.from_bytes(bytes(u), "little") % P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = pow(da + cb, 2, P)
        z3 = x1 * pow(da - cb, 2, P) % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def x25519_public(k):
    return x25519(k, (9).to_bytes(32, "little"))


# ---------------------------------------------------------------- ChaCha20-Poly1305 (RFC 8439)

WORD_MASK = (1 << 32) - 1
# RFC 8439 section 2.3: the four constant words spell "expand 32-byte k".
CHACHA_CONSTANTS = list(struct.unpack("<4I", b"expand 32-byte k"))
# RFC 8439 section 2.5.1: r clears the top four bits of bytes 3, 7, 11 and 15
# and the bottom two bits of bytes 4, 8 and 12.
POLY1305_TOP_CLEARED = (3, 7, 11, 15)
POLY1305_BOTTOM_CLEARED = (4, 8, 12)
LOW_NIBBLE = 15
CLEAR_LOW_TWO_BITS = 252


def _rotl(v, c):
    return ((v << c) & WORD_MASK) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & WORD_MASK; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & WORD_MASK; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & WORD_MASK; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & WORD_MASK; s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key, counter, nonce):
    s = CHACHA_CONSTANTS[:]
    s += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    w = s[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & WORD_MASK for a, b in zip(w, s)])


def _chacha(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def _poly1305(key, msg):
    clamped = bytearray(key[:16])
    for i in POLY1305_TOP_CLEARED:
        clamped[i] &= LOW_NIBBLE
    for i in POLY1305_BOTTOM_CLEARED:
        clamped[i] &= CLEAR_LOW_TWO_BITS
    r = int.from_bytes(bytes(clamped), "little")
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + bytes([1]), "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return bytes(-len(b) % 16)


def aead_encrypt(key, nonce, aad, pt):
    otk = _chacha_block(key, 0, nonce)[:32]
    ct = _chacha(key, 1, nonce, pt)
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + _poly1305(otk, mac)


# ---------------------------------------------------------------- Noise (revision 34), 25519 / ChaChaPoly / SHA512

HASHLEN = 64


def _noise_hkdf(ck, ikm, n):
    tk = hmac512(ck, ikm)
    o1 = hmac512(tk, bytes([1]))
    o2 = hmac512(tk, o1 + bytes([2]))
    if n == 2:
        return o1, o2
    return o1, o2, hmac512(tk, o2 + bytes([3]))


class Symmetric:
    def __init__(self, name, prologue):
        n = name.encode()
        self.h = n + bytes(HASHLEN - len(n)) if len(n) <= HASHLEN else sha512(n)
        self.ck = self.h
        self.k = None
        self.n = 0
        self.mix_hash(prologue)

    def mix_hash(self, data):
        self.h = sha512(self.h + data)

    def mix_key(self, ikm):
        self.ck, tk = _noise_hkdf(self.ck, ikm, 2)
        self.k, self.n = tk[:32], 0

    def mix_key_and_hash(self, ikm):
        self.ck, th, tk = _noise_hkdf(self.ck, ikm, 3)
        self.mix_hash(th)
        self.k, self.n = tk[:32], 0

    def encrypt_and_hash(self, pt):
        if self.k is None:
            ct = pt
        else:
            ct = aead_encrypt(self.k, bytes(4) + struct.pack("<Q", self.n), self.h, pt)
            self.n += 1
        self.mix_hash(ct)
        return ct

    def split(self):
        a, b = _noise_hkdf(self.ck, b"", 2)
        return a[:32], b[:32]


def noise_xxpsk3(prologue, i_s, r_s, i_e, r_e, psk):
    """Both sides of Noise_XXpsk3_25519_ChaChaPoly_SHA512 with empty payloads, run as one transcript."""
    st = Symmetric("Noise_XXpsk3_25519_ChaChaPoly_SHA512", prologue)
    i_e_pub, r_e_pub = x25519_public(i_e), x25519_public(r_e)
    i_s_pub, r_s_pub = x25519_public(i_s), x25519_public(r_s)
    # -> e
    m1 = i_e_pub
    st.mix_hash(i_e_pub); st.mix_key(i_e_pub)
    m1 += st.encrypt_and_hash(b"")
    # <- e, ee, s, es
    m2 = r_e_pub
    st.mix_hash(r_e_pub); st.mix_key(r_e_pub)
    st.mix_key(x25519(r_e, i_e_pub))
    m2 += st.encrypt_and_hash(r_s_pub)
    st.mix_key(x25519(r_s, i_e_pub))
    m2 += st.encrypt_and_hash(b"")
    # -> s, se, psk
    m3 = st.encrypt_and_hash(i_s_pub)
    st.mix_key(x25519(i_s, r_e_pub))
    st.mix_key_and_hash(psk)
    m3 += st.encrypt_and_hash(b"")
    c1, c2 = st.split()
    return [m1, m2, m3], st.h, c1, c2


def noise_kk(prologue, i_s, r_s, i_e, r_e):
    """Both sides of Noise_KK_25519_ChaChaPoly_SHA512 with empty payloads, run as one transcript."""
    st = Symmetric("Noise_KK_25519_ChaChaPoly_SHA512", prologue)
    i_s_pub, r_s_pub = x25519_public(i_s), x25519_public(r_s)
    i_e_pub, r_e_pub = x25519_public(i_e), x25519_public(r_e)
    st.mix_hash(i_s_pub); st.mix_hash(r_s_pub)
    # -> e, es, ss
    m1 = i_e_pub
    st.mix_hash(i_e_pub)
    st.mix_key(x25519(i_e, r_s_pub))
    st.mix_key(x25519(i_s, r_s_pub))
    m1 += st.encrypt_and_hash(b"")
    # <- e, ee, se
    m2 = r_e_pub
    st.mix_hash(r_e_pub)
    st.mix_key(x25519(r_e, i_e_pub))
    st.mix_key(x25519(r_e, i_s_pub))
    m2 += st.encrypt_and_hash(b"")
    c1, c2 = st.split()
    return [m1, m2], st.h, c1, c2


# ---------------------------------------------------------------- Ristretto255 (RFC 9496)

Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _neg(x):
    return x % P % 2 == 1


def _abs(x):
    x %= P
    return P - x if _neg(x) else x


def _sqrt_ratio_m1(u, v):
    u %= P; v %= P
    v3 = v * v * v % P
    v7 = v3 * v3 * v % P
    r = u * v3 * pow(u * v7, (P - 5) // 8, P) % P
    check = v * r * r % P
    correct = check == u
    flipped = check == (-u) % P
    flipped_i = check == (-u * SQRT_M1) % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return correct or flipped, _abs(r)


# RFC 9496 4.1 fixes the negative root of a*d - 1.
SQRT_AD_MINUS_ONE = P - _sqrt_ratio_m1((-D - 1) % P, 1)[1]
assert SQRT_AD_MINUS_ONE == 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = _sqrt_ratio_m1(1, (-1 - D) % P)[1]
assert INVSQRT_A_MINUS_D == 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = (1 - D * D) % P
D_MINUS_ONE_SQ = (D - 1) ** 2 % P


def _add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


IDENTITY = (0, 1, 1, 0)


def scalar_mult(k, pt):
    acc = IDENTITY
    for bit in bin(k % Q)[2:]:
        acc = _add(acc, acc)
        if bit == "1":
            acc = _add(acc, pt)
    return acc


def _map(t):
    r = SQRT_M1 * t * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = _sqrt_ratio_m1(u, v)
    if not was_square:
        s = (-_abs(s * t)) % P
        c = r
    else:
        c = P - 1
    n = (c * (r - 1) * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s * v % P
    w1 = n * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def from_uniform_bytes(b):
    mask = (1 << 255) - 1
    r0 = (int.from_bytes(b[:32], "little") & mask) % P
    r1 = (int.from_bytes(b[32:64], "little") & mask) % P
    return _add(_map(r0), _map(r1))


def encode(pt):
    x0, y0, z0, t0 = pt
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = _sqrt_ratio_m1(1, u1 * u2 * u2)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 * t0 % P
    if _neg(t0 * z_inv):
        x, y, den_inv = y0 * SQRT_M1 % P, x0 * SQRT_M1 % P, den1 * INVSQRT_A_MINUS_D % P
    else:
        x, y, den_inv = x0, y0, den2
    if _neg(x * z_inv):
        y = (-y) % P
    return _abs(den_inv * (z0 - y)).to_bytes(32, "little")


def decode(b):
    s = int.from_bytes(b, "little")
    if s >= P or _neg(s):
        raise ValueError("non-canonical")
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2s = u2 * u2 % P
    v = (-(D * u1 * u1) - u2s) % P
    was_square, invsqrt = _sqrt_ratio_m1(1, v * u2s)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x * v % P
    x = _abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or _neg(t) or y == 0:
        raise ValueError("invalid point")
    return (x, y, 1, t)


def _basepoint():
    y = 4 * pow(5, P - 2, P) % P
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if x % 2:
        x = P - x
    return (x, y, 1, x * y % P)


BASEPOINT = _basepoint()


# ---------------------------------------------------------------- self-test


# RFC 7748 section 6.1: Alice's private key and public key.
RFC7748_ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
RFC7748_ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
# RFC 8439 section 2.8.2: AEAD key, nonce, additional data, plaintext and tag.
RFC8439_KEY_FIRST_BYTE = 128
RFC8439_NONCE = "070000004041424344454647"
RFC8439_AAD = "50515253c0c1c2c3c4c5c6c7"
RFC8439_PLAINTEXT = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                     b"for the future, sunscreen would be it.")
RFC8439_TAG = "1ae10b594f09e26a7e902ecbd0600691"
# RFC 8949 section 4.2.1: map keys sort by their encoded bytes, so "z" precedes "aa".
RFC8949_MAP_ORDER = "a2617a0162616102"
# RFC 9496 appendix A.1: encodings of the generator and its double.
RFC9496_B = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
RFC9496_2B = "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"


def selftest():
    assert x25519_public(bytes.fromhex(RFC7748_ALICE_PRIVATE)).hex() == RFC7748_ALICE_PUBLIC
    key = bytes(range(RFC8439_KEY_FIRST_BYTE, RFC8439_KEY_FIRST_BYTE + 32))
    sealed = aead_encrypt(key, bytes.fromhex(RFC8439_NONCE), bytes.fromhex(RFC8439_AAD), RFC8439_PLAINTEXT)
    assert sealed[-16:].hex() == RFC8439_TAG
    assert encode(BASEPOINT).hex() == RFC9496_B
    assert encode(scalar_mult(2, BASEPOINT)).hex() == RFC9496_2B
    assert decode(bytes.fromhex(RFC9496_2B)) is not None
    assert cbor({"z": 1, "aa": 2}).hex() == RFC8949_MAP_ORDER
    sample = {"z": [1, -2, b"ab", "c", True, None], "aa": {"n": ONE_BYTE_ARGUMENT_LIMIT}}
    assert cbor_decode(cbor(sample)) == sample
