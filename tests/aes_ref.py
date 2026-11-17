"""AES-128 tham chiếu TỐI GIẢN, CHỈ DÙNG TRONG TEST của LEX engine.

Mục đích: để Khánh test round_engine trước khi code của Ngọc (transforms)
và Quân (key_schedule) được merge vào dev. KHÔNG import file này trong src/.
State: 16 byte xếp theo cột (FIPS-197), các hàm trả về list mới.
"""

from collections.abc import Sequence


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _build_sbox() -> list[int]:
    box = []
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if _gmul(x, y) == 1)
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        box.append(s ^ 0x63)
    return box


SBOX = _build_sbox()


def sub_bytes(state: Sequence[int]) -> list[int]:
    return [SBOX[b] for b in state]


def shift_rows(state: Sequence[int]) -> list[int]:
    # hàng r dịch trái r ô: s'[r][c] = s[r][(c + r) % 4]
    return [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(state: Sequence[int]) -> list[int]:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c : 4 * c + 4]
        out += [
            _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3,
            a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3,
            a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3),
            _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2),
        ]
    return out


def add_round_key(state: Sequence[int], key: Sequence[int]) -> list[int]:
    return [s ^ k for s, k in zip(state, key)]


def expand_key(key: bytes) -> list[bytes]:
    """AES-128 key schedule -> 11 round key, mỗi key 16 byte."""
    words = [list(key[4 * i : 4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], t)])
    return [bytes(b for w in words[4 * r : 4 * r + 4] for b in w) for r in range(11)]
