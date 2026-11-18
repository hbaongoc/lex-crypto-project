
"""Finite field GF(2^8) arithmetic for AES and LEX."""

AES_POLYNOMIAL = 0x11B


def _validate_byte(value: int) -> None:
    """Ensure that the input is a valid byte."""
    if not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise ValueError("Value must be an integer from 0 to 255.")


def gf_add(a: int, b: int) -> int:
    """Add two elements in GF(2^8) using XOR."""
    _validate_byte(a)
    _validate_byte(b)

    return a ^ b


def xtime(a: int) -> int:
    """Multiply an element by x (0x02) in GF(2^8)."""
    _validate_byte(a)

    result = a << 1

    if result & 0x100:
        result ^= AES_POLYNOMIAL

    return result & 0xFF


def gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    _validate_byte(a)
    _validate_byte(b)

    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        a = xtime(a)
        b >>= 1

    return result
