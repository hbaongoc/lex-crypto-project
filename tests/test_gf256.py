
"""Unit tests for GF(2^8) arithmetic."""

import pytest

from core.gf256 import gf_add, gf_mul, xtime


def test_gf_add():
    assert gf_add(0x57, 0x83) == 0xD4
    assert gf_add(0xFF, 0xFF) == 0x00
    assert gf_add(0x57, 0x00) == 0x57


def test_xtime():
    assert xtime(0x57) == 0xAE
    assert xtime(0xAE) == 0x47
    assert xtime(0x80) == 0x1B
    assert xtime(0x00) == 0x00


def test_gf_mul():
    assert gf_mul(0x57, 0x83) == 0xC1
    assert gf_mul(0x57, 0x13) == 0xFE
    assert gf_mul(0x57, 0x01) == 0x57
    assert gf_mul(0x57, 0x00) == 0x00


def test_commutative():
    assert gf_mul(0x57, 0x83) == gf_mul(0x83, 0x57)


@pytest.mark.parametrize("value", [-1, 256, 1000])
def test_invalid_byte(value):
    with pytest.raises(ValueError):
        xtime(value) 