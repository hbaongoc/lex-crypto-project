"""Unit test cho phần của Khánh: src/lex/extractor.py + src/lex/round_engine.py.

Chạy giống CI (từ thư mục gốc repo):
    PYTHONPATH=src python -m pytest tests -v
"""

import pytest

from lex.extractor import (
    EVEN_INDICES,
    ODD_INDICES,
    extract_leak,
    leak_indices,
    rc_to_index,
)
from lex.round_engine import (
    LEAK_BYTES_PER_BLOCK,
    RoundEngine,
    lex_round,
    run_block,
)
from tests import aes_ref as A

# FIPS-197 Appendix C.1 (AES-128)
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PT = bytes.fromhex("00112233445566778899aabbccddeeff")
CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
ROUND1_OUT = bytes.fromhex("89d810e8855ace682d1843d8cb128fe4")  # round[2].start
ROUND2_OUT = bytes.fromhex("4915598f55e5d7a0daca94fa1f0a63f7")  # round[3].start

RK = A.expand_key(KEY)


# ----------------------------- extractor ----------------------------------- #
def test_rc_to_index_column_major():
    assert rc_to_index(0, 0) == 0
    assert rc_to_index(2, 0) == 2
    assert rc_to_index(0, 1) == 4
    assert rc_to_index(2, 3) == 14


def test_leak_positions():
    assert ODD_INDICES == (0, 2, 8, 10)
    assert EVEN_INDICES == (4, 6, 12, 14)


@pytest.mark.parametrize("round_no", [1, 3, 5, 7, 9, 11])
def test_odd_rounds(round_no):
    assert leak_indices(round_no) == ODD_INDICES


@pytest.mark.parametrize("round_no", [2, 4, 6, 8, 10, 12])
def test_even_rounds(round_no):
    assert leak_indices(round_no) == EVEN_INDICES


def test_extract_simple():
    s = bytes(range(16))
    assert extract_leak(s, 1) == bytes([0, 2, 8, 10])
    assert extract_leak(s, 2) == bytes([4, 6, 12, 14])


def test_extract_on_fips_states():
    assert extract_leak(ROUND1_OUT, 1).hex() == "89102d43"
    assert extract_leak(ROUND2_OUT, 2).hex() == "55d71f63"


@pytest.mark.parametrize(
    ("state", "round_no"),
    [(bytes(15), 1), (bytes(16), 0), ([0] * 15 + [256], 1)],
    ids=["state-15-byte", "round-0", "byte-256"],
)
def test_extract_bad_inputs(state, round_no):
    with pytest.raises(ValueError):
        extract_leak(state, round_no)


def test_round_no_must_be_int():
    with pytest.raises(TypeError):
        leak_indices(1.0)


# ---------------------------- round engine --------------------------------- #
def test_standard_aes_matches_fips197():
    """whitening + bỏ MixColumns vòng cuối = AES chuẩn -> phải ra đúng CT."""
    ct, leak = run_block(PT, RK, whitening=True, final_mix_columns=False, ops=A)
    assert ct == CT
    assert len(leak) == LEAK_BYTES_PER_BLOCK
    assert leak[:8].hex() == "89102d4355d71f63"


def test_single_round():
    s0 = bytes(A.add_round_key(PT, RK[0]))
    assert lex_round(s0, RK[1], ops=A) == ROUND1_OUT


def test_lex_mode_matches_manual_loop():
    """Mode LEX: không whitening, đủ 4 phép ở cả 10 vòng, leak sau AddRoundKey."""
    state, leak = run_block(PT, RK, ops=A)

    s, expected = list(PT), bytearray()
    for r in range(1, 11):
        s = A.add_round_key(A.mix_columns(A.shift_rows(A.sub_bytes(s))), RK[r])
        idx = (0, 2, 8, 10) if r % 2 else (4, 6, 12, 14)
        expected += bytes(s[i] for i in idx)

    assert state == bytes(s)
    assert leak == bytes(expected)


def test_engine_chains_state():
    engine = RoundEngine(RK, PT, ops=A)
    ks = engine.next_block() + engine.next_block()

    s1, l1 = run_block(PT, RK, ops=A)
    s2, l2 = run_block(s1, RK, ops=A)
    assert ks == l1 + l2
    assert engine.state == s2
    assert engine.blocks_done == 2


def test_deterministic_and_iv_sensitive():
    a = RoundEngine(RK, PT, ops=A).next_block()
    b = RoundEngine(RK, PT, ops=A).next_block()
    c = RoundEngine(RK, CT, ops=A).next_block()
    assert a == b
    assert a != c


def test_accepts_inplace_ops():
    """Nếu transforms sửa tại chỗ và trả None thì engine vẫn chạy đúng."""

    class InPlace:
        @staticmethod
        def sub_bytes(s):
            s[:] = A.sub_bytes(s)

        @staticmethod
        def shift_rows(s):
            s[:] = A.shift_rows(s)

        @staticmethod
        def mix_columns(s):
            s[:] = A.mix_columns(s)

        @staticmethod
        def add_round_key(s, k):
            s[:] = A.add_round_key(s, k)

    assert run_block(PT, RK, ops=InPlace) == run_block(PT, RK, ops=A)


def test_bad_round_keys():
    with pytest.raises(ValueError):
        run_block(PT, RK[:10], ops=A)
    with pytest.raises(ValueError):
        RoundEngine(RK, bytes(8), ops=A)


# ------------------- tích hợp với transforms của Ngọc ----------------------- #
def test_integration_with_team_transforms():
    """Tự chạy khi src/aes/transforms.py của Ngọc đã merge vào dev và đã pull về."""
    pytest.importorskip("aes.transforms", reason="chưa có transforms của Ngọc")
    ct, _ = run_block(PT, RK, whitening=True, final_mix_columns=False)
    assert ct == CT
    assert run_block(PT, RK) == run_block(PT, RK, ops=A)
