"""Trích xuất leak (Leak EXtraction) cho LEX.

Quy ước trạng thái (state)
--------------------------
State AES là 16 byte xếp theo CỘT như FIPS-197:
    byte thứ k  <->  b[r][c] với  k = r + 4*c   (r = hàng, c = cột)

        c=0  c=1  c=2  c=3
    r=0  0    4    8   12
    r=1  1    5    9   13
    r=2  2    6   10   14
    r=3  3    7   11   15

Vị trí leak (Biryukov, "The Design of a Stream Cipher LEX")
------------------------------------------------------------
- Vòng LẺ  : b(0,0), b(2,0), b(0,2), b(2,2)  -> chỉ số 0, 2, 8, 10
- Vòng CHẴN: b(0,1), b(2,1), b(0,3), b(2,3)  -> chỉ số 4, 6, 12, 14
Mỗi vòng ra 4 byte, mỗi lần AES 10 vòng ra 40 byte keystream.
Leak được lấy SAU khi kết thúc một vòng đầy đủ (sau AddRoundKey).
"""

from __future__ import annotations

from collections.abc import Sequence

STATE_SIZE = 16
LEAK_SIZE = 4

# (hàng, cột) theo đúng thứ tự byte được xuất ra
ODD_POSITIONS: tuple[tuple[int, int], ...] = ((0, 0), (2, 0), (0, 2), (2, 2))
EVEN_POSITIONS: tuple[tuple[int, int], ...] = ((0, 1), (2, 1), (0, 3), (2, 3))


def rc_to_index(row: int, col: int) -> int:
    """Đổi (hàng, cột) sang chỉ số trong mảng 16 byte xếp theo cột."""
    if not (0 <= row < 4 and 0 <= col < 4):
        raise ValueError(f"(row, col) phải trong [0, 3], nhận ({row}, {col})")
    return row + 4 * col


ODD_INDICES: tuple[int, ...] = tuple(rc_to_index(r, c) for r, c in ODD_POSITIONS)    # (0, 2, 8, 10)
EVEN_INDICES: tuple[int, ...] = tuple(rc_to_index(r, c) for r, c in EVEN_POSITIONS)  # (4, 6, 12, 14)


def leak_indices(round_no: int) -> tuple[int, ...]:
    """Trả về 4 chỉ số byte cần leak ở vòng `round_no` (đếm từ 1)."""
    if not isinstance(round_no, int) or isinstance(round_no, bool):
        raise TypeError("round_no phải là số nguyên")
    if round_no < 1:
        raise ValueError(f"round_no đếm từ 1, nhận {round_no}")
    return ODD_INDICES if round_no % 2 == 1 else EVEN_INDICES


def _check_state(state: Sequence[int]) -> None:
    if len(state) != STATE_SIZE:
        raise ValueError(f"state phải dài {STATE_SIZE} byte, nhận {len(state)}")
    for b in state:
        if not (isinstance(b, int) and 0 <= b <= 0xFF):
            raise ValueError(f"mỗi phần tử state phải là byte 0..255, nhận {b!r}")


def extract_leak(state: Sequence[int], round_no: int) -> bytes:
    """Lấy 4 byte leak từ `state` sau vòng thứ `round_no`.

    >>> s = bytes(range(16))
    >>> extract_leak(s, 1).hex()   # vòng lẻ: chỉ số 0, 2, 8, 10
    '0002080a'
    >>> extract_leak(s, 2).hex()   # vòng chẵn: chỉ số 4, 6, 12, 14
    '04060c0e'
    """
    _check_state(state)
    return bytes(state[i] for i in leak_indices(round_no))
