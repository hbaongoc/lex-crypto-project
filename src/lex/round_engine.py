"""LEX round engine: chạy các vòng AES trên state và gom leak thành keystream.

Luồng LEX (Biryukov):
    1. Key schedule AES-128 cho K  -> 11 round key k0..k10      (Quân)
    2. IV setup: S = AES_K(IV) (AES chuẩn)                      (Dương)
    3. Sinh keystream: S được mã hóa lặp kiểu OFB; sau MỖI vòng
       lấy 4 byte leak -> 40 byte / 10 vòng                     (Khánh - file này)
    4. Đệm keystream, XOR với plaintext                         (Quyết)

Biến thể vòng dùng cho keystream (mặc định của run_block / RoundEngine):
    - KHÔNG có AddRoundKey(k0) "whitening" ở đầu mỗi lần 10 vòng
    - Cả 10 vòng đều đầy đủ: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(k_r)
    - State sau vòng 10 nối thẳng sang vòng 1 của lần kế tiếp
  (theo mô tả LEX trong Dunkelman & Keller, ASIACRYPT 2008, footnote 2).
  Đặt whitening=True, final_mix_columns=False sẽ ra đúng AES-128 chuẩn
  (dùng để kiểm tra với test vector FIPS-197 và cho bước IV setup).

Phụ thuộc: các phép biến đổi AES lấy từ module của Ngọc (src/aes/transforms.py,
import là `aes.transforms`) qua tham số `ops`. Hợp đồng (contract) mong đợi ở module đó:
    sub_bytes(state)            -> state mới
    shift_rows(state)           -> state mới
    mix_columns(state)          -> state mới
    add_round_key(state, key16) -> state mới
  với state = 16 byte xếp theo cột (FIPS-197). Hàm trả về None (sửa tại chỗ)
  cũng được chấp nhận.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

# Quy ước của repo: CI đặt PYTHONPATH=src nên import không có tiền tố "src."
from lex.extractor import LEAK_SIZE, STATE_SIZE, extract_leak

ROUNDS_PER_BLOCK = 10
NUM_ROUND_KEYS = ROUNDS_PER_BLOCK + 1              # k0..k10
LEAK_BYTES_PER_BLOCK = LEAK_SIZE * ROUNDS_PER_BLOCK  # 40


# --------------------------------------------------------------------------- #
# Tiện ích nội bộ
# --------------------------------------------------------------------------- #
def _default_ops() -> Any:
    """Module transforms của Ngọc. Import trễ để test được khi chưa merge."""
    from aes import transforms

    return transforms


def _to_block(data: Sequence[int], name: str) -> bytes:
    """Ép về bytes 16 phần tử, báo lỗi rõ ràng nếu sai."""
    try:
        block = bytes(data)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{name} phải là 16 byte (bytes/bytearray/list[int])") from exc
    if len(block) != STATE_SIZE:
        raise ValueError(f"{name} phải dài {STATE_SIZE} byte, nhận {len(block)}")
    return block


def _call(fn: Callable[..., Any], state: bytes, *args: Any) -> bytes:
    """Gọi 1 phép biến đổi AES; chấp nhận cả kiểu trả về state mới lẫn sửa tại chỗ."""
    buf = list(state)
    result = fn(buf, *args)
    return _to_block(buf if result is None else result, f"kết quả {fn.__name__}")


def _check_round_keys(round_keys: Sequence[Sequence[int]]) -> list[bytes]:
    if len(round_keys) != NUM_ROUND_KEYS:
        raise ValueError(
            f"cần {NUM_ROUND_KEYS} round key (k0..k10), nhận {len(round_keys)}"
        )
    return [_to_block(k, f"round_keys[{i}]") for i, k in enumerate(round_keys)]


# --------------------------------------------------------------------------- #
# API chính
# --------------------------------------------------------------------------- #
def lex_round(
    state: Sequence[int],
    round_key: Sequence[int],
    *,
    mix_columns: bool = True,
    ops: Any | None = None,
) -> bytes:
    """Một vòng AES: SubBytes -> ShiftRows -> (MixColumns) -> AddRoundKey."""
    if ops is None:
        ops = _default_ops()
    s = _to_block(state, "state")
    key = _to_block(round_key, "round_key")

    s = _call(ops.sub_bytes, s)
    s = _call(ops.shift_rows, s)
    if mix_columns:
        s = _call(ops.mix_columns, s)
    s = _call(ops.add_round_key, s, key)
    return s


def run_block(
    state: Sequence[int],
    round_keys: Sequence[Sequence[int]],
    *,
    whitening: bool = False,
    final_mix_columns: bool = True,
    ops: Any | None = None,
) -> tuple[bytes, bytes]:
    """Chạy 10 vòng liên tiếp, leak sau mỗi vòng.

    Trả về (state_mới, leak_40_byte).
    Vòng r (1..10) dùng round key k_r; vòng lẻ/chẵn quyết định vị trí leak.
    """
    if ops is None:
        ops = _default_ops()
    keys = _check_round_keys(round_keys)
    s = _to_block(state, "state")

    if whitening:
        s = _call(ops.add_round_key, s, keys[0])

    leak = bytearray()
    for r in range(1, ROUNDS_PER_BLOCK + 1):
        use_mix = final_mix_columns or r < ROUNDS_PER_BLOCK
        s = lex_round(s, keys[r], mix_columns=use_mix, ops=ops)
        leak += extract_leak(s, r)

    return s, bytes(leak)


class RoundEngine:
    """Giữ state + round key, mỗi lần gọi next_block() trả 40 byte keystream.

    Ví dụ (sau khi có round_keys từ key_schedule và S từ iv_setup):
        engine = RoundEngine(round_keys, S)
        ks = engine.next_block() + engine.next_block()   # 80 byte
    """

    def __init__(
        self,
        round_keys: Sequence[Sequence[int]],
        initial_state: Sequence[int],
        *,
        ops: Any | None = None,
    ) -> None:
        self._ops = _default_ops() if ops is None else ops
        self._keys = _check_round_keys(round_keys)
        self._state = _to_block(initial_state, "initial_state")
        self.blocks_done = 0  # số lần chạy 10 vòng (để phần khác đổi khóa sau 500 lần nếu cần)

    @property
    def state(self) -> bytes:
        return self._state

    def next_block(self) -> bytes:
        """Chạy thêm 10 vòng, cập nhật state, trả về 40 byte leak."""
        self._state, leak = run_block(self._state, self._keys, ops=self._ops)
        self.blocks_done += 1
        return leak
