"""Deterministic TV3 stand-in for testing the TV5 API in isolation."""

from __future__ import annotations

import sys
import types
from types import ModuleType
from typing import Any


class MockRoundEngine:
    """Produce deterministic 40-byte blocks; not the LEX algorithm."""

    def __init__(self, round_keys: Any, initial_state: bytes) -> None:
        if not isinstance(round_keys, (tuple, list)) or len(round_keys) != 11:
            raise ValueError("round_keys must contain 11 entries")
        if any(len(bytes(key)) != 16 for key in round_keys):
            raise ValueError("each round key must contain 16 bytes")
        if len(initial_state) != 16:
            raise ValueError("initial_state must contain 16 bytes")
        self._seed = (sum(round_keys[0]) + sum(initial_state)) % 256
        self._block_number = 0

    def next_block(self) -> bytes:
        start = self._seed + self._block_number * 40
        self._block_number += 1
        return bytes((start + index) % 256 for index in range(40))


def build_mock_dependencies() -> dict[str, ModuleType]:
    round_engine = types.ModuleType("lex.round_engine")
    round_engine.RoundEngine = MockRoundEngine
    return {"lex.round_engine": round_engine}


def install_mock_dependencies() -> None:
    """Install a deterministic fake RoundEngine in sys.modules."""
    sys.modules.update(build_mock_dependencies())
