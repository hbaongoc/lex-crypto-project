"""Buffer 40-byte keystream blocks into a continuous byte stream."""

from __future__ import annotations

from typing import Any

_BLOCK_SIZE = 40


class KeystreamBuffer:
    """Read any number of bytes from a TV3 round engine."""

    def __init__(self, engine: Any) -> None:
        if not callable(getattr(engine, "next_block", None)):
            raise TypeError("engine must provide a callable next_block()")
        self._engine = engine
        self._buffer = bytearray()

    def read(self, n_bytes: int) -> bytes:
        """Return exactly n_bytes, keeping unused bytes for the next read."""
        if not isinstance(n_bytes, int) or isinstance(n_bytes, bool):
            raise TypeError("n_bytes must be an integer")
        if n_bytes < 0:
            raise ValueError("n_bytes must be nonnegative")
        if n_bytes == 0:
            return b""

        while len(self._buffer) < n_bytes:
            block = self._engine.next_block()
            if not isinstance(block, (bytes, bytearray, memoryview)):
                raise TypeError("next_block() must return bytes-like data")
            if len(block) != _BLOCK_SIZE:
                raise ValueError("next_block() must return exactly 40 bytes")
            self._buffer.extend(block)

        result = bytes(self._buffer[:n_bytes])
        del self._buffer[:n_bytes]
        return result
