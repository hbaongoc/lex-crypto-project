"""Public streaming and one-shot API for the LEX project.

TV5 consumes the outputs of TV4 (round keys and initial AES state) and
delegates keystream generation to TV3's RoundEngine.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeAlias

from .keystream import KeystreamBuffer

ByteData: TypeAlias = bytes | bytearray | memoryview
RoundKeys: TypeAlias = Sequence[bytes]


def _coerce_data(data: ByteData, *, name: str) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(data)


class LEX:
    """One stateful LEX stream.

    Args:
        round_keys: The 11 AES-128 round keys produced by TV2/TV4.
        initial_state: The 16-byte initial state produced by TV4's IV setup.

    A LEX instance has one stream position. Use a new instance for each
    independent message.
    """

    def __init__(self, round_keys: RoundKeys, initial_state: ByteData) -> None:
        try:
            from .round_engine import RoundEngine
        except ImportError as exc:
            raise ImportError(
                "TV3 round_engine.py must be available before the LEX API can run"
            ) from exc

        state = _coerce_data(initial_state, name="initial_state")
        if len(state) != 16:
            raise ValueError("initial_state must contain exactly 16 bytes")

        self._engine = RoundEngine(round_keys, state)
        self._keystream = KeystreamBuffer(self._engine)

    def keystream(self, n_bytes: int) -> bytes:
        """Return the next n_bytes of keystream."""
        return self._keystream.read(n_bytes)

    def process(self, data: ByteData) -> bytes:
        """Encrypt or decrypt data using the next keystream bytes."""
        raw_data = _coerce_data(data, name="data")
        stream = self._keystream.read(len(raw_data))
        return bytes(
            data_byte ^ stream_byte for data_byte, stream_byte in zip(raw_data, stream)
        )


def encrypt(
    round_keys: RoundKeys,
    initial_state: ByteData,
    plaintext: ByteData,
) -> bytes:
    """Encrypt one message with a fresh LEX stream.

    TV4 is responsible for deriving round_keys and initial_state from key/IV.
    """
    return LEX(round_keys, initial_state).process(plaintext)


def decrypt(
    round_keys: RoundKeys,
    initial_state: ByteData,
    ciphertext: ByteData,
) -> bytes:
    """Decrypt one message with a fresh LEX stream."""
    return LEX(round_keys, initial_state).process(ciphertext)
