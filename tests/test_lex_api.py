"""Tests for the TV5 public API using a deterministic TV3 stand-in."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from lex.api import LEX, decrypt, encrypt
from tests.support.mock_round_engine import build_mock_round_engine_module

ROUND_KEYS = (bytes(16),) * 11
INITIAL_STATE = bytes(16)


class TestLEXAPI(unittest.TestCase):
    def setUp(self) -> None:
        self.dependencies = patch.dict(
            "sys.modules",
            {"lex.round_engine": build_mock_round_engine_module()},
        )
        self.dependencies.start()
        self.addCleanup(self.dependencies.stop)

    def test_encrypt_decrypt_round_trip(self) -> None:
        plaintext = b"LEX TV5 API"
        ciphertext = encrypt(ROUND_KEYS, INITIAL_STATE, plaintext)

        self.assertIsInstance(ciphertext, bytes)
        self.assertEqual(decrypt(ROUND_KEYS, INITIAL_STATE, ciphertext), plaintext)

    def test_streaming_matches_one_shot(self) -> None:
        plaintext = bytes(index % 256 for index in range(151))
        expected = encrypt(ROUND_KEYS, INITIAL_STATE, plaintext)

        session = LEX(ROUND_KEYS, INITIAL_STATE)
        actual = (
            session.process(plaintext[:39])
            + session.process(plaintext[39:40])
            + session.process(plaintext[40:])
        )

        self.assertEqual(actual, expected)

    def test_keystream_and_process_share_one_position(self) -> None:
        session = LEX(ROUND_KEYS, INITIAL_STATE)
        prefix = session.keystream(7)
        encrypted = session.process(b"AB")
        stream_for_data = bytes(
            encrypted_byte ^ plain_byte
            for encrypted_byte, plain_byte in zip(encrypted, b"AB")
        )

        self.assertEqual(prefix + stream_for_data, bytes(range(9)))

    def test_each_session_has_an_independent_position(self) -> None:
        first = LEX(ROUND_KEYS, INITIAL_STATE)
        second = LEX(ROUND_KEYS, INITIAL_STATE)

        self.assertEqual(first.keystream(7), bytes(range(7)))
        self.assertEqual(second.keystream(3), bytes(range(3)))
        self.assertEqual(first.keystream(3), bytes(range(7, 10)))
        self.assertEqual(second.keystream(7), bytes(range(3, 10)))

    def test_empty_data_does_not_consume_keystream(self) -> None:
        session = LEX(ROUND_KEYS, INITIAL_STATE)

        self.assertEqual(session.process(b""), b"")
        self.assertEqual(session.keystream(0), b"")
        self.assertEqual(session.keystream(5), bytes(range(5)))

    def test_bytes_like_inputs_are_supported(self) -> None:
        ciphertext = encrypt(
            ROUND_KEYS,
            bytearray(INITIAL_STATE),
            memoryview(b"LEX"),
        )

        self.assertEqual(decrypt(ROUND_KEYS, INITIAL_STATE, ciphertext), b"LEX")

    def test_invalid_round_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            LEX((bytes(16),) * 10, INITIAL_STATE)
        with self.assertRaises(ValueError):
            LEX((bytes(15),) + (bytes(16),) * 10, INITIAL_STATE)

    def test_invalid_state_and_data_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            LEX(ROUND_KEYS, "bad state")
        with self.assertRaises(ValueError):
            LEX(ROUND_KEYS, bytes(15))
        with self.assertRaises(TypeError):
            LEX(ROUND_KEYS, INITIAL_STATE).process("not bytes")

    def test_invalid_request_does_not_advance_stream(self) -> None:
        session = LEX(ROUND_KEYS, INITIAL_STATE)

        with self.assertRaises(ValueError):
            session.keystream(-1)
        with self.assertRaises(TypeError):
            session.process("not bytes")

        self.assertEqual(session.keystream(5), bytes(range(5)))


if __name__ == "__main__":
    unittest.main()
