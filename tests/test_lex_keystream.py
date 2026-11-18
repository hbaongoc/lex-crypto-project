"""Tests for the TV5 keystream buffer."""

from __future__ import annotations

import unittest

from lex.keystream import KeystreamBuffer


class FakeEngine:
    def __init__(self) -> None:
        self.blocks_generated = 0

    def next_block(self) -> bytes:
        start = self.blocks_generated * 40
        self.blocks_generated += 1
        return bytes((start + index) % 256 for index in range(40))


class TestKeystreamBuffer(unittest.TestCase):
    def test_read_across_40_byte_boundaries(self) -> None:
        for size in (39, 40, 41):
            with self.subTest(size=size):
                engine = FakeEngine()
                buffer = KeystreamBuffer(engine)
                self.assertEqual(
                    buffer.read(size),
                    bytes(index % 256 for index in range(size)),
                )
                self.assertEqual(engine.blocks_generated, (size + 39) // 40)

    def test_split_reads_match_one_contiguous_read(self) -> None:
        split = KeystreamBuffer(FakeEngine())
        full = KeystreamBuffer(FakeEngine())

        result = split.read(7) + split.read(10) + split.read(83)

        self.assertEqual(result, full.read(100))

    def test_unused_bytes_are_kept_for_next_read(self) -> None:
        engine = FakeEngine()
        buffer = KeystreamBuffer(engine)

        self.assertEqual(buffer.read(5), bytes(range(5)))
        self.assertEqual(buffer.read(35), bytes(range(5, 40)))
        self.assertEqual(engine.blocks_generated, 1)

    def test_zero_read_does_not_generate_a_block(self) -> None:
        engine = FakeEngine()
        buffer = KeystreamBuffer(engine)

        self.assertEqual(buffer.read(0), b"")
        self.assertEqual(engine.blocks_generated, 0)

    def test_invalid_read_lengths_are_rejected(self) -> None:
        buffer = KeystreamBuffer(FakeEngine())

        for value in (True, 1.5, "5", None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                buffer.read(value)

        with self.assertRaises(ValueError):
            buffer.read(-1)

    def test_engine_must_provide_next_block(self) -> None:
        with self.assertRaises(TypeError):
            KeystreamBuffer(object())

    def test_engine_output_must_be_bytes_like(self) -> None:
        class BadEngine:
            def next_block(self):
                return "not bytes"

        with self.assertRaises(TypeError):
            KeystreamBuffer(BadEngine()).read(1)

    def test_engine_output_must_contain_40_bytes(self) -> None:
        class BadEngine:
            def next_block(self):
                return bytes(39)

        with self.assertRaises(ValueError):
            KeystreamBuffer(BadEngine()).read(1)


if __name__ == "__main__":
    unittest.main()
