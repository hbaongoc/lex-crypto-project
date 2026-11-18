"""Demonstrate the TV5 streaming and XOR API."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="LEX TV5 demonstration")
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use a deterministic fake RoundEngine (not real LEX)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(project_root / "src"))

    if args.mock:
        from tests.support.mock_lex_dependencies import install_mock_dependencies

        install_mock_dependencies()

    try:
        from lex.api import LEX, decrypt, encrypt
    except ImportError as exc:
        print("TV3 RoundEngine is not available yet.")
        print("Run the isolated TV5 demonstration with: python run_demo.py --mock")
        print(f"Details: {exc}")
        return 2

    # TV4 supplies these values after deriving the round keys and IV state.
    round_keys = (bytes(16),) * 11
    initial_state = bytes(16)
    plaintext = b"LEX stream API demo"

    ciphertext = encrypt(round_keys, initial_state, plaintext)
    recovered = decrypt(round_keys, initial_state, ciphertext)
    if recovered != plaintext:
        raise AssertionError("Decryption did not recover the plaintext")

    split_session = LEX(round_keys, initial_state)
    split_stream = split_session.keystream(7) + split_session.keystream(33)
    full_stream = LEX(round_keys, initial_state).keystream(40)
    if split_stream != full_stream:
        raise AssertionError("Split reads differ from one 40-byte read")

    mode = "MOCK - not a real LEX keystream" if args.mock else "LEX engine"
    print(f"Mode: {mode}")
    print(f"Plaintext: {plaintext!r}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered: {recovered!r}")
    print("Split 7 + 33 byte read matches a 40-byte read: PASS")
    print("Demo: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
