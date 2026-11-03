"""İnternet erişimi veya ek paket gerektirmeyen eğitim modeli testleri."""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "uygulama"))
from tcp_handshake_sim import create_handshake, validate_handshake, MAX_SEQ


class HandshakeTests(unittest.TestCase):
    def test_expected_three_step_sequence_is_valid(self) -> None:
        packets = create_handshake()
        self.assertTrue(validate_handshake(packets))
        self.assertEqual(len(packets), 3)

    def test_invalid_ack_is_rejected(self) -> None:
        packets = create_handshake()
        broken = (*packets[:2], replace(packets[2], acknowledgement=999))
        self.assertFalse(validate_handshake(broken))

    def test_missing_packet_is_rejected(self) -> None:
        self.assertFalse(validate_handshake(create_handshake()[:2]))

    def test_negative_sequence_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_handshake(client_isn=-1)

    def test_sequence_wrap_is_supported_in_toy_model(self) -> None:
        packets = create_handshake(client_isn=MAX_SEQ - 1)
        self.assertTrue(validate_handshake(packets))
        self.assertEqual(packets[1].acknowledgement, 0)


if __name__ == "__main__":
    unittest.main()
