import struct
import unittest

from dns_peer import build_response


def query(qtype=1, name=b"\x06wg-e2e\x04test\x00"):
    return b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)


class DnsPeerTest(unittest.TestCase):
    def test_a_query_returns_fixture_address(self):
        response = build_response(query())
        self.assertIsNotNone(response)
        self.assertGreaterEqual(len(response), 8)
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
        self.assertEqual(response[-4:], b"\x0a\x58\x00\x01")

    def test_aaaa_query_has_no_answer(self):
        response = build_response(query(28))
        self.assertIsNotNone(response)
        self.assertGreaterEqual(len(response), 8)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)

    def test_openvpn_name_uses_selected_address(self):
        response = build_response(
            query(name=b"\x08ovpn-e2e\x04test\x00"), b"\x0a\x59\x00\x01"
        )
        self.assertEqual(response[-4:], b"\x0a\x59\x00\x01")

    def test_xray_name_uses_selected_address(self):
        response = build_response(
            query(name=b"\x08xray-e2e\x04test\x00"), b"\x0a\x63\x00\x01"
        )
        self.assertEqual(response[-4:], b"\x0a\x63\x00\x01")

    def test_malformed_packet_is_ignored(self):
        self.assertIsNone(build_response(b"\x12\x34"))


if __name__ == "__main__":
    unittest.main()
