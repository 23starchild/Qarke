import asyncio
import os
import unittest
from qarmr_v9_core import (
    AEAD_TAG_LEN,
    HOP_LEN,
    HOPS_HEADER_LEN,
    INBOUND_RATE_LIMIT,
    MAX_HOPS,
    MAX_PAYLOAD_SIZE,
    MSG_ID_LEN,
    NONCE_LEN,
    PACKET_SIZE_LIMIT,
    SENDER_MAX_LEN,
    VERSION,
    AsyncConnectionPool,
    AuthenticationError,
    ConfigurationError,
    EpochReplayCache,
    HardRateLimiter,
    HopError,
    InsecureTestAuthenticator,
    PacketRejected,
    QARMRDataPlane,
    ReplayError,
    StructuralError,
    _canonicalize_hop,
    _ct_eq,
    create_qarmr_onion_packet,
    parse_frame,
    process_hop,
)


class TestQARMRv9Core(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.auth = InsecureTestAuthenticator()
        self.node_a = _canonicalize_hop(b"NODE_A")
        self.node_b = _canonicalize_hop(b"NODE_B")
        self.node_c = _canonicalize_hop(b"NODE_C")

    def test_packet_creation_and_parse_success(self):
        msg_id = os.urandom(MSG_ID_LEN)
        pkt = create_qarmr_onion_packet(
            hops=[self.node_a, self.node_b],
            payload=b"HELLO WORLD",
            sender=b"SENDER_X",
            msg_id=msg_id,
            authenticator=self.auth,
        )
        self.assertEqual(len(pkt), PACKET_SIZE_LIMIT)

        frame = parse_frame(pkt)
        self.assertEqual(frame.version, VERSION)
        self.assertEqual(frame.msg_id, msg_id)
        self.assertEqual(len(frame.nonce), NONCE_LEN)
        self.assertEqual(frame.sender, b"SENDER_X")
        self.assertEqual(frame.payload, b"HELLO WORLD")

    def test_first_hop_authorization(self):
        msg_id = os.urandom(MSG_ID_LEN)
        pkt = create_qarmr_onion_packet(
            hops=[self.node_a, self.node_b],
            payload=b"DATA",
            sender=b"SENDER",
            msg_id=msg_id,
            authenticator=self.auth,
        )
        frame = parse_frame(pkt)

        is_final, new_hops, current, next_t = process_hop(frame.hops_data, self.node_a)
        self.assertFalse(is_final)
        self.assertEqual(current, self.node_a)
        self.assertEqual(next_t, self.node_b)

        with self.assertRaises(HopError):
            process_hop(frame.hops_data, self.node_b)

    async def test_engine_processing_pipeline(self):
        engine = QARMRDataPlane(
            local_identity=b"NODE_A", authenticator=self.auth, max_workers=2
        )
        await engine.start()

        msg_id = os.urandom(MSG_ID_LEN)
        pkt = create_qarmr_onion_packet(
            hops=[self.node_a],
            payload=b"FINAL DESTINATION",
            sender=b"SENDER",
            msg_id=msg_id,
            authenticator=self.auth,
        )

        await engine.submit(pkt)
        await asyncio.sleep(0.1)

        stats = engine.get_telemetry()
        self.assertEqual(stats["packets_received"], 1)
        self.assertEqual(stats["packets_accepted"], 1)

        await engine.stop()


if __name__ == "__main__":
    unittest.main()
