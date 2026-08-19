"""
QARMR+ v1.0 - Standalone Post-Quantum Hybrid Onion Model
Forked from QARMR v4.7, now independent model line.
Architecture: Hybrid HKDF( X25519_ECDH || ML-KEM-768 ) + ChaCha20Poly1305
Wire: 32KB jumbo frames, 10-hop max, I2P-style randomized path selection
"""
import os, struct, random, hashlib, time, asyncio, logging
from typing import Dict, List, Tuple, Optional, Set, Callable
from collections import deque

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --- QARMR+ Constants ---
QARMR_PLUS_VERSION = "1.0"
QARMR_PLUS_WIRE_VERSION = 3 # independent from QARMR v4.7's VERSION=2

PACKET_SIZE_LIMIT = 32768
MSG_ID_LEN = 16
HOP_LEN = 16
SENDER_MAX_LEN = 32
INNER_PAD = 1024
MAX_HOPS = 10
TERMINAL_HOP = b"FINAL+"
DEFAULT_RANDOM_HOPS = 3

try:
    from cryptography.hazmat.primitives.asymmetric import ml_kem
    HAS_MLKEM = True
except ImportError:
    HAS_MLKEM = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [QARMR+ %(message)s]")

# --- Crypto Core ---
def qarmr_plus_kdf(x_shared: bytes, pq_shared: bytes = b"") -> bytes:
    return HKDF(hashes.SHA256(), 32, None, b"QARMR+ v1.0 hybrid KDF").derive(x_shared + pq_shared)

class QARMRPlusKeys:
    def __init__(self):
        self.x_priv = X25519PrivateKey.generate()
        self.x_pub_raw = self.x_priv.public_key().public_bytes_raw()
        if HAS_MLKEM:
            self.kem_priv = ml_kem.MLKEM768PrivateKey.generate()
            self.kem_pub_raw = self.kem_priv.public_key().public_bytes()
        else:
            self.kem_priv = None
            self.kem_pub_raw = b"\x00"*1184

    @property
    def pub_bundle(self) -> Tuple[bytes, bytes]:
        return (self.x_pub_raw, self.kem_pub_raw)

    def decapsulate(self, x_eph_raw: bytes, kem_ct: bytes) -> bytes:
        x_shared = self.x_priv.exchange(X25519PublicKey.from_public_bytes(x_eph_raw))
        pq_shared = self.kem_priv.decapsulate(kem_ct) if HAS_MLKEM and self.kem_priv and kem_ct else b""
        return qarmr_plus_kdf(x_shared, pq_shared)

def qarmr_plus_encrypt_layer(x_pub_raw: bytes, kem_pub_raw: bytes, plaintext: bytes) -> bytes:
    x_shared = X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(x_pub_raw))
    # ephemeral X key
    x_eph_priv = X25519PrivateKey.generate()
    x_shared_real = x_eph_priv.exchange(X25519PublicKey.from_public_bytes(x_pub_raw))

    kem_ct, pq_shared = b"", b""
    if HAS_MLKEM and kem_pub_raw[0]!=0:
        kem_ct, pq_shared = ml_kem.MLKEM768PublicKey.from_public_bytes(kem_pub_raw).encapsulate()

    key = qarmr_plus_kdf(x_shared_real, pq_shared)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return x_eph_priv.public_key().public_bytes_raw() + struct.pack("!H", len(kem_ct)) + kem_ct + nonce + ct

def qarmr_plus_decrypt_layer(priv: QARMRPlusKeys, blob: bytes) -> bytes:
    x_eph = blob[:32]
    clen = struct.unpack("!H", blob[32:34])[0]
    off = 34
    kem_ct = blob[off:off+clen]; off+=clen
    nonce = blob[off:off+12]; off+=12
    ct = blob[off:]
    key = priv.decapsulate(x_eph, kem_ct)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)

# --- Packet Creation (QARMR+ API) ---
def create_qarmr_plus_onion_packet(
    sender: str,
    payload: bytes,
    hops: List[bytes],
    hop_pub_bundles: Dict[bytes, Tuple[bytes, bytes]],
) -> bytes:
    if TERMINAL_HOP not in hops: hops = hops + [TERMINAL_HOP]
    if len(hops) > MAX_HOPS: raise ValueError(f"QARMR+ max {MAX_HOPS} hops")

    sb = sender.encode()[:SENDER_MAX_LEN].ljust(SENDER_MAX_LEN, b"\x00")
    inner = struct.pack("!I", len(payload)) + sb + payload
    inner = inner.ljust(INNER_PAD, b"\x00")

    blob = inner
    next_hop = b"\x00"*HOP_LEN
    for hop in reversed(hops):
        x_pub, kem_pub = hop_pub_bundles[hop]
        pt = (TERMINAL_HOP if hop==TERMINAL_HOP else next_hop).ljust(HOP_LEN, b"\x00") + blob
        blob = qarmr_plus_encrypt_layer(x_pub, kem_pub, pt)
        next_hop = hop

    pkt = QARMR_PLUS_WIRE_VERSION.to_bytes(1,'big') + os.urandom(MSG_ID_LEN) + blob
    if len(pkt) > PACKET_SIZE_LIMIT: raise ValueError(f"QARMR+ packet {len(pkt)} > {PACKET_SIZE_LIMIT}")
    return pkt.ljust(PACKET_SIZE_LIMIT, b"\x00")

def create_randomized_qarmr_plus_packet(
    sender: str,
    payload: bytes,
    peer_bundles: Dict[bytes, Tuple[bytes, bytes]],
    num_intermediate: int = DEFAULT_RANDOM_HOPS,
) -> bytes:
    peers = [p for p in peer_bundles.keys() if p!= TERMINAL_HOP]
    if len(peers) < num_intermediate: raise ValueError("insufficient peers")
    intermediates = random.sample(peers, num_intermediate)
    hops = intermediates + [TERMINAL_HOP]
    return create_qarmr_plus_onion_packet(sender, payload, hops, peer_bundles)

# --- Node ---
class EpochReplayCache:
    def __init__(self): self.seen = {}
    def is_replayed(self, d: bytes) -> bool:
        now = time.monotonic()
        self.seen = {k:v for k,v in self.seen.items() if now-v < 300}
        if d in self.seen: return True
        self.seen[d]=now; return False

class AsyncQARMRPlusNode:
    def __init__(self, name: str, host: str, port: int, rate_lambda=3.0):
        self.name = name.encode()
        self.host=host; self.port=port
        self.keys = QARMRPlusKeys()
        self.routing: Dict[bytes, Tuple[str,int,Tuple[bytes,bytes]]] = {}
        self.queue = asyncio.Queue(1024)
        self.replay = EpochReplayCache()
        self.rate = rate_lambda
        self.server=None; self.running=False; self.workers=set()
        self.payload_cb: Optional[Callable[[str,bytes],None]] = None

    def register_route(self, hop: bytes, host: str, port: int, bundle: Tuple[bytes,bytes]):
        self.routing[hop]=(host,port,bundle)

    async def start(self):
        self.running=True
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        for _ in range(4): self.workers.add(asyncio.create_task(self._worker()))
        logging.info(f"[{self.name.decode()}] QARMR+ {QARMR_PLUS_VERSION} Online {self.host}:{self.port} PQ={HAS_MLKEM}")

    async def stop(self):
        self.running=False
        self.server.close(); await self.server.wait_closed()
        for t in self.workers: t.cancel()

    async def _handle(self, r,w):
        try:
            while self.running:
                try: pkt = await asyncio.wait_for(r.readexactly(PACKET_SIZE_LIMIT),5.0)
                except: break
                self.queue.put_nowait(pkt)
        finally: w.close(); await w.wait_closed()

    async def _worker(self):
        while self.running:
            try:
                pkt = await self.queue.get()
                await asyncio.sleep(random.expovariate(self.rate))
                blob_stripped = pkt[1+MSG_ID_LEN:].rstrip(b"\x00")
                if self.replay.is_replayed(hashlib.sha256(blob_stripped).digest()): continue
                try:
                    if pkt[0]!=QARMR_PLUS_WIRE_VERSION: continue
                    pt = qarmr_plus_decrypt_layer(self.keys, blob_stripped)
                except: continue
                cur = pt[:HOP_LEN].rstrip(b"\x00")
                rest = pt[HOP_LEN:]
                if cur==TERMINAL_HOP:
                    pl = struct.unpack("!I", rest[:4])[0]
                    sender = rest[4:4+SENDER_MAX_LEN].rstrip(b"\x00").decode()
                    payload = rest[4+SENDER_MAX_LEN:4+SENDER_MAX_LEN+pl]
                    if self.payload_cb: self.payload_cb(sender, payload)
                    continue
                route = self.routing.get(cur)
                if not route: continue
                host,port,_ = route
                fwd = (QARMR_PLUS_WIRE_VERSION.to_bytes(1,'big') + pkt[1:1+MSG_ID_LEN] + rest).ljust(PACKET_SIZE_LIMIT,b"\x00")
                try:
                    _,ww = await asyncio.wait_for(asyncio.open_connection(host,port),3.0)
                    ww.write(fwd); await ww.drain(); ww.close(); await ww.wait_closed()
                except Exception as e: logging.error(f"fwd fail {e}")
            except asyncio.CancelledError: break

# Model identifier
QARMR_PLUS_MODEL_ID = f"QARMR+/{QARMR_PLUS_VERSION} PQ-Hybrid { 'MLKEM768+X25519' if HAS_MLKEM else 'X25519-only' }"
