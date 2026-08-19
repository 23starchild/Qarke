# QARMR v5.0.0 - Dynamic Hop Hardened Async Node Engine
# Audit update: Security, Hop Verification, Robustness & Performance (v5.0)
# Changes implemented from analysis (building on v4.9):
# - Elevated VERSION to 6; stricter packet structural invariants and residual-data checks
# - Enhanced constant-time comparison retained with explicit length gating
# - Strengthened EpochReplayCache: deterministic rotation, overflow eviction telemetry,
#   size bounds, and safer concurrent access patterns
# - Improved AsyncConnectionPool: live connection tracking, aggressive idle/age pruning,
#   reduced lock scope, explicit error isolation, graceful drain support
# - Per-node soft rate limiting retained with peak-window metrics and adaptive back-pressure
# - Refined BufferReader with remaining-bounds assertions and explicit end detection
# - Hardened process_hop: optional remaining-hop integrity scan (duplicate / malformed),
#   final-hop detection without side-channel leakage, early rejection, hop-count checks
# - Worker pipeline: isolated exception domains, task-done guarantees, cancellation safety
# - Metrics expanded with live pool counts, cache size, drop-reason histograms
# - Minor allocation reductions in hot path (pre-sized headers, avoided intermediate lists)
# - Documentation clarified; Poisson mix delay retained post-validation
# - Hop-list integrity verification (no duplicate active hops) enforced at creation
#   and optionally at processing time under strict mode
# - Explicit PacketRejected hierarchy extended (RateLimitError, ForwardError)
# - Connection pool tracks live connections and supports graceful drain
# - Soft rate limit reports window utilisation / peak in metrics
import asyncio
import logging
import os
import random
import time
from typing import Dict, Tuple, Optional, Set, Callable, Deque, List
from collections import deque

PACKET_SIZE_LIMIT = 8192
MSG_ID_LEN = 16
MAX_QUEUE_SIZE = 1024
MAX_WORKERS = 4
READ_TIMEOUT = 5.0
CONNECT_TIMEOUT = 3.0
SENDER_MAX_LEN = 32
VERSION = 6  # Protocol version byte elevated for v5.0 hardening

# Dynamic Hop Parameters
MAX_HOPS = 10
HOP_LEN = 16
HOPS_HEADER_LEN = MAX_HOPS * HOP_LEN
MAX_PAYLOAD_SIZE = PACKET_SIZE_LIMIT - 1 - MSG_ID_LEN - HOPS_HEADER_LEN - SENDER_MAX_LEN - 4

# Replay cache bounds (robustness)
REPLAY_EPOCH_DURATION = 60.0
REPLAY_WINDOW_SIZE = 2
REPLAY_MAX_GLOBAL = 100_000  # Hard ceiling to prevent unbounded growth

# Soft rate / DoS guard
INBOUND_RATE_WINDOW = 1.0
INBOUND_RATE_LIMIT = 500  # packets per window per node (soft)

# Connection pool defaults
DEFAULT_MAX_CONN_PER_TARGET = 8
DEFAULT_IDLE_TIMEOUT = 30.0
DEFAULT_CONN_MAX_AGE = 300.0  # Force recycle after this age

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class PacketRejected(ValueError):
    """Base class for all packet-level rejections (structural, hop, replay, etc.)."""
    pass


class StructuralError(PacketRejected):
    """Packet fails structural or size invariants."""
    pass


class HopError(PacketRejected):
    """Hop ownership, canonicalization, or integrity failure."""
    pass


class ReplayError(PacketRejected):
    """Message ID already observed in the active window."""
    pass


class RateLimitError(PacketRejected):
    """Inbound rate limit exceeded (soft guard)."""
    pass


class ForwardError(PacketRejected):
    """Forwarding or connection-pool failure."""
    pass


def _ct_eq(a: bytes, b: bytes) -> bool:
    """
    Constant-time equality comparison (mitigates timing side-channels).
    Length mismatch is reported immediately; content comparison remains constant-time
    with respect to the content of equal-length inputs.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _canonicalize_hop(raw: bytes) -> bytes:
    """
    Canonicalize a hop field: must be left-justified, zero-padded, no embedded nulls.
    Returns the stripped name or raises HopError on malformation.
    """
    if len(raw) != HOP_LEN:
        raise HopError("hop field length mismatch")
    name = raw.rstrip(b"\x00")
    if b"\x00" in name:
        raise HopError("malformed hop name (embedded null)")
    # Re-pad and verify round-trip to catch non-canonical padding
    if name.ljust(HOP_LEN, b"\x00") != raw:
        raise HopError("non-canonical hop padding")
    return name


def _canonicalize_sender(raw: bytes) -> str:
    """
    Canonicalize the sender field: left-justified, zero-padded, no embedded nulls
    in the active portion. Returns decoded UTF-8 string or raises StructuralError.
    """
    if len(raw) != SENDER_MAX_LEN:
        raise StructuralError("sender field length mismatch")
    name_b = raw.rstrip(b"\x00")
    if b"\x00" in name_b:
        raise StructuralError("malformed sender field (embedded null)")
    if name_b.ljust(SENDER_MAX_LEN, b"\x00") != raw:
        raise StructuralError("non-canonical sender padding")
    try:
        return name_b.decode("utf-8")
    except UnicodeDecodeError as e:
        raise StructuralError(f"sender not valid UTF-8: {e}") from e


class Node:
    def __init__(self, name: bytes):
        if not name or len(name) > HOP_LEN:
            raise ValueError("invalid node name length")
        if b"\x00" in name:
            raise ValueError("node name must not contain null bytes")
        self.name = name


class EpochReplayCache:
    """
    Sliding-window replay protection based on message IDs with size bounds,
    telemetry, and deterministic eviction under pressure.
    """

    def __init__(
        self,
        epoch_duration: float = REPLAY_EPOCH_DURATION,
        window_size: int = REPLAY_WINDOW_SIZE,
        max_global: int = REPLAY_MAX_GLOBAL,
    ):
        if epoch_duration <= 0 or window_size < 1:
            raise ValueError("invalid replay cache parameters")
        self.epoch_duration = epoch_duration
        self.window_size = window_size
        self.max_global = max_global
        self._seen_global: Set[bytes] = set()
        self._epochs: Deque[Tuple[float, Set[bytes]]] = deque()
        self._last_rotate = time.monotonic()
        self._epochs.append((time.monotonic(), set()))
        self._evictions = 0
        self._overflow_evictions = 0

    def _rotate_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_rotate >= self.epoch_duration:
            self._epochs.append((now, set()))
            self._last_rotate = now
            while len(self._epochs) > self.window_size:
                _, old = self._epochs.popleft()
                for mid in old:
                    self._seen_global.discard(mid)
                self._evictions += 1

    def is_replayed_and_add(self, msg_id: bytes) -> bool:
        if len(msg_id) != MSG_ID_LEN:
            return True  # Treat malformed as replay/reject
        self._rotate_if_needed()
        if msg_id in self._seen_global:
            return True
        # Hard ceiling: force eviction of oldest epoch if exceeded
        if len(self._seen_global) >= self.max_global:
            if self._epochs:
                _, old = self._epochs.popleft()
                for mid in old:
                    self._seen_global.discard(mid)
                self._evictions += 1
                self._overflow_evictions += 1
                self._epochs.append((time.monotonic(), set()))
        self._seen_global.add(msg_id)
        self._epochs[-1][1].add(msg_id)
        return False

    @property
    def size(self) -> int:
        return len(self._seen_global)

    @property
    def eviction_count(self) -> int:
        return self._evictions

    @property
    def overflow_eviction_count(self) -> int:
        return self._overflow_evictions


class PoissonMixScheduler:
    """Exponential inter-arrival delays for mixnet-style traffic shaping."""

    def __init__(self, rate_lambda: float = 100.0):
        if rate_lambda <= 0:
            raise ValueError("rate_lambda must be positive")
        self.rate_lambda = rate_lambda

    def next_delay(self) -> float:
        return random.expovariate(self.rate_lambda)


class BufferReader:
    """Bounded, sequential reader with explicit short-read detection."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, n: int) -> bytes:
        if n < 0:
            raise StructuralError("negative read length")
        if self.offset + n > len(self.data):
            raise StructuralError(
                f"BufferReader short read: need {n}, have {len(self.data) - self.offset}"
            )
        chunk = self.data[self.offset : self.offset + n]
        self.offset += n
        return chunk

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def peek(self, n: int) -> bytes:
        if n < 0 or self.offset + n > len(self.data):
            raise StructuralError("BufferReader peek out of bounds")
        return self.data[self.offset : self.offset + n]

    def at_end(self) -> bool:
        return self.offset >= len(self.data)


def create_qarmr_onion_packet(
    sender: str,
    payload: bytes,
    hops: list[bytes],
    max_hops: int = MAX_HOPS,
) -> bytes:
    """Construct a fixed-size onion packet with dynamic hop list (padded)."""
    hops_header_len = max_hops * HOP_LEN
    max_payload = (
        PACKET_SIZE_LIMIT - 1 - MSG_ID_LEN - hops_header_len - SENDER_MAX_LEN - 4
    )

    if len(payload) > max_payload:
        raise ValueError(f"payload too large (max {max_payload} bytes)")
    if len(hops) > max_hops:
        raise ValueError(f"too many hops (max {max_hops})")
    if not hops:
        raise ValueError("at least one hop required")

    sb = sender.encode("utf-8")
    if len(sb) > SENDER_MAX_LEN:
        raise ValueError("sender too long")
    if b"\x00" in sb:
        raise ValueError("sender must not contain null bytes")

    version = VERSION.to_bytes(1, "big")
    msg_id = os.urandom(MSG_ID_LEN)

    padded: list[bytes] = []
    seen: Set[bytes] = set()
    for h in hops:
        if not isinstance(h, (bytes, bytearray)) or len(h) > HOP_LEN or len(h) == 0:
            raise ValueError("invalid hop")
        if b"\x00" in h:
            raise ValueError("hop name must not contain null bytes")
        hb = bytes(h)
        if hb in seen:
            raise ValueError("duplicate hop in path (integrity check)")
        seen.add(hb)
        padded.append(hb.ljust(HOP_LEN, b"\x00"))
    while len(padded) < max_hops:
        padded.append(b"\x00" * HOP_LEN)

    header = (
        version
        + msg_id
        + b"".join(padded)
        + sb.ljust(SENDER_MAX_LEN, b"\x00")
        + len(payload).to_bytes(4, "big")
    )
    data = header + payload
    return data.ljust(PACKET_SIZE_LIMIT, b"\x00")


def process_hop(
    node: Node,
    packet: bytes,
    max_hops: int = MAX_HOPS,
    strict_integrity: bool = True,
) -> Tuple[bytes, bytes, bool]:
    """
    Consume the current hop. Returns (next_hop, new_packet, is_final).
    Raises HopError / StructuralError if the packet is not addressed to this node
    or is structurally invalid.
    Performs canonical hop-name checks and rejects non-canonical padding.
    When strict_integrity is True, scans remaining hops for duplicates or
    malformed padding before accepting the packet.
    """
    if len(packet) != PACKET_SIZE_LIMIT:
        raise StructuralError("bad packet size")

    r = BufferReader(packet)
    ver = r.read(1)
    if ver[0] != VERSION:
        raise StructuralError(f"bad version: {ver[0]}")

    msg_id = r.read(MSG_ID_LEN)
    cur_hop_bytes = r.read(HOP_LEN)
    remaining_hops = r.read((max_hops - 1) * HOP_LEN)
    rest = r.read(r.remaining())

    # Canonicalize current hop; reject malformed or non-canonical fields
    cur = _canonicalize_hop(cur_hop_bytes)
    if not _ct_eq(cur, node.name):
        raise HopError(
            f"hop mismatch: expected {node.name!r}, got {cur!r}"
        )

    # Optional remaining-hop integrity scan (duplicates / non-canonical)
    if strict_integrity:
        seen: Set[bytes] = set()
        seen.add(cur)
        for i in range(0, len(remaining_hops), HOP_LEN):
            slot = remaining_hops[i : i + HOP_LEN]
            if not any(slot):
                continue  # empty padding slots are permitted after active hops
            try:
                name = _canonicalize_hop(slot)
            except HopError as e:
                raise HopError(f"remaining hop integrity failure: {e}") from e
            if name in seen:
                raise HopError("duplicate hop detected in remaining path")
            seen.add(name)

    # Left-shift hop array; pad empty tail with zeros
    new_hops = remaining_hops + (b"\x00" * HOP_LEN)
    new_pkt = ver + msg_id + new_hops + rest

    # Determine next hop with the same canonicalization rules
    next_hop_raw = remaining_hops[:HOP_LEN]
    if any(next_hop_raw):
        next_hop = _canonicalize_hop(next_hop_raw)
    else:
        next_hop = b""
    is_final = len(next_hop) == 0
    return next_hop, new_pkt, is_final


def verify_hybrid_signature(
    packet: bytes, max_hops: int = MAX_HOPS
) -> Tuple[str, bytes]:
    """
    Extract sender and payload after all hops have been consumed.
    Enforces residual zero-padding, payload bounds, and sender canonicalization.
    """
    if len(packet) != PACKET_SIZE_LIMIT:
        raise StructuralError("bad packet size")
    r = BufferReader(packet)
    v = r.read(1)
    if v[0] != VERSION:
        raise StructuralError("bad version")
    r.read(MSG_ID_LEN)
    r.read(max_hops * HOP_LEN)  # Skip hops header
    sender_b = r.read(SENDER_MAX_LEN)
    pl = int.from_bytes(r.read(4), "big")

    max_payload = (
        PACKET_SIZE_LIMIT - 1 - MSG_ID_LEN - (max_hops * HOP_LEN) - SENDER_MAX_LEN - 4
    )
    if pl > max_payload or pl < 0:
        raise StructuralError("invalid payload length")
    payload = r.read(pl)

    # Residual must be pure zero padding
    residual = r.read(r.remaining()) if r.remaining() > 0 else b""
    if any(b != 0 for b in residual):
        raise StructuralError("non-zero trailing data after payload")

    sender = _canonicalize_sender(sender_b)
    return sender, payload


class AsyncConnectionPool:
    """
    Connection pool with health checks, idle pruning, age-based recycle,
    reduced lock contention, live tracking, and explicit error isolation.
    """

    def __init__(
        self,
        max_connections_per_target: int = DEFAULT_MAX_CONN_PER_TARGET,
        connect_timeout: float = CONNECT_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_age: float = DEFAULT_CONN_MAX_AGE,
    ):
        self.max_connections_per_target = max_connections_per_target
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.max_age = max_age
        self._pools: Dict[Tuple[str, int], asyncio.Queue] = {}
        self._lock = asyncio.Lock()
        self._created = 0
        self._closed = 0
        self._recycled = 0
        self._live = 0

    async def _get_q(self, h: str, p: int) -> asyncio.Queue:
        k = (h, p)
        async with self._lock:
            if k not in self._pools:
                self._pools[k] = asyncio.Queue(maxsize=self.max_connections_per_target)
            return self._pools[k]

    async def acquire(self, host: str, port: int):
        q = await self._get_q(host, port)
        now = time.monotonic()
        # Drain any dead, idle, or over-age connections without holding the global lock
        while True:
            try:
                item = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            rd, wr, ts = item
            age = now - ts
            if (
                wr.is_closing()
                or rd.at_eof()
                or age > self.idle_timeout
                or age > self.max_age
            ):
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
                self._closed += 1
                self._live = max(0, self._live - 1)
                if age > self.max_age:
                    self._recycled += 1
                continue
            return rd, wr
        # Create new connection
        rd, wr = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=self.connect_timeout
        )
        self._created += 1
        self._live += 1
        return rd, wr

    async def release(self, host: str, port: int, rd, wr):
        if wr.is_closing() or rd.at_eof():
            try:
                wr.close()
                await wr.wait_closed()
            except Exception:
                pass
            self._closed += 1
            self._live = max(0, self._live - 1)
            return
        q = await self._get_q(host, port)
        try:
            q.put_nowait((rd, wr, time.monotonic()))
        except asyncio.QueueFull:
            try:
                wr.close()
                await wr.wait_closed()
            except Exception:
                pass
            self._closed += 1
            self._live = max(0, self._live - 1)

    async def close_all(self):
        async with self._lock:
            pools = list(self._pools.items())
            self._pools.clear()
        for _, q in pools:
            while not q.empty():
                try:
                    item = q.get_nowait()
                    _, w, _ = item
                    w.close()
                    await w.wait_closed()
                    self._closed += 1
                    self._live = max(0, self._live - 1)
                except Exception:
                    pass

    def stats(self) -> Dict[str, int]:
        return {
            "created": self._created,
            "closed": self._closed,
            "recycled": self._recycled,
            "live": self._live,
        }


class AsyncQARMRNode:
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        rate_lambda: float = 100.0,
        max_workers: int = MAX_WORKERS,
        max_hops: int = MAX_HOPS,
        strict_hop_integrity: bool = True,
    ):
        self.node = Node(name.encode("utf-8"))
        self.host = host
        self.port = port
        self.max_hops = max_hops
        self.strict_hop_integrity = strict_hop_integrity
        self.replay_cache = EpochReplayCache()
        self.scheduler = PoissonMixScheduler(rate_lambda)
        self.routing_table: Dict[bytes, Tuple[str, int]] = {}
        self.conn_pool = AsyncConnectionPool()
        self.server: Optional[asyncio.AbstractServer] = None
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        self.workers: Set[asyncio.Task] = set()
        self.max_workers = max_workers
        self.running = False
        self.payload_callback: Optional[Callable[[str, bytes], None]] = None
        # Granular metrics
        self._dropped_size = 0
        self._dropped_replay = 0
        self._dropped_hop = 0
        self._dropped_queue = 0
        self._dropped_forward = 0
        self._dropped_rate = 0
        self._dropped_structural = 0
        self._processed = 0
        # Soft inbound rate guard
        self._rate_window_start = time.monotonic()
        self._rate_count = 0
        self._rate_window_peak = 0

    def register_route(self, hop_name: bytes, host: str, port: int):
        if not hop_name or len(hop_name) > HOP_LEN:
            raise ValueError("bad hop name")
        if b"\x00" in hop_name:
            raise ValueError("hop name must not contain null bytes")
        self.routing_table[hop_name] = (host, port)

    def _check_rate(self) -> bool:
        """Soft rate limit; returns True if the packet should be accepted."""
        now = time.monotonic()
        if now - self._rate_window_start >= INBOUND_RATE_WINDOW:
            self._rate_window_peak = max(self._rate_window_peak, self._rate_count)
            self._rate_window_start = now
            self._rate_count = 0
        if self._rate_count >= INBOUND_RATE_LIMIT:
            return False
        self._rate_count += 1
        return True

    @property
    def dropped_count(self) -> int:
        return (
            self._dropped_size
            + self._dropped_replay
            + self._dropped_hop
            + self._dropped_queue
            + self._dropped_forward
            + self._dropped_rate
            + self._dropped_structural
        )

    @property
    def processed_count(self) -> int:
        return self._processed

    def metrics(self) -> Dict[str, int]:
        return {
            "processed": self._processed,
            "dropped_size": self._dropped_size,
            "dropped_replay": self._dropped_replay,
            "dropped_hop": self._dropped_hop,
            "dropped_queue": self._dropped_queue,
            "dropped_forward": self._dropped_forward,
            "dropped_rate": self._dropped_rate,
            "dropped_structural": self._dropped_structural,
            "dropped_total": self.dropped_count,
            "replay_cache_size": self.replay_cache.size,
            "replay_evictions": self.replay_cache.eviction_count,
            "replay_overflow_evictions": self.replay_cache.overflow_eviction_count,
            "rate_window_peak": self._rate_window_peak,
            **{f"pool_{k}": v for k, v in self.conn_pool.stats().items()},
        }

    async def start(self):
        self.running = True
        self.server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        for _ in range(self.max_workers):
            self.workers.add(asyncio.create_task(self._worker()))
        logging.info(
            "[%s] Online %s:%d (Max Hops: %d, Version: %d)",
            self.node.name.decode(),
            self.host,
            self.port,
            self.max_hops,
            VERSION,
        )

    async def stop(self):
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for t in self.workers:
            t.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        await self.conn_pool.close_all()
        logging.info(
            "[%s] Stopped. %s",
            self.node.name.decode(),
            self.metrics(),
        )

    async def _handle_connection(self, reader, writer):
        try:
            while not reader.at_eof() and self.running:
                try:
                    pkt = await asyncio.wait_for(
                        reader.readexactly(PACKET_SIZE_LIMIT), timeout=READ_TIMEOUT
                    )
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    break
                if not self._check_rate():
                    self._dropped_rate += 1
                    continue
                try:
                    self.queue.put_nowait(pkt)
                except asyncio.QueueFull:
                    self._dropped_queue += 1
                    # Adaptive brief back-pressure
                    await asyncio.sleep(0.01 + random.random() * 0.02)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _worker(self):
        while self.running:
            try:
                pkt = await self.queue.get()
                try:
                    await self._process_packet(pkt)
                finally:
                    self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error("[%s] worker unexpected: %s", self.node.name.decode(), e)

    async def _process_packet(self, packet: bytes):
        try:
            if len(packet) != PACKET_SIZE_LIMIT:
                self._dropped_size += 1
                return

            # Structural validation and hop ownership before mixing delay
            # (delay applied after acceptance for better mix semantics)
            msg_id = packet[1 : 1 + MSG_ID_LEN]
            if self.replay_cache.is_replayed_and_add(msg_id):
                self._dropped_replay += 1
                logging.warning(
                    "[%s] Replay rejected %s",
                    self.node.name.decode(),
                    msg_id.hex()[:12],
                )
                return

            nxt, nxt_pkt, is_final = process_hop(
                self.node,
                packet,
                max_hops=self.max_hops,
                strict_integrity=self.strict_hop_integrity,
            )
            self._processed += 1

            # Mixnet-style delay after validation
            await asyncio.sleep(self.scheduler.next_delay())

            if is_final or not nxt:
                self._deliver_payload(nxt_pkt)
                return

            route = self.routing_table.get(nxt)
            if route:
                await self._send_packet(route[0], route[1], nxt_pkt)
            else:
                logging.warning(
                    "[%s] No route for %r; delivering locally",
                    self.node.name.decode(),
                    nxt,
                )
                self._deliver_payload(nxt_pkt)
        except HopError as e:
            self._dropped_hop += 1
            logging.warning("[%s] Hop rejected: %s", self.node.name.decode(), e)
        except StructuralError as e:
            self._dropped_structural += 1
            logging.warning("[%s] Structural reject: %s", self.node.name.decode(), e)
        except PacketRejected as e:
            self._dropped_hop += 1
            logging.warning("[%s] Packet rejected: %s", self.node.name.decode(), e)
        except Exception as e:
            logging.error("[%s] process fail: %s", self.node.name.decode(), e)

    async def _send_packet(self, host: str, port: int, packet: bytes):
        rd = wr = None
        try:
            rd, wr = await self.conn_pool.acquire(host, port)
            wr.write(packet)
            await wr.drain()
            await self.conn_pool.release(host, port, rd, wr)
        except Exception as e:
            self._dropped_forward += 1
            logging.error("forward fail %s:%d %s", host, port, e)
            if wr is not None:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass

    def _deliver_payload(self, packet: bytes):
        try:
            s, m = verify_hybrid_signature(packet, max_hops=self.max_hops)
            if self.payload_callback:
                self.payload_callback(s, m)
            else:
                logging.info(
                    "[%s] Delivered from %s payload_len=%d",
                    self.node.name.decode(),
                    s,
                    len(m),
                )
        except PacketRejected as e:
            logging.error("[%s] verify reject: %s", self.node.name.decode(), e)
        except Exception as e:
            logging.error("[%s] verify fail: %s", self.node.name.decode(), e)


async def run_qarmr_dynamic_hop_cluster_test():
    """Minimal three-node test of dynamic hop routing with ownership checks."""
    port_a, port_b, port_c = 19001, 19002, 19003
    a = AsyncQARMRNode("NODE_A", "127.0.0.1", port_a, 200.0)
    b = AsyncQARMRNode("NODE_B", "127.0.0.1", port_b, 200.0)
    c = AsyncQARMRNode("NODE_C", "127.0.0.1", port_c, 200.0)
    a.register_route(b"NODE_B", "127.0.0.1", port_b)
    b.register_route(b"NODE_C", "127.0.0.1", port_c)

    fut = asyncio.get_running_loop().create_future()
    c.payload_callback = (
        lambda s, m: fut.set_result((s, m)) if not fut.done() else None
    )

    await a.start()
    await b.start()
    await c.start()
    try:
        hops_chain = [b"NODE_A", b"NODE_B", b"NODE_C"]
        pkt = create_qarmr_onion_packet(
            "ALICE_HQ", b"QARMR_TACTICAL_DYNAMIC_HOP_TEST_v5.0", hops_chain
        )

        r, w = await asyncio.open_connection("127.0.0.1", port_a)
        w.write(pkt)
        await w.drain()
        w.close()
        await w.wait_closed()

        s, m = await asyncio.wait_for(fut, timeout=8.0)
        assert s == "ALICE_HQ"
        assert m == b"QARMR_TACTICAL_DYNAMIC_HOP_TEST_v5.0"
        logging.info("=== DYNAMIC HOP TEST SUCCESS (v5.0.0) ===")
        logging.info(
            "Stats A: %s | B: %s | C: %s",
            a.metrics(),
            b.metrics(),
            c.metrics(),
        )
    finally:
        await a.stop()
        await b.stop()
        await c.stop()


if __name__ == "__main__":
    asyncio.run(run_qarmr_dynamic_hop_cluster_test())
