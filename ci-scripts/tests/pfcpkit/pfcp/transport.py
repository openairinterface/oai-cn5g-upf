# SPDX-License-Identifier: MIT
"""PFCP transport: one persistent socket, sequence correlation, retries, heartbeats.

Two design decisions here are load-bearing, both learned from the reference
tooling this suite replaces:

1. **A single long-lived bound socket with a dedicated receiver thread**, rather
   than opening a listener per request. Opening a listener *after* sending races
   the response -- a UPF answering in microseconds beats the new socket into
   existence, and every request appears to time out even though the UPF replied.

2. **The receiver answers Heartbeat Requests unconditionally.** A heartbeat that
   arrives between two requests and goes unanswered causes the UPF to tear the
   association down, which surfaces later as an unexplained data-plane collapse
   rather than as a control-plane error.

Responses are parked in a dict keyed by sequence number, so an unsolicited
message (e.g. Session Report Request) can never be mistaken for the reply to a
pending request.
"""

from __future__ import annotations

import itertools
import logging
import socket
import threading
import time
from types import TracebackType

from scapy.contrib.pfcp import PFCP
from scapy.packet import Packet

from ..config import Settings
from ..errors import PfcpDecodeError, PfcpTimeout, TransportError
from . import codec
from .types import MessageType

logger = logging.getLogger(__name__)

#: Generous enough for any PFCP message we send or expect.
_RECV_BUFFER = 8192

#: How long the receiver thread blocks before re-checking the stop flag.
_RECV_POLL_INTERVAL = 0.25


class PfcpTransport:
    """Sends PFCP requests and correlates responses by sequence number.

    Use as a context manager so the socket and receiver thread are always
    released::

        with PfcpTransport(settings) as transport:
            response = transport.request(payload, seid=0)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._socket: socket.socket | None = None

        self._seq_counter = itertools.count(1)
        self._send_lock = threading.Lock()

        self._responses: dict[int, Packet] = {}
        self._responses_cv = threading.Condition()

        self._reports: list[Packet] = []
        self._reports_lock = threading.Lock()

        self._receiver: threading.Thread | None = None
        self._stop = threading.Event()

        # Recovery timestamp echoed in heartbeat responses. Constant for the
        # lifetime of this "CP function" instance, as the spec requires.
        self._recovery_timestamp = int(time.time())

        self.heartbeats_answered = 0

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> PfcpTransport:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def open(self) -> None:
        if self._socket is not None:
            raise RuntimeError("transport is already open")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_addr = self._settings.pfcp_bind_addr
        bind_port = self._settings.pfcp_bind_port
        try:
            sock.bind((bind_addr, bind_port))
        except OSError as exc:
            sock.close()
            raise TransportError(
                f"could not bind {bind_addr}:{bind_port} for PFCP ({exc.strerror}). "
                f"PFCP uses {bind_port} for both source and destination, so a local "
                f"SMF/UPF or a leftover container may already hold it -- check with "
                f"`ss -ulnp | grep {bind_port}`. Override with PFCP_BIND_ADDR / "
                f"PFCP_BIND_PORT if the UPF under test tolerates another source port."
            ) from exc
        sock.settimeout(_RECV_POLL_INTERVAL)
        self._socket = sock

        self._stop.clear()
        self._receiver = threading.Thread(
            target=self._receive_loop, name="pfcp-receiver", daemon=True
        )
        self._receiver.start()

        logger.debug(
            "PFCP transport bound to %s:%d, peer %s:%d",
            self._settings.pfcp_bind_addr,
            self._settings.pfcp_bind_port,
            self._settings.upf_n4_addr,
            self._settings.pfcp_port,
        )

    def close(self) -> None:
        self._stop.set()
        if self._receiver is not None:
            self._receiver.join(timeout=2.0)
            self._receiver = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        logger.debug(
            "PFCP transport closed (answered %d heartbeat(s))", self.heartbeats_answered
        )

    # -- sending -----------------------------------------------------------
    def request(
        self,
        payload: Packet,
        *,
        seid: int | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> Packet:
        """Send one request and block until its correlated response arrives.

        ``seid`` controls the header: ``None`` clears the S flag (node-level
        messages), any integer -- **including 0** -- sets S=1 with that value.
        That distinction matters: a Session Establishment Request must carry
        SEID=0 *with* S=1, and some UPFs reject S=0 session messages outright.

        Raises:
            PfcpTimeout: no response after the retry budget was exhausted.
        """
        timeout = self._settings.response_timeout if timeout is None else timeout
        attempts = self._settings.request_retries if retries is None else retries
        seq = next(self._seq_counter)
        label = _message_label(payload)

        for attempt in range(1, attempts + 1):
            self._send(payload, seq=seq, seid=seid)
            response = self._await_response(seq, timeout)
            if response is not None:
                return response
            if attempt < attempts:
                logger.warning(
                    "no response to %s (seq=%d) within %.1fs -- retrying (%d/%d)",
                    label,
                    seq,
                    timeout,
                    attempt + 1,
                    attempts,
                )

        raise PfcpTimeout(label, seq, attempts, timeout)

    def send_no_response(self, payload: Packet, *, seid: int | None = None) -> None:
        """Fire a message without waiting for a reply (e.g. Association Release)."""
        self._send(payload, seq=next(self._seq_counter), seid=seid)

    def _send(self, payload: Packet, *, seq: int, seid: int | None) -> None:
        if self._socket is None:
            raise RuntimeError("transport is not open")

        header = PFCP(
            version=1,
            S=0 if seid is None else 1,
            seid=0 if seid is None else seid,
            seq=seq,
        )
        datagram = bytes(header / payload)
        destination = (self._settings.upf_n4_addr, self._settings.pfcp_port)

        with self._send_lock:
            self._socket.sendto(datagram, destination)

        logger.debug(
            "-> %s seq=%d seid=%s (%d bytes)",
            _message_label(payload),
            seq,
            "none" if seid is None else f"0x{seid:x}",
            len(datagram),
        )

    def _await_response(self, seq: int, timeout: float) -> Packet | None:
        deadline = time.monotonic() + timeout
        with self._responses_cv:
            while True:
                if seq in self._responses:
                    return self._responses.pop(seq)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._responses_cv.wait(remaining)

    # -- receiving ---------------------------------------------------------
    def _receive_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._socket
            if sock is None:
                return
            try:
                data, peer = sock.recvfrom(_RECV_BUFFER)
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                logger.exception("PFCP receive failed")
                continue

            try:
                self._dispatch(PFCP(data), peer)
            except Exception:  # noqa: BLE001 - a bad datagram must not kill the loop
                logger.exception("failed to handle a datagram from %s", peer)

    def _dispatch(self, packet: Packet, peer: tuple[str, int]) -> None:
        message_type = int(packet.message_type)
        seq = int(packet.seq)
        logger.debug(
            "<- %s seq=%d from %s:%d",
            _type_label(message_type),
            seq,
            peer[0],
            peer[1],
        )

        if message_type == MessageType.HEARTBEAT_REQUEST:
            self._answer_heartbeat(seq)
            return

        if message_type == MessageType.SESSION_REPORT_REQUEST:
            # Not correlated to any request of ours; park it for inspection.
            with self._reports_lock:
                self._reports.append(packet)
            return

        with self._responses_cv:
            self._responses[seq] = packet
            self._responses_cv.notify_all()

    def _answer_heartbeat(self, seq: int) -> None:
        try:
            self._send(
                codec.heartbeat_response(self._recovery_timestamp),
                seq=seq,
                seid=None,
            )
            self.heartbeats_answered += 1
        except Exception:  # noqa: BLE001 - never let this kill the receiver
            logger.exception("failed to answer heartbeat seq=%d", seq)

    # -- accessors ---------------------------------------------------------
    @property
    def recovery_timestamp(self) -> int:
        return self._recovery_timestamp

    def drain_session_reports(self) -> list[Packet]:
        """Return and clear any unsolicited Session Report Requests received."""
        with self._reports_lock:
            reports = list(self._reports)
            self._reports.clear()
        return reports

    def decode(self, packet: Packet) -> object:
        """Convenience wrapper so callers need not import the codec."""
        try:
            return codec.decode_response(packet)
        except PfcpDecodeError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PfcpDecodeError(f"could not decode response: {exc}") from exc


def _message_label(payload: Packet) -> str:
    return type(payload).__name__


def _type_label(message_type: int) -> str:
    try:
        return MessageType(message_type).label
    except ValueError:
        return f"message_type={message_type}"
