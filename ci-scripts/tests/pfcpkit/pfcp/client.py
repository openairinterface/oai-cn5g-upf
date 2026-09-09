# SPDX-License-Identifier: MIT
"""The PFCP facade scenarios use.

Everything above this layer speaks specs (:mod:`pfcpkit.models`) and
:class:`SessionContext`; nothing above it needs to know about scapy, sockets, or
sequence numbers.

The client is a context manager: entering sets up the PFCP association, leaving
releases it and closes the transport. Sessions established through it are tracked
so a scenario can be cleaned up even if it failed part-way.
"""

from __future__ import annotations

import logging
from types import TracebackType

from ..config import Settings
from ..errors import PfcpRejected
from ..models import ModificationSpec, PfcpResponse, SessionSpec
from . import codec
from .session import SeidAllocator, SessionContext
from .transport import PfcpTransport
from .types import ESTABLISHMENT_HEADER_SEID, Cause, MessageType, cause_name

logger = logging.getLogger(__name__)


class PfcpClient:
    """Drives a UPF over N4 for the duration of a test run.

    One client holds one PFCP association and may establish many sessions::

        with PfcpClient(settings) as client:
            session = client.establish_session(spec)
            client.modify_session(session, delta)
            client.delete_session(session)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._transport = PfcpTransport(settings)
        self._seids = SeidAllocator(settings.seid_base)
        self._sessions: list[SessionContext] = []
        self._associated = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> PfcpClient:
        self._transport.open()
        try:
            self.associate()
        except Exception:
            self._transport.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.release()
        finally:
            self._transport.close()

    def associate(self) -> PfcpResponse:
        """PFCP Association Setup -- required before any session message."""
        payload = codec.association_setup_request(
            self._settings.cp_node_id, self._transport.recovery_timestamp
        )
        response = self._exchange(payload, seid=None, expect_accepted=True)
        self._associated = True
        logger.info("PFCP association established with %s", self._settings.upf_n4_addr)
        return response

    def release(self) -> None:
        """PFCP Association Release, best effort.

        Sent without waiting for a reply: by the time we get here the run is
        finishing, and a UPF that has already gone away must not turn teardown
        into a failure.
        """
        if not self._associated:
            return
        try:
            self._transport.send_no_response(
                codec.association_release_request(self._settings.cp_node_id), seid=None
            )
            logger.info("PFCP association release sent")
        except Exception:  # noqa: BLE001 - teardown must not mask a test failure
            logger.exception("association release failed")
        finally:
            self._associated = False

    # -- session lifecycle -------------------------------------------------
    def establish_session(self, spec: SessionSpec) -> SessionContext:
        """Send a Session Establishment Request and record the resulting state.

        The header carries SEID=0 with the S flag set (TS 29.244 Section
        7.2.2.4.2) -- the UP has not allocated a SEID yet, but a session message
        with S=0 is rejected at decode time by stricter UPFs.
        """
        cp_seid = self._seids.next()
        session = SessionContext(cp_seid=cp_seid, spec=spec)
        self._sessions.append(session)

        payload = codec.session_establishment_request(
            spec, node_id=self._settings.cp_node_id, cp_seid=cp_seid
        )
        response = self._exchange(
            payload, seid=ESTABLISHMENT_HEADER_SEID, expect_accepted=False
        )

        session.up_seid = response.up_seid
        for created in response.created_pdrs:
            if created.teid is not None:
                session.reported_teids[created.pdr_id] = created.teid

        if response.accepted:
            logger.info(
                "established %s (%d PDR, %d FAR, %d QER)",
                session.describe(),
                len(spec.pdrs),
                len(spec.fars),
                len(spec.qers),
            )
        else:
            session.active = False
            logger.error(
                "session establishment rejected: cause=%s",
                cause_name(response.cause),
            )
        return session

    def send_establishment(self, spec: SessionSpec, cp_seid: int) -> PfcpResponse:
        """Send a raw Session Establishment Request without tracking a session.

        For scenarios that deliberately probe establishment behaviour -- e.g.
        re-using a CP F-SEID the UPF already knows -- where the point is the
        response, not a usable session. Never raises on a rejection.
        """
        payload = codec.session_establishment_request(
            spec, node_id=self._settings.cp_node_id, cp_seid=cp_seid
        )
        return self._exchange(
            payload, seid=ESTABLISHMENT_HEADER_SEID, expect_accepted=False
        )

    def modify_session(
        self, session: SessionContext, delta: ModificationSpec
    ) -> PfcpResponse:
        """Send a Session Modification Request against an established session."""
        seid = session.require_up_seid()
        payload = codec.session_modification_request(
            delta, network_instance=session.spec.network_instance
        )
        logger.info("modifying %s: %s", session.describe(), delta.describe())
        response = self._exchange(payload, seid=seid, expect_accepted=False)
        if response.accepted:
            session.modifications += 1
        else:
            logger.error(
                "session modification rejected: cause=%s failed_rule=%s",
                cause_name(response.cause),
                response.failed_rule_id,
            )
        return response

    def delete_session(
        self, session: SessionContext, *, tolerate_failure: bool = False
    ) -> PfcpResponse | None:
        """Send a Session Deletion Request.

        ``tolerate_failure`` is used by automatic teardown, where a session may
        already be gone (or was never fully established) and a raised exception
        would mask the real test failure.
        """
        if not session.active:
            return None
        if session.up_seid is None:
            if not tolerate_failure:
                session.require_up_seid()
            logger.debug(
                "skipping deletion of cp_seid=0x%x: never got a UP F-SEID",
                session.cp_seid,
            )
            session.active = False
            return None

        try:
            response = self._exchange(
                codec.session_deletion_request(),
                seid=session.up_seid,
                expect_accepted=False,
            )
        except Exception:  # noqa: BLE001
            if not tolerate_failure:
                raise
            logger.exception("deletion of %s failed", session.describe())
            session.active = False
            return None

        session.active = False
        if response.accepted:
            logger.info("deleted %s", session.describe())
        else:
            level = logger.debug if tolerate_failure else logger.error
            level("session deletion rejected: cause=%s", cause_name(response.cause))
        return response

    # -- introspection -----------------------------------------------------
    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def sessions(self) -> tuple[SessionContext, ...]:
        """Every session this client established, newest last."""
        return tuple(self._sessions)

    def active_sessions(self) -> tuple[SessionContext, ...]:
        return tuple(s for s in self._sessions if s.active)

    def delete_all_sessions(self) -> None:
        """Best-effort cleanup of everything still active, newest first."""
        for session in reversed(self.active_sessions()):
            self.delete_session(session, tolerate_failure=True)

    def drain_session_reports(self) -> int:
        """Discard any buffered Session Report Requests, returning the count."""
        return len(self._transport.drain_session_reports())

    # -- internals ---------------------------------------------------------
    def _exchange(
        self, payload: object, *, seid: int | None, expect_accepted: bool
    ) -> PfcpResponse:
        raw = self._transport.request(payload, seid=seid)  # type: ignore[arg-type]
        response = codec.decode_response(raw)

        if expect_accepted and not response.accepted:
            raise PfcpRejected(
                _label(response.message_type),
                response.cause,
                cause_name(response.cause),
            )
        return response


def _label(message_type: int) -> str:
    try:
        return MessageType(message_type).label
    except ValueError:
        return f"message_type={message_type}"


__all__ = ["PfcpClient", "Cause"]
