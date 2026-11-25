"""
Transparent OCPP forwarding session (one per charger connection).

Message flow:
    charger CALL / CALLRESULT / CALLERROR  ->  primary service (e.g. Grizzl-E)
    charger CALL                           ->  every monitor service (e.g. Eddie)
    primary service frames                 ->  charger
    monitor service frames (replies, CALLs) -> dropped (monitoring/logging only)

Teardown: if the charger or the primary service disconnects, the whole session is
closed. A monitor service disconnecting is logged and the session continues without it.
"""

import asyncio
import base64
import json
import logging
import uuid
from typing import Any

import aiohttp
from aiohttp import WSCloseCode, WSMsgType, web

_LOGGER = logging.getLogger(__name__)

SUPPORTED_SUBPROTOCOLS: tuple[str, ...] = ("ocpp1.6", "ocpp2.0.1")
PREFERRED_SUBPROTOCOL = "ocpp1.6"

ROLE_PRIMARY = "primary"
ROLE_MONITOR = "monitor"

# OCPP-J message type ids
CALL = 2
CALLRESULT = 3
CALLERROR = 4


def parse_requested_subprotocols(header_value: str | None) -> list[str]:
    """Split a Sec-WebSocket-Protocol header into a clean list of protocol tokens."""
    if not header_value:
        return []
    return [p.strip() for p in header_value.split(",") if p.strip()]


def negotiate_subprotocol(requested: list[str]) -> str | None:
    """
    Pick the sub-protocol to echo back to the charger.

    Order: ocpp1.6 if offered, else the first offered protocol we support, else the
    first protocol the charger offered (echoing *something* keeps strict chargers from
    dropping the connection). Returns the charger's exact token so the echo matches.
    """
    if not requested:
        return None
    lowered = [p.lower() for p in requested]
    if PREFERRED_SUBPROTOCOL in lowered:
        return requested[lowered.index(PREFERRED_SUBPROTOCOL)]
    for original, low in zip(requested, lowered, strict=True):
        if low in SUPPORTED_SUBPROTOCOLS:
            return original
    return requested[0]


def subprotocol_to_version(subprotocol: str | None) -> str | None:
    """Map a negotiated sub-protocol to the version string used by ChargePointFactory."""
    if not subprotocol:
        return None
    low = subprotocol.lower()
    if "1.6" in low:
        return "1.6"
    if "2.0" in low:
        return "2.0.1"
    return None


def forwarding_services(config: Any) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Return (primary_service, monitor_services) from the enabled ocpp_services config."""
    services = [
        s for s in getattr(config, "ocpp_services", []) or [] if s.get("enabled", True)
    ]
    primary = next((s for s in services if s.get("role") == ROLE_PRIMARY), None)
    monitors = [s for s in services if s.get("role") == ROLE_MONITOR]
    return primary, monitors


def forwarding_enabled(config: Any) -> bool:
    """Forwarding mode is active when an enabled service is marked role: primary."""
    return forwarding_services(config)[0] is not None


def build_auth_headers(service: dict[str, Any]) -> dict[str, str]:
    """Build Authorization header for an upstream service."""
    auth_type = service.get("auth_type")
    if auth_type == "basic" and service.get("username") and service.get("password"):
        creds = base64.b64encode(f"{service['username']}:{service['password']}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}
    if auth_type == "token" and service.get("token"):
        return {"Authorization": f"Bearer {service['token']}"}
    return {}


def build_service_url(service: dict[str, Any], cp_id: str) -> str:
    """Resolve the service URL; supports an optional {cp_id} placeholder."""
    return str(service["url"]).replace("{cp_id}", cp_id)


class ProxySession:
    """Bridges one charger WebSocket to a primary service and N monitor services."""

    def __init__(
        self,
        cp_id: str,
        charger_ws: web.WebSocketResponse,
        subprotocol: str | None,
        primary: dict[str, Any],
        monitors: list[dict[str, Any]],
        manager: Any = None,
    ) -> None:
        self.cp_id = cp_id
        self.charger_ws = charger_ws
        self.subprotocol = subprotocol
        self.primary_cfg = primary
        self.monitor_cfgs = monitors
        self.manager = manager
        self.ocpp_version = subprotocol_to_version(subprotocol) or "1.6"
        self._http: aiohttp.ClientSession | None = None
        self._primary_ws: aiohttp.ClientWebSocketResponse | None = None
        self._monitor_ws: dict[str, aiohttp.ClientWebSocketResponse] = {}
        # Calls originated by the proxy itself (local /backend control requests)
        self._pending: dict[str, asyncio.Future[list[Any]]] = {}
        self._closed = False

    # ------------------------------------------------------------------ lifecycle
    async def _connect(self, service: dict[str, Any]) -> aiohttp.ClientWebSocketResponse:
        assert self._http is not None
        url = build_service_url(service, self.cp_id)
        protocols = (self.subprotocol,) if self.subprotocol else ()
        ws = await self._http.ws_connect(
            url,
            protocols=protocols,
            headers=build_auth_headers(service),
            heartbeat=30,
        )
        _LOGGER.info(
            "[%s] connected to %s service %s (%s, subprotocol=%s)",
            self.cp_id,
            service.get("role"),
            service.get("id"),
            url,
            ws.protocol,
        )
        return ws

    async def run(self) -> None:
        """Connect upstreams and pump messages until the session ends."""
        self._http = aiohttp.ClientSession()
        try:
            try:
                self._primary_ws = await self._connect(self.primary_cfg)
            except Exception:
                _LOGGER.exception(
                    "[%s] primary service %s unreachable; closing charger connection",
                    self.cp_id,
                    self.primary_cfg.get("id"),
                )
                return

            for svc in self.monitor_cfgs:
                try:
                    self._monitor_ws[svc["id"]] = await self._connect(svc)
                except Exception:
                    # Monitor services are best-effort; never block charging on them
                    _LOGGER.exception(
                        "[%s] monitor service %s unreachable; continuing without it",
                        self.cp_id,
                        svc.get("id"),
                    )

            critical = {
                asyncio.create_task(self._pump_charger(), name="charger"),
                asyncio.create_task(self._pump_primary(), name="primary"),
            }
            monitors = {
                asyncio.create_task(self._pump_monitor(sid, ws), name=f"monitor:{sid}")
                for sid, ws in self._monitor_ws.items()
            }
            try:
                done, _ = await asyncio.wait(critical, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if not task.cancelled() and task.exception():
                        _LOGGER.error(
                            "[%s] %s pump failed", self.cp_id, task.get_name(),
                            exc_info=task.exception(),
                        )
                    else:
                        _LOGGER.info("[%s] %s side disconnected", self.cp_id, task.get_name())
            finally:
                for task in critical | monitors:
                    task.cancel()
                await asyncio.gather(*critical, *monitors, return_exceptions=True)
        finally:
            await self.close()

    async def close(self) -> None:
        """Close every socket owned by this session (idempotent)."""
        if self._closed:
            return
        self._closed = True
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()
        sockets: list[Any] = [self._primary_ws, *self._monitor_ws.values(), self.charger_ws]
        for ws in sockets:
            if ws is not None and not ws.closed:
                try:
                    await ws.close(code=WSCloseCode.GOING_AWAY)
                except Exception as e:  # noqa: BLE001 - best-effort teardown
                    _LOGGER.debug("[%s] error closing socket: %s", self.cp_id, e)
        if self._http is not None:
            await self._http.close()
        _LOGGER.info("[%s] proxy session closed", self.cp_id)

    # ------------------------------------------------------------------ pumps
    @staticmethod
    def _decode(raw: str) -> list[Any] | None:
        try:
            frame = json.loads(raw)
        except ValueError:
            return None
        if isinstance(frame, list) and len(frame) >= 3 and isinstance(frame[0], int):
            return frame
        return None

    async def _pump_charger(self) -> None:
        async for msg in self.charger_ws:
            if msg.type != WSMsgType.TEXT:
                if msg.type == WSMsgType.ERROR:
                    break
                continue
            raw = msg.data
            frame = self._decode(raw)
            msg_type = frame[0] if frame else None

            # Response to a call the proxy itself issued: consume locally
            if msg_type in (CALLRESULT, CALLERROR) and frame and frame[1] in self._pending:
                fut = self._pending.pop(frame[1])
                if not fut.done():
                    fut.set_result(frame)
                continue

            # Everything goes to the primary
            await self._safe_send(self._primary_ws, raw, "primary")

            # Only charger-initiated CALLs fan out to monitors. Charger replies answer
            # primary-initiated CALLs, which monitors never issued.
            if msg_type == CALL:
                for sid, ws in list(self._monitor_ws.items()):
                    await self._safe_send(ws, raw, f"monitor:{sid}")
                await self._broadcast(frame)

    async def _pump_primary(self) -> None:
        assert self._primary_ws is not None
        async for msg in self._primary_ws:
            if msg.type == WSMsgType.TEXT:
                await self.charger_ws.send_str(msg.data)
            elif msg.type == WSMsgType.ERROR:
                break

    async def _pump_monitor(self, sid: str, ws: aiohttp.ClientWebSocketResponse) -> None:
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # Monitor replies and commands are intentionally dropped
                    _LOGGER.debug("[%s] dropped frame from monitor %s: %s", self.cp_id, sid, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            self._monitor_ws.pop(sid, None)
            if not self._closed:
                _LOGGER.warning("[%s] monitor service %s disconnected", self.cp_id, sid)

    async def _safe_send(self, ws: Any, raw: str, label: str) -> None:
        if ws is None or ws.closed:
            return
        try:
            await ws.send_str(raw)
        except Exception as e:  # noqa: BLE001 - a dead upstream is handled by its pump
            _LOGGER.warning("[%s] failed to forward to %s: %s", self.cp_id, label, e)

    async def _broadcast(self, frame: list[Any] | None) -> None:
        """Mirror charger CALLs to local /backend subscribers as events."""
        if not frame or not self.manager:
            return
        try:
            await self.manager.broadcast_event(
                {"type": "ocpp_message", "action": frame[2], "payload": frame[3] if len(frame) > 3 else {}}
            )
        except Exception as e:  # noqa: BLE001 - never let local fan-out break forwarding
            _LOGGER.debug("[%s] local broadcast failed: %s", self.cp_id, e)

    # ------------------------------------------------------------------ local control
    async def call(self, action: str, payload: dict[str, Any], timeout: float = 30) -> list[Any]:
        """Send a proxy-originated CALL to the charger and await its reply (not forwarded)."""
        uid = str(uuid.uuid4())
        fut: asyncio.Future[list[Any]] = asyncio.get_running_loop().create_future()
        self._pending[uid] = fut
        try:
            await self.charger_ws.send_str(json.dumps([CALL, uid, action, payload]))
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(uid, None)

    async def send_remote_start_transaction(self, connector_id: int, id_tag: str) -> bool:
        """Compatibility with ChargePointBase for the /backend control endpoint."""
        try:
            if self.ocpp_version == "2.0.1":
                payload: dict[str, Any] = {
                    "evseId": connector_id,
                    "remoteStartId": uuid.uuid4().int & 0x7FFFFFFF,
                    "idToken": {"idToken": id_tag or "", "type": "Central"},
                }
                reply = await self.call("RequestStartTransaction", payload)
            else:
                reply = await self.call(
                    "RemoteStartTransaction", {"connectorId": connector_id, "idTag": id_tag}
                )
        except Exception:
            _LOGGER.exception("[%s] remote start failed", self.cp_id)
            return False
        return reply[0] == CALLRESULT and reply[2].get("status") == "Accepted"

    async def send_remote_stop_transaction(self, transaction_id: int) -> bool:
        """Compatibility with ChargePointBase for the /backend control endpoint."""
        try:
            if self.ocpp_version == "2.0.1":
                reply = await self.call(
                    "RequestStopTransaction", {"transactionId": str(transaction_id)}
                )
            else:
                reply = await self.call("RemoteStopTransaction", {"transactionId": transaction_id})
        except Exception:
            _LOGGER.exception("[%s] remote stop failed", self.cp_id)
            return False
        return reply[0] == CALLRESULT and reply[2].get("status") == "Accepted"
