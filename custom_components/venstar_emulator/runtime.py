"""Runtime state for the Venstar WiFi sensor emulator integration."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import random
import secrets
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.storage import Store

from .const import (
    ATTR_BATTERY,
    ATTR_KEY_B64,
    ATTR_LAST_TEMP_C,
    ATTR_PAIRING_UNTIL,
    ATTR_SEQUENCE,
    CONF_SENSOR_MAC,
    CONF_SENSOR_KEY_B64,
    CONF_SENSOR_NAME,
    CONF_SENSOR_TYPE,
    CONF_SOURCE_INTERFACE,
    CONF_SOURCE_IP,
    CONF_START_SEQUENCE,
    CONF_TEMPERATURE_ENTITY,
    CONF_TEMPERATURE_UNIT,
    CONF_UNIT_ID,
    CONF_UPDATE_INTERVAL_SEC,
    DEFAULT_BATTERY_PERCENT,
    DEFAULT_PAIRING_WINDOW_SEC,
    DEFAULT_SENSOR_NAME,
    DEFAULT_SOURCE_INTERFACE,
    DEFAULT_SOURCE_IP,
    DEFAULT_START_SEQUENCE,
    DEFAULT_TEMPERATURE_UNIT,
    DEFAULT_UNIT_ID,
    DEFAULT_UPDATE_INTERVAL_SEC,
    DOMAIN,
    SENSOR_TYPE_NAME_TO_VALUE,
    STORAGE_VERSION,
)

_LOGGER = logging.getLogger(__name__)
from .protocol import (
    build_info,
    build_message,
    decode_message,
    hmac_b64,
    index_to_temp_c,
    normalize_mac,
    temp_c_to_index,
)


@dataclass
class SimulatedPacket:
    """Last simulated packet details."""

    stage: str
    message_type: int
    sequence: int
    temperature_c: float
    temperature_index: int
    battery_percent: int
    auth_b64: str
    info_hex: str
    payload_hex: str
    generated_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "message_type": self.message_type,
            "sequence": self.sequence,
            "temperature_c": self.temperature_c,
            "temperature_index": self.temperature_index,
            "battery_percent": self.battery_percent,
            "auth_b64": self.auth_b64,
            "info_hex": self.info_hex,
            "payload_hex": self.payload_hex,
            "generated_utc": self.generated_utc,
        }


class VenstarRuntime:
    """Holds persistent emulation state and simulation actions."""

    LEGACY_CONF_BROADCAST_SUBNET = "broadcast_subnet"
    VENSTAR_MULTICAST_TARGET = "224.0.0.1"
    VENSTAR_UDP_PORT = 5001
    PERIODIC_FAILURE_LOG_INTERVAL_SEC = 60

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}_{entry.entry_id}"
        )

        self._key_b64: str = ""
        self._sequence: int = DEFAULT_START_SEQUENCE
        self._pairing_until: datetime | None = None
        # Battery remains fixed at 100 for this integration phase.
        self._battery_percent: int = DEFAULT_BATTERY_PERCENT
        self._last_temp_c: float | None = None
        self._update_unsub: CALLBACK_TYPE | None = None
        self._update_start_unsub: CALLBACK_TYPE | None = None
        self._last_periodic_failure_log: datetime | None = None
        self._suppressed_periodic_failures: int = 0

        self._rng = random.Random()

    def _entry_value(self, key: str, default: Any) -> Any:
        if key in self.entry.options:
            return self.entry.options[key]
        return self.entry.data.get(key, default)

    @property
    def key_b64(self) -> str:
        return self._key_b64

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def battery_percent(self) -> int:
        return self._battery_percent

    @property
    def pairing_until(self) -> datetime | None:
        return self._pairing_until

    def is_pairing_active(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self._pairing_until is None:
            return False
        if now >= self._pairing_until:
            self._pairing_until = None
            return False
        return True

    @staticmethod
    def _normalize_entry_key_b64(value: str) -> str | None:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            return None
        if len(decoded) != 32:
            return None
        return base64.b64encode(decoded).decode("ascii")

    def _entry_default_key_b64(self) -> str:
        entry_key = self.entry.data.get(CONF_SENSOR_KEY_B64)
        if isinstance(entry_key, str):
            normalized = self._normalize_entry_key_b64(entry_key)
            if normalized:
                return normalized
        return base64.b64encode(secrets.token_bytes(32)).decode("ascii")

    def _entry_default_sequence(self) -> int:
        entry_seq = self.entry.data.get(CONF_START_SEQUENCE)
        if isinstance(entry_seq, int) and entry_seq >= 0:
            return entry_seq
        return DEFAULT_START_SEQUENCE

    async def async_initialize(self) -> None:
        """Load persistent state from storage."""
        stored = await self._store.async_load() or {}

        key_b64 = stored.get(ATTR_KEY_B64)
        if isinstance(key_b64, str):
            normalized_stored_key = self._normalize_entry_key_b64(key_b64)
            self._key_b64 = normalized_stored_key or self._entry_default_key_b64()
        else:
            self._key_b64 = self._entry_default_key_b64()

        seq = stored.get(ATTR_SEQUENCE)
        if isinstance(seq, int):
            self._sequence = seq
        else:
            self._sequence = self._entry_default_sequence()

        # Ignore persisted battery and keep it fixed.
        self._battery_percent = DEFAULT_BATTERY_PERCENT

        last_temp = stored.get(ATTR_LAST_TEMP_C)
        if isinstance(last_temp, (float, int)):
            self._last_temp_c = float(last_temp)

        pairing_until = stored.get(ATTR_PAIRING_UNTIL)
        if isinstance(pairing_until, str):
            try:
                self._pairing_until = datetime.fromisoformat(pairing_until)
            except ValueError:
                self._pairing_until = None

        await self._persist_state()

    async def _persist_state(self) -> None:
        payload: dict[str, Any] = {
            ATTR_KEY_B64: self._key_b64,
            ATTR_SEQUENCE: self._sequence,
            ATTR_BATTERY: self._battery_percent,
            ATTR_LAST_TEMP_C: self._last_temp_c,
            ATTR_PAIRING_UNTIL: self._pairing_until.isoformat()
            if self._pairing_until
            else None,
        }
        await self._store.async_save(payload)

    def _update_interval_seconds(self) -> int:
        raw = self._entry_value(CONF_UPDATE_INTERVAL_SEC, DEFAULT_UPDATE_INTERVAL_SEC)
        try:
            return min(60, max(2, int(raw)))
        except (TypeError, ValueError):
            return DEFAULT_UPDATE_INTERVAL_SEC

    async def async_start_periodic_updates(self) -> None:
        await self.async_stop_periodic_updates()
        interval_seconds = self._update_interval_seconds()
        interval = timedelta(seconds=interval_seconds)
        phase_offset = self._periodic_phase_offset_seconds(interval_seconds)

        async def _async_start_loop(_now: datetime) -> None:
            self._update_unsub = async_track_time_interval(
                self.hass, self._async_periodic_update_tick, interval
            )

        if phase_offset <= 0:
            await _async_start_loop(datetime.now(timezone.utc))
            return

        self._update_start_unsub = async_call_later(
            self.hass, float(phase_offset), _async_start_loop
        )

    async def async_stop_periodic_updates(self) -> None:
        if self._update_start_unsub is not None:
            self._update_start_unsub()
            self._update_start_unsub = None
        if self._update_unsub is not None:
            self._update_unsub()
            self._update_unsub = None

    async def async_shutdown(self) -> None:
        await self.async_stop_periodic_updates()

    async def _async_periodic_update_tick(self, now: datetime) -> None:
        if self.is_pairing_active(now):
            return
        try:
            await self.async_simulate_update_packet()
        except Exception as err:  # noqa: BLE001
            should_log = False
            if self._last_periodic_failure_log is None:
                should_log = True
            else:
                elapsed = (now - self._last_periodic_failure_log).total_seconds()
                if elapsed >= self.PERIODIC_FAILURE_LOG_INTERVAL_SEC:
                    should_log = True

            if should_log:
                suppressed = self._suppressed_periodic_failures
                self._suppressed_periodic_failures = 0
                self._last_periodic_failure_log = now
                if suppressed:
                    _LOGGER.warning(
                        "Periodic update send failed: %s (%s similar failures suppressed)",
                        err,
                        suppressed,
                    )
                else:
                    _LOGGER.warning("Periodic update send failed: %s", err)
            else:
                self._suppressed_periodic_failures += 1

    def _periodic_phase_offset_seconds(self, interval_seconds: int) -> int:
        """Deterministically stagger sensor update loops across entries."""
        if interval_seconds <= 1:
            return 0
        seed = f"{self.entry.entry_id}:{self._entry_value(CONF_SENSOR_MAC, '')}"
        phase = int.from_bytes(
            hashlib.sha256(seed.encode("utf-8")).digest()[:4], "big"
        ) % interval_seconds
        if phase == 0 and interval_seconds > 2:
            return 1
        return phase

    def _resolve_source_temperature_c(self) -> float | None:
        entity_id = self._entry_value(CONF_TEMPERATURE_ENTITY, None)
        if not entity_id:
            return None

        state = self.hass.states.get(entity_id)
        if state is None:
            return None
        if state.state in {"unknown", "unavailable", "none", ""}:
            return None

        try:
            value = float(state.state)
        except ValueError:
            return None

        unit_mode = str(
            self._entry_value(CONF_TEMPERATURE_UNIT, DEFAULT_TEMPERATURE_UNIT)
        ).lower()
        if unit_mode == "fahrenheit":
            value = (value - 32.0) * (5.0 / 9.0)

        return value

    def _sample_temperature_c(self) -> float:
        source_temp = self._resolve_source_temperature_c()
        if source_temp is not None:
            return source_temp
        return self._rng.uniform(10.0, 30.0)

    async def _async_resolve_source_ip_for_interface(
        self, source_interface: str
    ) -> str | None:
        adapters: list[dict[str, Any]] | None = None

        # Preferred API from HA docs.
        try:
            from homeassistant.components import network

            adapters = await network.async_get_adapters(self.hass)
        except Exception:  # noqa: BLE001
            adapters = None

        # Backward compatibility fallback.
        if adapters is None:
            try:
                from homeassistant.components.network.util import async_get_adapters
            except Exception:  # noqa: BLE001
                return None

            try:
                adapters = await async_get_adapters(self.hass)
            except Exception:  # noqa: BLE001
                return None

        for adapter in adapters:
            name = str(adapter.get("name", "")).strip()
            if name != source_interface:
                continue

            ipv4_list = adapter.get("ipv4")
            if not isinstance(ipv4_list, list):
                return None

            for ipv4 in ipv4_list:
                if not isinstance(ipv4, dict):
                    continue
                addr = ipv4.get("address")
                prefix = ipv4.get("network_prefix")
                if isinstance(addr, str) and isinstance(prefix, int) and prefix < 31:
                    return f"{addr}/{prefix}"
            return None

        return None

    def _resolve_network_config(
        self,
        *,
        resolved_interface_source_ip_cidr: str | None = None,
    ) -> dict[str, Any]:
        source_interface = str(
            self._entry_value(CONF_SOURCE_INTERFACE, DEFAULT_SOURCE_INTERFACE)
        ).strip()
        source_interface = source_interface or None

        configured_source_ip_raw = str(
            self._entry_value(CONF_SOURCE_IP, DEFAULT_SOURCE_IP)
        ).strip()
        source_ip_raw = configured_source_ip_raw
        source_mode = "static"
        if source_interface:
            if resolved_interface_source_ip_cidr:
                source_ip_raw = resolved_interface_source_ip_cidr
                source_mode = "interface"
            elif configured_source_ip_raw:
                source_mode = "interface_fallback_static"
            else:
                source_mode = "interface_unresolved"

        source_ip: str | None = None
        source_ip_cidr: str | None = None
        directed_broadcast: str | None = None

        if source_ip_raw:
            try:
                source_iface = ipaddress.ip_interface(source_ip_raw)
                if isinstance(source_iface, ipaddress.IPv4Interface):
                    source_ip = str(source_iface.ip)
                    source_ip_cidr = str(source_iface)
                    directed_broadcast = str(source_iface.network.broadcast_address)
            except ValueError:
                pass

        legacy_broadcast_subnet: str | None = None
        if directed_broadcast is None:
            legacy_subnet_raw = str(
                self._entry_value(self.LEGACY_CONF_BROADCAST_SUBNET, "")
            ).strip()
            if legacy_subnet_raw:
                try:
                    legacy_network = ipaddress.ip_network(legacy_subnet_raw, strict=False)
                    if isinstance(legacy_network, ipaddress.IPv4Network):
                        directed_broadcast = str(legacy_network.broadcast_address)
                        legacy_broadcast_subnet = str(legacy_network)
                except ValueError:
                    pass

        targets: list[dict[str, Any]] = [
            {
                "address": self.VENSTAR_MULTICAST_TARGET,
                "port": self.VENSTAR_UDP_PORT,
                "kind": "multicast",
            }
        ]
        if directed_broadcast and directed_broadcast != self.VENSTAR_MULTICAST_TARGET:
            targets.append(
                {
                    "address": directed_broadcast,
                    "port": self.VENSTAR_UDP_PORT,
                    "kind": "directed_broadcast",
                }
            )

        return {
            "source_interface": source_interface,
            "source_ip": source_ip,
            "source_ip_cidr": source_ip_cidr,
            "source_mode": source_mode,
            "directed_broadcast": directed_broadcast,
            "multicast_target": self.VENSTAR_MULTICAST_TARGET,
            "udp_port": self.VENSTAR_UDP_PORT,
            "legacy_broadcast_subnet": legacy_broadcast_subnet,
            "targets": targets,
        }

    async def _async_network_config(self) -> dict[str, Any]:
        source_interface = str(
            self._entry_value(CONF_SOURCE_INTERFACE, DEFAULT_SOURCE_INTERFACE)
        ).strip()
        resolved_ip_cidr = None
        if source_interface:
            resolved_ip_cidr = await self._async_resolve_source_ip_for_interface(
                source_interface
            )
        return self._resolve_network_config(
            resolved_interface_source_ip_cidr=resolved_ip_cidr
        )

    @staticmethod
    def _send_udp_sync(payload: bytes, network: dict[str, Any]) -> dict[str, Any]:
        source_ip = network.get("source_ip")
        source_interface = network.get("source_interface")
        targets = network.get("targets")
        if not isinstance(targets, list):
            targets = []

        result: dict[str, Any] = {
            "source_ip": source_ip,
            "source_interface": source_interface,
            "source_mode": network.get("source_mode"),
            "bind_source_ip": "skipped",
            "bind_interface": "skipped",
            "set_multicast_interface": "skipped",
            "targets": [],
            "sent_count": 0,
        }

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            except OSError:
                pass

            if isinstance(source_ip, str) and source_ip:
                try:
                    sock.bind((source_ip, 0))
                    result["bind_source_ip"] = "ok"
                except OSError as err:
                    result["bind_source_ip"] = f"error:{err}"

                try:
                    sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip)
                    )
                    result["set_multicast_interface"] = "ok"
                except OSError as err:
                    result["set_multicast_interface"] = f"error:{err}"

            if isinstance(source_interface, str) and source_interface:
                bind_to_device = getattr(socket, "SO_BINDTODEVICE", None)
                if bind_to_device is None:
                    result["bind_interface"] = "unsupported"
                else:
                    try:
                        sock.setsockopt(
                            socket.SOL_SOCKET,
                            bind_to_device,
                            source_interface.encode("utf-8") + b"\x00",
                        )
                        result["bind_interface"] = "ok"
                    except OSError as err:
                        result["bind_interface"] = f"error:{err}"

            for target in targets:
                address = str(target.get("address", "")).strip()
                kind = str(target.get("kind", "unknown"))
                port_raw = target.get("port")
                try:
                    port = int(port_raw)
                except (TypeError, ValueError):
                    port = 0

                if not address or port <= 0:
                    result["targets"].append(
                        {
                            "address": address,
                            "port": port,
                            "kind": kind,
                            "status": "invalid_target",
                        }
                    )
                    continue

                try:
                    sent_bytes = sock.sendto(payload, (address, port))
                    result["targets"].append(
                        {
                            "address": address,
                            "port": port,
                            "kind": kind,
                            "status": "sent",
                            "bytes": sent_bytes,
                        }
                    )
                    result["sent_count"] = int(result["sent_count"]) + 1
                except OSError as err:
                    result["targets"].append(
                        {
                            "address": address,
                            "port": port,
                            "kind": kind,
                            "status": f"error:{err}",
                        }
                    )

        return result

    async def _async_send_packet(
        self,
        pkt: SimulatedPacket,
        network: dict[str, Any],
    ) -> dict[str, Any]:
        payload = bytes.fromhex(pkt.payload_hex)
        return await self.hass.async_add_executor_job(
            self._send_udp_sync, payload, network
        )

    def _build_packet(
        self,
        *,
        stage: str,
        message_type: int,
        sequence: int,
        temperature_c: float,
        battery_percent: int,
        pair_auth_key_mode: bool,
    ) -> SimulatedPacket:
        temp_idx = temp_c_to_index(temperature_c)

        info = build_info(
            sequence=sequence,
            mac=self._entry_value(CONF_SENSOR_MAC, "dcf31c286547"),
            unit_id=int(self._entry_value(CONF_UNIT_ID, DEFAULT_UNIT_ID)),
            sensor_name=str(self._entry_value(CONF_SENSOR_NAME, DEFAULT_SENSOR_NAME)),
            sensor_type=int(
                SENSOR_TYPE_NAME_TO_VALUE.get(
                    str(self._entry_value(CONF_SENSOR_TYPE, "remote")), 3
                )
            ),
            temp_idx=temp_idx,
            battery_percent=battery_percent,
        )

        key = base64.b64decode(self._key_b64)
        auth_b64 = self._key_b64 if pair_auth_key_mode else hmac_b64(key, info)

        payload = build_message(
            message_type=message_type,
            info_bytes=info,
            auth_b64=auth_b64,
        )

        decoded = decode_message(payload)
        decoded_temp_idx = int(decoded["fields"]["temperature_index"])

        return SimulatedPacket(
            stage=stage,
            message_type=message_type,
            sequence=sequence,
            temperature_c=index_to_temp_c(decoded_temp_idx),
            temperature_index=decoded_temp_idx,
            battery_percent=battery_percent,
            auth_b64=auth_b64,
            info_hex=str(decoded["info_hex"]),
            payload_hex=payload.hex(),
            generated_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    async def async_enter_pairing_mode(self) -> None:
        self._pairing_until = datetime.now(timezone.utc) + timedelta(
            seconds=DEFAULT_PAIRING_WINDOW_SEC
        )
        await self._persist_state()

    async def async_simulate_pair_packet(self) -> SimulatedPacket:
        temp_c = self._sample_temperature_c()
        pkt = self._build_packet(
            stage="pair",
            message_type=43,
            sequence=self._sequence,
            temperature_c=temp_c,
            battery_percent=self._battery_percent,
            pair_auth_key_mode=True,
        )
        network = await self._async_network_config()
        await self._async_send_packet(pkt, network)

        self._last_temp_c = pkt.temperature_c
        await self._persist_state()
        return pkt

    async def async_simulate_update_packet(self) -> SimulatedPacket:
        self._sequence += 1

        temp_c = self._sample_temperature_c()
        pkt = self._build_packet(
            stage="update",
            message_type=42,
            sequence=self._sequence,
            temperature_c=temp_c,
            battery_percent=self._battery_percent,
            pair_auth_key_mode=False,
        )
        network = await self._async_network_config()
        await self._async_send_packet(pkt, network)

        self._last_temp_c = pkt.temperature_c
        await self._persist_state()
        return pkt

    async def async_snapshot(self) -> dict[str, Any]:
        source_temp_c = self._resolve_source_temperature_c()
        network = await self._async_network_config()

        data: dict[str, Any] = {
            "entry_id": self.entry.entry_id,
            "name": self.entry.title,
            "source_interface": network["source_interface"],
            "source_ip": network["source_ip"],
            "source_ip_cidr": network["source_ip_cidr"],
            "source_mode": network["source_mode"],
            "directed_broadcast": network["directed_broadcast"],
            "multicast_target": network["multicast_target"],
            "udp_port": network["udp_port"],
            "legacy_broadcast_subnet": network["legacy_broadcast_subnet"],
            "targets": network["targets"],
            "unit_id": int(self._entry_value(CONF_UNIT_ID, DEFAULT_UNIT_ID)),
            "sensor_type": str(self._entry_value(CONF_SENSOR_TYPE, "remote")),
            "sensor_name": str(self._entry_value(CONF_SENSOR_NAME, DEFAULT_SENSOR_NAME)),
            "sensor_mac": normalize_mac(
                str(self._entry_value(CONF_SENSOR_MAC, "dcf31c286547"))
            ),
            "temperature_entity": self._entry_value(CONF_TEMPERATURE_ENTITY, None),
            "temperature_unit_mode": self._entry_value(
                CONF_TEMPERATURE_UNIT, DEFAULT_TEMPERATURE_UNIT
            ),
            "source_temperature_c": source_temp_c,
            "last_temperature_c": self._last_temp_c,
            "sequence": self._sequence,
            "battery_percent": self._battery_percent,
            "pairing_active": self.is_pairing_active(),
            "pairing_until": self._pairing_until.isoformat()
            if self._pairing_until
            else None,
        }
        return data
