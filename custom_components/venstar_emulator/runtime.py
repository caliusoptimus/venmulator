"""Runtime state for the WiFi sensor emulator for Venstar integration."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import random
import secrets
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
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
    CONF_START_SEQUENCE,
    CONF_TARGET_MODE,
    CONF_TEMPERATURE_ENTITY,
    CONF_TEMPERATURE_UNIT,
    CONF_UNIT_ID,
    CONF_UPDATE_INTERVAL_SEC,
    CONF_UNICAST_TARGET,
    DEFAULT_BATTERY_PERCENT,
    DEFAULT_PAIRING_WINDOW_SEC,
    DEFAULT_SENSOR_NAME,
    DEFAULT_SOURCE_INTERFACE,
    DEFAULT_START_SEQUENCE,
    DEFAULT_TARGET_MODE,
    DEFAULT_TEMPERATURE_UNIT,
    DEFAULT_UNIT_ID,
    DEFAULT_UPDATE_INTERVAL_SEC,
    DEFAULT_UNICAST_TARGET,
    DOMAIN,
    MAX_SEQUENCE,
    MAX_UPDATE_INTERVAL_SEC,
    MIN_UPDATE_INTERVAL_SEC,
    SENSOR_TYPE_NAME_TO_VALUE,
    STORAGE_VERSION,
    TARGET_MODE_UNICAST,
    TARGET_MODES,
)
from .protocol import (
    build_info,
    build_message,
    decode_message,
    hmac_b64,
    index_to_temp_c,
    normalize_mac,
    temp_c_to_index,
)

_LOGGER = logging.getLogger(__name__)


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


@dataclass(frozen=True)
class ResolvedTemperatureSource:
    """Resolved state of the configured HA temperature source."""

    entity_id: str | None
    status: str
    temperature_c: float | None

    @property
    def broadcast_enabled(self) -> bool:
        """Return True when update packets should still be sent."""
        return self.status in {"unset", "ready"}

    @property
    def uses_random_fallback(self) -> bool:
        """Return True when packets should use a generated temperature."""
        return self.status == "unset"


class VenstarRuntime:
    """Holds persistent emulation state and simulation actions."""

    LEGACY_CONF_BROADCAST_SUBNET = "broadcast_subnet"
    LEGACY_CONF_SOURCE_IP = "source_ip"
    VENSTAR_MULTICAST_TARGET = "224.0.0.1"
    VENSTAR_UDP_PORT = 5001
    VENSTAR_BURST_REPEAT_COUNT = 12
    VENSTAR_BURST_PACKET_DELAY_SEC = 0.005
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
        self._last_packet: SimulatedPacket | None = None
        self._last_send_result: dict[str, Any] | None = None
        self._last_send_completed_utc: str | None = None
        self._packets_generated_since_start: int = 0
        self._udp_packets_sent_since_start: int = 0
        self._update_unsub: CALLBACK_TYPE | None = None
        self._update_start_unsub: CALLBACK_TYPE | None = None
        self._last_periodic_failure_log: datetime | None = None
        self._suppressed_periodic_failures: int = 0
        self._paused_temperature_entity: str | None = None
        self._last_network_debug_signature: tuple[Any, ...] | None = None
        self._last_temperature_source_debug_signature: tuple[Any, ...] | None = None

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
            return self._normalize_sequence(entry_seq)
        return DEFAULT_START_SEQUENCE

    @staticmethod
    def _normalize_sequence(value: int) -> int:
        """Wrap sequence into the 16-bit range expected by the thermostat."""
        return int(value) % (MAX_SEQUENCE + 1)

    @staticmethod
    def _target_summary(targets: Any) -> list[str]:
        """Return a compact, log-safe target summary."""
        if not isinstance(targets, list):
            return []

        summary: list[str] = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            kind = str(target.get("kind", "unknown"))
            address = str(target.get("address", ""))
            port = target.get("port", "")
            status = target.get("status")
            if status:
                summary.append(f"{kind}:{address}:{port}:{status}")
            else:
                summary.append(f"{kind}:{address}:{port}")
        return summary

    @staticmethod
    def _packet_diagnostics(pkt: SimulatedPacket | None) -> dict[str, Any] | None:
        """Return useful packet diagnostics without exposing auth or payload data."""
        if pkt is None:
            return None

        return {
            "stage": pkt.stage,
            "message_type": pkt.message_type,
            "sequence": pkt.sequence,
            "temperature_c": pkt.temperature_c,
            "temperature_index": pkt.temperature_index,
            "battery_percent": pkt.battery_percent,
            "generated_utc": pkt.generated_utc,
        }

    @staticmethod
    def _send_status(result: dict[str, Any] | None) -> str | None:
        """Return a compact status for the last send attempt."""
        if result is None:
            return None

        try:
            sent_count = int(result.get("sent_count", 0))
        except (TypeError, ValueError):
            sent_count = 0

        targets = result.get("targets")
        statuses = (
            [
                str(target.get("status", ""))
                for target in targets
                if isinstance(target, dict)
            ]
            if isinstance(targets, list)
            else []
        )

        if sent_count > 0:
            if statuses and any(status != "sent" for status in statuses):
                return "partial"
            return "sent"

        if not isinstance(targets, list) or not targets:
            return "no_targets"

        if any(status.startswith("error:") for status in statuses):
            return "error"
        if "invalid_target" in statuses:
            return "invalid_target"
        return "not_sent"

    def _send_diagnostics(self) -> dict[str, Any] | None:
        """Return useful send diagnostics from the last send attempt."""
        if self._last_send_result is None:
            return None

        try:
            sent_count = int(self._last_send_result.get("sent_count", 0))
        except (TypeError, ValueError):
            sent_count = 0

        return {
            "completed_utc": self._last_send_completed_utc,
            "status": self._send_status(self._last_send_result),
            "sent_count": sent_count,
            "source_ip": self._last_send_result.get("source_ip"),
            "source_interface": self._last_send_result.get("source_interface"),
            "source_mode": self._last_send_result.get("source_mode"),
            "bind_source_ip": self._last_send_result.get("bind_source_ip"),
            "bind_interface": self._last_send_result.get("bind_interface"),
            "set_multicast_interface": self._last_send_result.get(
                "set_multicast_interface"
            ),
            "burst_repeat_count": self._last_send_result.get("burst_repeat_count"),
            "burst_packet_delay_ms": self._last_send_result.get(
                "burst_packet_delay_ms"
            ),
            "logical_target_count": self._last_send_result.get("logical_target_count"),
            "targets": self._last_send_result.get("targets"),
        }

    async def async_initialize(self) -> None:
        """Load persistent state from storage."""
        stored = await self._store.async_load() or {}
        _LOGGER.debug(
            "Initializing runtime for entry %s; stored state present=%s",
            self.entry.entry_id,
            bool(stored),
        )

        key_b64 = stored.get(ATTR_KEY_B64)
        if isinstance(key_b64, str):
            normalized_stored_key = self._normalize_entry_key_b64(key_b64)
            self._key_b64 = normalized_stored_key or self._entry_default_key_b64()
        else:
            self._key_b64 = self._entry_default_key_b64()

        seq = stored.get(ATTR_SEQUENCE)
        if isinstance(seq, int):
            self._sequence = self._normalize_sequence(seq)
            if seq != self._sequence:
                _LOGGER.debug(
                    "Normalized stored sequence for entry %s from %s to %s",
                    self.entry.entry_id,
                    seq,
                    self._sequence,
                )
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
        _LOGGER.debug(
            "Runtime initialized for entry %s: sequence=%s, "
            "last_temp_c=%s, pairing_active=%s, key_present=%s",
            self.entry.entry_id,
            self._sequence,
            self._last_temp_c,
            self.is_pairing_active(),
            bool(self._key_b64),
        )

    async def _persist_state(self) -> None:
        self._sequence = self._normalize_sequence(self._sequence)
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
        _LOGGER.debug(
            "Persisted runtime state for entry %s: sequence=%s, "
            "last_temp_c=%s, pairing_until=%s",
            self.entry.entry_id,
            self._sequence,
            self._last_temp_c,
            payload[ATTR_PAIRING_UNTIL],
        )

    def _update_interval_seconds(self) -> int:
        raw = self._entry_value(CONF_UPDATE_INTERVAL_SEC, DEFAULT_UPDATE_INTERVAL_SEC)
        try:
            return min(
                MAX_UPDATE_INTERVAL_SEC,
                max(MIN_UPDATE_INTERVAL_SEC, int(raw)),
            )
        except (TypeError, ValueError):
            return DEFAULT_UPDATE_INTERVAL_SEC

    async def async_start_periodic_updates(self) -> None:
        await self.async_stop_periodic_updates()
        interval_seconds = self._update_interval_seconds()
        interval = timedelta(seconds=interval_seconds)
        phase_offset = self._periodic_phase_offset_seconds(interval_seconds)
        _LOGGER.debug(
            "Scheduling periodic updates for entry %s: interval=%ss, phase_offset=%ss",
            self.entry.entry_id,
            interval_seconds,
            phase_offset,
        )

        async def _async_start_loop(_now: datetime) -> None:
            self._update_unsub = async_track_time_interval(
                self.hass, self._async_periodic_update_tick, interval
            )
            _LOGGER.debug(
                "Periodic update loop started for entry %s: interval=%ss",
                self.entry.entry_id,
                interval_seconds,
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
            _LOGGER.debug(
                "Cancelled delayed update start for entry %s",
                self.entry.entry_id,
            )
        if self._update_unsub is not None:
            self._update_unsub()
            self._update_unsub = None
            _LOGGER.debug(
                "Stopped periodic update loop for entry %s",
                self.entry.entry_id,
            )

    async def async_shutdown(self) -> None:
        _LOGGER.debug("Shutting down runtime for entry %s", self.entry.entry_id)
        await self.async_stop_periodic_updates()

    async def _async_periodic_update_tick(self, now: datetime) -> None:
        if self.is_pairing_active(now):
            _LOGGER.debug(
                "Skipping periodic update for entry %s while pairing is active "
                "until %s",
                self.entry.entry_id,
                self._pairing_until,
            )
            return
        try:
            pkt = await self.async_simulate_update_packet()
            if pkt is None:
                _LOGGER.debug(
                    "Periodic update produced no packet for entry %s",
                    self.entry.entry_id,
                )
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

    def _resolve_temperature_source(self) -> ResolvedTemperatureSource:
        entity_id = self._entry_value(CONF_TEMPERATURE_ENTITY, None)
        if not entity_id:
            return ResolvedTemperatureSource(
                entity_id=None,
                status="unset",
                temperature_c=None,
            )

        state = self.hass.states.get(entity_id)
        if state is None:
            return ResolvedTemperatureSource(
                entity_id=entity_id,
                status="missing",
                temperature_c=None,
            )
        if state.state == STATE_UNKNOWN:
            return ResolvedTemperatureSource(
                entity_id=entity_id,
                status="unknown",
                temperature_c=None,
            )
        if state.state == STATE_UNAVAILABLE:
            return ResolvedTemperatureSource(
                entity_id=entity_id,
                status="unavailable",
                temperature_c=None,
            )
        if state.state == "":
            return ResolvedTemperatureSource(
                entity_id=entity_id,
                status="invalid",
                temperature_c=None,
            )

        try:
            value = float(state.state)
        except ValueError:
            return ResolvedTemperatureSource(
                entity_id=entity_id,
                status="invalid",
                temperature_c=None,
            )

        unit_mode = str(
            self._entry_value(CONF_TEMPERATURE_UNIT, DEFAULT_TEMPERATURE_UNIT)
        ).lower()
        if unit_mode == "fahrenheit":
            value = (value - 32.0) * (5.0 / 9.0)

        return ResolvedTemperatureSource(
            entity_id=entity_id,
            status="ready",
            temperature_c=value,
        )

    def _sample_temperature_c(
        self, source: ResolvedTemperatureSource | None = None
    ) -> float:
        source = source or self._resolve_temperature_source()
        if source.temperature_c is not None:
            return source.temperature_c
        return self._rng.uniform(10.0, 30.0)

    def _handle_temperature_source_status(
        self, source: ResolvedTemperatureSource
    ) -> bool:
        """Track whether broadcasts should pause for an unusable source."""
        signature = (
            source.entity_id,
            source.status,
            source.broadcast_enabled,
            source.uses_random_fallback,
        )
        if signature != self._last_temperature_source_debug_signature:
            self._last_temperature_source_debug_signature = signature
            _LOGGER.debug(
                "Temperature source status for entry %s: entity=%s, "
                "status=%s, broadcast_enabled=%s, random_fallback=%s",
                self.entry.entry_id,
                source.entity_id,
                source.status,
                source.broadcast_enabled,
                source.uses_random_fallback,
            )

        if not source.broadcast_enabled:
            if self._paused_temperature_entity != source.entity_id:
                _LOGGER.info(
                    "Configured temperature source entity '%s' is not usable "
                    "(status: %s); pausing update broadcasts until it reports "
                    "a numeric state or the source entity is cleared",
                    source.entity_id,
                    source.status,
                )
                self._paused_temperature_entity = source.entity_id
            return False

        if self._paused_temperature_entity is not None:
            _LOGGER.info(
                "Temperature source is usable again; resuming update broadcasts"
            )
            self._paused_temperature_entity = None

        return True

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
            _LOGGER.debug(
                "Could not read adapters from homeassistant.components.network",
                exc_info=True,
            )

        # Backward compatibility fallback.
        if adapters is None:
            try:
                from homeassistant.components.network.util import async_get_adapters
            except Exception:  # noqa: BLE001
                return None

            try:
                adapters = await async_get_adapters(self.hass)
            except Exception:  # noqa: BLE001
                _LOGGER.debug(
                    "Could not read adapters from legacy network helper",
                    exc_info=True,
                )
                return None

        if adapters is None:
            _LOGGER.debug(
                "Network adapter discovery returned no adapter data for entry %s",
                self.entry.entry_id,
            )
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
                    _LOGGER.debug(
                        "Resolved source interface for entry %s: %s -> %s/%s",
                        self.entry.entry_id,
                        source_interface,
                        addr,
                        prefix,
                    )
                    return f"{addr}/{prefix}"
            _LOGGER.debug(
                "Source interface %s for entry %s has no usable IPv4 address",
                source_interface,
                self.entry.entry_id,
            )
            return None

        _LOGGER.debug(
            "Source interface %s for entry %s was not found",
            source_interface,
            self.entry.entry_id,
        )
        return None

    def _log_network_config(self, network: dict[str, Any]) -> None:
        """Log network configuration when it changes."""
        signature = (
            network.get("source_interface"),
            network.get("source_ip"),
            network.get("source_ip_cidr"),
            network.get("source_mode"),
            network.get("target_mode"),
            network.get("unicast_target"),
            tuple(self._target_summary(network.get("targets"))),
        )
        if signature == self._last_network_debug_signature:
            return

        self._last_network_debug_signature = signature
        _LOGGER.debug(
            "Resolved network config for entry %s: source_interface=%s, "
            "source_ip=%s, source_ip_cidr=%s, source_mode=%s, "
            "target_mode=%s, unicast_target=%s, targets=%s",
            self.entry.entry_id,
            network.get("source_interface"),
            network.get("source_ip"),
            network.get("source_ip_cidr"),
            network.get("source_mode"),
            network.get("target_mode"),
            network.get("unicast_target"),
            self._target_summary(network.get("targets")),
        )

    def _resolve_network_config(
        self,
        *,
        resolved_interface_source_ip_cidr: str | None = None,
    ) -> dict[str, Any]:
        source_interface = str(
            self._entry_value(CONF_SOURCE_INTERFACE, DEFAULT_SOURCE_INTERFACE)
        ).strip()
        source_interface = source_interface or None

        target_mode = str(
            self._entry_value(CONF_TARGET_MODE, DEFAULT_TARGET_MODE)
        ).strip()
        if target_mode not in TARGET_MODES:
            target_mode = DEFAULT_TARGET_MODE

        unicast_target_raw = str(
            self._entry_value(CONF_UNICAST_TARGET, DEFAULT_UNICAST_TARGET)
        ).strip()
        unicast_target: str | None = None
        if unicast_target_raw:
            try:
                address = ipaddress.ip_address(unicast_target_raw)
                if isinstance(address, ipaddress.IPv4Address):
                    unicast_target = str(address)
            except ValueError:
                unicast_target = None
                _LOGGER.debug(
                    "Ignoring invalid unicast target for entry %s: %s",
                    self.entry.entry_id,
                    unicast_target_raw,
                )

        legacy_source_ip_raw = str(
            self._entry_value(self.LEGACY_CONF_SOURCE_IP, "")
        ).strip()

        source_ip_raw = resolved_interface_source_ip_cidr
        source_mode = "os_route"
        if source_interface:
            if resolved_interface_source_ip_cidr:
                source_mode = "interface"
            elif legacy_source_ip_raw:
                source_ip_raw = legacy_source_ip_raw
                source_mode = "interface_fallback_legacy_source_ip"
            else:
                source_mode = "interface_unresolved"
        elif legacy_source_ip_raw:
            source_ip_raw = legacy_source_ip_raw
            source_mode = "legacy_source_ip"

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
                _LOGGER.debug(
                    "Ignoring invalid source IP CIDR for entry %s: %s",
                    self.entry.entry_id,
                    source_ip_raw,
                )
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
                    _LOGGER.debug(
                        "Ignoring invalid legacy broadcast subnet for entry %s: %s",
                        self.entry.entry_id,
                        legacy_subnet_raw,
                    )
                    pass

        if target_mode == TARGET_MODE_UNICAST:
            targets: list[dict[str, Any]] = []
            if unicast_target:
                targets.append(
                    {
                        "address": unicast_target,
                        "port": self.VENSTAR_UDP_PORT,
                        "kind": "unicast",
                    }
                )
        else:
            targets = []
            if (
                directed_broadcast
                and directed_broadcast != self.VENSTAR_MULTICAST_TARGET
            ):
                targets.append(
                    {
                        "address": directed_broadcast,
                        "port": self.VENSTAR_UDP_PORT,
                        "kind": "directed_broadcast",
                    }
                )
            targets.append(
                {
                    "address": self.VENSTAR_MULTICAST_TARGET,
                    "port": self.VENSTAR_UDP_PORT,
                    "kind": "multicast",
                }
            )

        return {
            "source_interface": source_interface,
            "source_ip": source_ip,
            "source_ip_cidr": source_ip_cidr,
            "source_mode": source_mode,
            "target_mode": target_mode,
            "unicast_target": unicast_target,
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
        network = self._resolve_network_config(
            resolved_interface_source_ip_cidr=resolved_ip_cidr
        )
        self._log_network_config(network)
        return network

    @staticmethod
    def _send_udp_sync(payload: bytes, network: dict[str, Any]) -> dict[str, Any]:
        source_ip = network.get("source_ip")
        source_interface = network.get("source_interface")
        targets = network.get("targets")
        if not isinstance(targets, list):
            targets = []
        repeat_count = VenstarRuntime.VENSTAR_BURST_REPEAT_COUNT
        packet_delay_sec = VenstarRuntime.VENSTAR_BURST_PACKET_DELAY_SEC

        valid_target_count = 0
        for target in targets:
            address = str(target.get("address", "")).strip()
            port_raw = target.get("port")
            try:
                port = int(port_raw)
            except (TypeError, ValueError):
                port = 0
            if address and port > 0:
                valid_target_count += 1
        total_send_attempts = valid_target_count * repeat_count
        send_attempt_index = 0

        result: dict[str, Any] = {
            "source_ip": source_ip,
            "source_interface": source_interface,
            "source_mode": network.get("source_mode"),
            "bind_source_ip": "skipped",
            "bind_interface": "skipped",
            "set_multicast_interface": "skipped",
            "burst_repeat_count": repeat_count,
            "burst_packet_delay_ms": packet_delay_sec * 1000,
            "logical_target_count": len(targets),
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
                            "attempts": 0,
                            "sent_count": 0,
                        }
                    )
                    continue

                success_count = 0
                total_bytes = 0
                last_error: OSError | None = None
                for _ in range(repeat_count):
                    try:
                        sent_bytes = sock.sendto(payload, (address, port))
                    except OSError as err:
                        last_error = err
                    else:
                        success_count += 1
                        total_bytes += sent_bytes
                    send_attempt_index += 1
                    if send_attempt_index < total_send_attempts:
                        time.sleep(packet_delay_sec)

                result["sent_count"] = int(result["sent_count"]) + success_count
                if success_count == repeat_count:
                    status = "sent"
                elif success_count > 0:
                    status = "partial"
                elif last_error is not None:
                    status = f"error:{last_error}"
                else:
                    status = "not_sent"

                target_result: dict[str, Any] = {
                    "address": address,
                    "port": port,
                    "kind": kind,
                    "status": status,
                    "attempts": repeat_count,
                    "sent_count": success_count,
                }
                if success_count:
                    target_result["bytes_per_packet"] = len(payload)
                    target_result["total_bytes"] = total_bytes
                if last_error is not None:
                    target_result["last_error"] = str(last_error)
                result["targets"].append(target_result)

        return result

    async def _async_send_packet(
        self,
        pkt: SimulatedPacket,
        network: dict[str, Any],
    ) -> dict[str, Any]:
        payload = bytes.fromhex(pkt.payload_hex)
        result = await self.hass.async_add_executor_job(
            self._send_udp_sync, payload, network
        )
        try:
            sent_count = int(result.get("sent_count", 0))
        except (TypeError, ValueError):
            sent_count = 0
        self._last_packet = pkt
        self._last_send_result = result
        self._last_send_completed_utc = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        self._packets_generated_since_start += 1
        self._udp_packets_sent_since_start += sent_count
        _LOGGER.debug(
            "Sent %s packet for entry %s: message_type=%s, sequence=%s, "
            "temperature_c=%s, temperature_index=%s, battery=%s, "
            "target_mode=%s, source_ip=%s, sent_count=%s, burst_repeats=%s, "
            "burst_delay_ms=%s, targets=%s, bind_source_ip=%s, "
            "bind_interface=%s, multicast_if=%s",
            pkt.stage,
            self.entry.entry_id,
            pkt.message_type,
            pkt.sequence,
            pkt.temperature_c,
            pkt.temperature_index,
            pkt.battery_percent,
            network.get("target_mode"),
            result.get("source_ip"),
            sent_count,
            result.get("burst_repeat_count"),
            result.get("burst_packet_delay_ms"),
            self._target_summary(result.get("targets")),
            result.get("bind_source_ip"),
            result.get("bind_interface"),
            result.get("set_multicast_interface"),
        )
        return result

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
        _LOGGER.debug(
            "Entered pairing mode for entry %s until %s",
            self.entry.entry_id,
            self._pairing_until,
        )
        await self._persist_state()

    async def async_exit_pairing_mode(self) -> None:
        self._pairing_until = None
        _LOGGER.debug("Exited pairing mode for entry %s", self.entry.entry_id)
        await self._persist_state()

    async def async_apply_pairing_state(self, key_b64: str, sequence: int) -> None:
        """Persist pairing credentials and sequence after a successful re-pair."""
        normalized_key = self._normalize_entry_key_b64(key_b64)
        if normalized_key is None:
            raise ValueError("Invalid sensor key")

        self._key_b64 = normalized_key
        self._sequence = self._normalize_sequence(sequence)
        self._pairing_until = None
        _LOGGER.debug(
            "Applied re-pairing state for entry %s: sequence=%s",
            self.entry.entry_id,
            self._sequence,
        )
        await self._persist_state()

    async def async_simulate_pair_packet(self) -> SimulatedPacket | None:
        source = self._resolve_temperature_source()
        if not self._handle_temperature_source_status(source):
            _LOGGER.debug(
                "Pair packet suppressed for entry %s because source status is %s",
                self.entry.entry_id,
                source.status,
            )
            return None

        temp_c = self._sample_temperature_c(source)
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

    async def async_simulate_update_packet(self) -> SimulatedPacket | None:
        source = self._resolve_temperature_source()
        if not self._handle_temperature_source_status(source):
            _LOGGER.debug(
                "Update packet suppressed for entry %s because source status is %s",
                self.entry.entry_id,
                source.status,
            )
            return None

        previous_sequence = self._sequence
        self._sequence = self._normalize_sequence(self._sequence + 1)
        if self._sequence < previous_sequence:
            _LOGGER.debug(
                "Sequence wrapped for entry %s: %s -> %s",
                self.entry.entry_id,
                previous_sequence,
                self._sequence,
            )

        temp_c = self._sample_temperature_c(source)
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
        source = self._resolve_temperature_source()
        network = await self._async_network_config()

        data: dict[str, Any] = {
            "entry_id": self.entry.entry_id,
            "name": self.entry.title,
            "source_interface": network["source_interface"],
            "source_ip": network["source_ip"],
            "source_ip_cidr": network["source_ip_cidr"],
            "source_mode": network["source_mode"],
            "target_mode": network["target_mode"],
            "unicast_target": network["unicast_target"],
            "directed_broadcast": network["directed_broadcast"],
            "multicast_target": network["multicast_target"],
            "udp_port": network["udp_port"],
            "legacy_broadcast_subnet": network["legacy_broadcast_subnet"],
            "targets": network["targets"],
            "unit_id": int(self._entry_value(CONF_UNIT_ID, DEFAULT_UNIT_ID)),
            "sensor_type": str(self._entry_value(CONF_SENSOR_TYPE, "remote")),
            "sensor_name": str(
                self._entry_value(CONF_SENSOR_NAME, DEFAULT_SENSOR_NAME)
            ),
            "sensor_mac": normalize_mac(
                str(self._entry_value(CONF_SENSOR_MAC, "dcf31c286547"))
            ),
            "temperature_entity": self._entry_value(CONF_TEMPERATURE_ENTITY, None),
            "temperature_source_status": source.status,
            "temperature_unit_mode": self._entry_value(
                CONF_TEMPERATURE_UNIT, DEFAULT_TEMPERATURE_UNIT
            ),
            "broadcast_enabled": source.broadcast_enabled,
            "temperature_random_fallback_active": source.uses_random_fallback,
            "source_temperature_c": source.temperature_c,
            "last_temperature_c": self._last_temp_c,
            "sequence": self._sequence,
            "battery_percent": self._battery_percent,
            "pairing_active": self.is_pairing_active(),
            "pairing_until": self._pairing_until.isoformat()
            if self._pairing_until
            else None,
            "last_packet": self._packet_diagnostics(self._last_packet),
            "last_send": self._send_diagnostics(),
            "last_send_status": self._send_status(self._last_send_result),
            "packets_generated_since_start": self._packets_generated_since_start,
            "udp_packets_sent_since_start": self._udp_packets_sent_since_start,
        }
        return data
