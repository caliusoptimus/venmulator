"""Config flow for WiFi Sensor Emulator for Venstar."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import random
import secrets
import socket
from datetime import datetime, timedelta, timezone
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import section
from homeassistant.helpers import selector

from .const import (
    DEFAULT_BATTERY_PERCENT,
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
    DEFAULT_NAME,
    DEFAULT_PAIRING_WINDOW_SEC,
    DEFAULT_SENSOR_NAME,
    DEFAULT_SENSOR_TYPE,
    DEFAULT_SOURCE_INTERFACE,
    DEFAULT_START_SEQUENCE,
    DEFAULT_TARGET_MODE,
    DEFAULT_TEMPERATURE_UNIT,
    DEFAULT_UNIT_ID,
    DEFAULT_UPDATE_INTERVAL_SEC,
    DEFAULT_UNICAST_TARGET,
    DOMAIN,
    IntegrationData,
    MAX_SEQUENCE,
    MAX_UPDATE_INTERVAL_SEC,
    MIN_UPDATE_INTERVAL_SEC,
    SENSOR_TYPE_NAME_TO_VALUE,
    TARGET_MODE_AUTO,
    TARGET_MODE_UNICAST,
    TARGET_MODES,
)
from .protocol import build_info, build_message, hmac_b64, normalize_mac, temp_c_to_index

OptionsFlowBase = getattr(
    config_entries, "OptionsFlowWithReload", config_entries.OptionsFlow
)
_LOGGER = logging.getLogger(__name__)
SECTION_ADVANCED = "advanced"
CONF_PAIR_AGAIN = "pair_again"
LEGACY_CONF_SOURCE_IP = "source_ip"


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


def _generate_default_mac() -> str:
    # Locally administered unicast MAC prefix.
    return "02" + secrets.token_hex(5)


def _existing_macs_for_entries(entries: list[config_entries.ConfigEntry]) -> set[str]:
    found: set[str] = set()
    for entry in entries:
        existing = entry.options.get(CONF_SENSOR_MAC, entry.data.get(CONF_SENSOR_MAC, ""))
        try:
            found.add(normalize_mac(str(existing)))
        except ValueError:
            continue
    return found


def _existing_unit_ids_for_entries(entries: list[config_entries.ConfigEntry]) -> set[int]:
    found: set[int] = set()
    for entry in entries:
        existing = entry.options.get(CONF_UNIT_ID, entry.data.get(CONF_UNIT_ID))
        try:
            unit_id = int(existing)
        except (TypeError, ValueError):
            continue
        if 1 <= unit_id <= 20:
            found.add(unit_id)
    return found


def _next_available_unit_id(used_unit_ids: set[int]) -> str:
    for candidate in range(1, 21):
        if candidate not in used_unit_ids:
            return str(candidate)
    return str(DEFAULT_UNIT_ID)


def _generate_unique_mac(existing_macs: set[str]) -> str | None:
    for _ in range(64):
        candidate = _generate_default_mac()
        if candidate not in existing_macs:
            return candidate
    return None


def _sensor_type_selector() -> selector.SelectSelector:
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=[
                selector.SelectOptionDict(value="outdoor", label="Outdoor"),
                selector.SelectOptionDict(value="return", label="Return"),
                selector.SelectOptionDict(value="remote", label="Remote"),
                selector.SelectOptionDict(value="supply", label="Supply"),
            ],
            mode=selector.SelectSelectorMode.DROPDOWN,
            translation_key="sensor_type",
        )
    )


def _unit_id_selector() -> selector.SelectSelector:
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=[
                selector.SelectOptionDict(value=str(n), label=str(n))
                for n in range(1, 21)
            ],
            mode=selector.SelectSelectorMode.DROPDOWN,
        )
    )


def _temperature_unit_selector() -> selector.SelectSelector:
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=[
                selector.SelectOptionDict(value="celsius", label="Celsius"),
                selector.SelectOptionDict(value="fahrenheit", label="Fahrenheit"),
            ],
            mode=selector.SelectSelectorMode.DROPDOWN,
            translation_key="temperature_unit",
        )
    )


def _temperature_entity_selector() -> selector.EntitySelector:
    return selector.EntitySelector(
        selector.EntitySelectorConfig(
            domain=["sensor", "number", "input_number"],
            multiple=False,
        )
    )


def _target_mode_selector() -> selector.SelectSelector:
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=[
                selector.SelectOptionDict(
                    value=TARGET_MODE_AUTO, label="Broadcast"
                ),
                selector.SelectOptionDict(value=TARGET_MODE_UNICAST, label="Unicast"),
            ],
            mode=selector.SelectSelectorMode.DROPDOWN,
            translation_key="target_mode",
        )
    )


def _source_interface_selector(
    options: list[selector.SelectOptionDict],
) -> selector.SelectSelector:
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=options,
            mode=selector.SelectSelectorMode.DROPDOWN,
            custom_value=True,
        )
    )


async def _async_get_adapters(
    flow: config_entries.ConfigFlow,
) -> list[dict[str, Any]] | None:
    adapters: list[dict[str, Any]] | None = None

    # Preferred API from HA docs.
    try:
        from homeassistant.components import network

        adapters = await network.async_get_adapters(flow.hass)
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
            adapters = await async_get_adapters(flow.hass)
        except Exception:  # noqa: BLE001
            _LOGGER.debug(
                "Could not read adapters from legacy network helper",
                exc_info=True,
            )
            return None

    if adapters is None:
        _LOGGER.debug("Network adapter discovery returned no adapter data")
        return None

    _LOGGER.debug("Network adapter discovery returned %s adapters", len(adapters))
    return adapters


async def _async_source_interface_options(
    flow: config_entries.ConfigFlow,
) -> list[selector.SelectOptionDict] | None:
    adapters = await _async_get_adapters(flow)
    if adapters is None:
        _LOGGER.debug("No network adapters available for source interface selector")
        return None

    options: list[selector.SelectOptionDict] = []
    seen: set[str] = set()
    for adapter in adapters:
        name = str(adapter.get("name", "")).strip()
        if not name or name in seen:
            continue
        seen.add(name)

        labels: list[str] = []
        ipv4_list = adapter.get("ipv4")
        if isinstance(ipv4_list, list):
            for ipv4 in ipv4_list:
                if not isinstance(ipv4, dict):
                    continue
                addr = ipv4.get("address")
                prefix = ipv4.get("network_prefix")
                if isinstance(addr, str) and isinstance(prefix, int):
                    labels.append(f"{addr}/{prefix}")

        label = name if not labels else f"{name} ({', '.join(labels)})"
        options.append(selector.SelectOptionDict(value=name, label=label))

    options.sort(key=lambda item: str(item["label"]).lower())
    _LOGGER.debug("Source interface selector has %s options", len(options))
    return options or None


def _normalize_unicast_target(value: str) -> str:
    address = ipaddress.ip_address(value.strip())
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("IPv4 unicast target required")
    return str(address)


def _normalize_target_mode(value: Any) -> str:
    target_mode = str(value or DEFAULT_TARGET_MODE).strip()
    if target_mode not in TARGET_MODES:
        return DEFAULT_TARGET_MODE
    return target_mode


def _normalize_key_b64(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    if len(decoded) != 32:
        return None
    return base64.b64encode(decoded).decode("ascii")


def _entry_runtime(entry: config_entries.ConfigEntry) -> Any | None:
    data = getattr(entry, "runtime_data", None)
    if isinstance(data, IntegrationData):
        return data.runtime
    return None


def _entry_pairing_key_b64(entry: config_entries.ConfigEntry) -> str | None:
    runtime = _entry_runtime(entry)
    if runtime is not None:
        runtime_key = _normalize_key_b64(runtime.key_b64)
        if runtime_key is not None:
            return runtime_key
    return _normalize_key_b64(entry.data.get(CONF_SENSOR_KEY_B64))


def _clean_target_settings(cleaned: dict[str, Any], errors: dict[str, str]) -> None:
    cleaned[CONF_TARGET_MODE] = _normalize_target_mode(
        cleaned.get(CONF_TARGET_MODE, DEFAULT_TARGET_MODE)
    )
    unicast_target_raw = str(
        cleaned.get(CONF_UNICAST_TARGET, DEFAULT_UNICAST_TARGET)
    ).strip()
    cleaned[CONF_UNICAST_TARGET] = unicast_target_raw

    if unicast_target_raw:
        try:
            cleaned[CONF_UNICAST_TARGET] = _normalize_unicast_target(unicast_target_raw)
        except ValueError:
            errors["base"] = "invalid_unicast_target"
    elif cleaned[CONF_TARGET_MODE] == TARGET_MODE_UNICAST:
        errors["base"] = "unicast_target_required"


def _flatten_advanced_input(user_input: dict[str, Any]) -> dict[str, Any]:
    """Flatten sectioned form input into stored config keys."""
    cleaned = dict(user_input)
    advanced = cleaned.pop(SECTION_ADVANCED, {})
    if isinstance(advanced, dict):
        cleaned.update(advanced)
    return cleaned


def _default_source_interface(
    source_interface_options: list[selector.SelectOptionDict] | None,
) -> str:
    if source_interface_options:
        return str(source_interface_options[0]["value"])
    return DEFAULT_SOURCE_INTERFACE


def _advanced_section_schema(defaults: dict[str, Any]) -> Any:
    return section(
        vol.Schema(
            {
                vol.Required(
                    CONF_TARGET_MODE, default=defaults[CONF_TARGET_MODE]
                ): _target_mode_selector(),
                vol.Optional(
                    CONF_UNICAST_TARGET, default=defaults[CONF_UNICAST_TARGET]
                ): str,
            }
        ),
        {"collapsed": True},
    )


def _normalize_sensor_name(value: str) -> str:
    name = value.strip()
    if not name:
        raise ValueError("sensor_name_required")
    if len(name.encode("utf-8")) > 14:
        raise ValueError("sensor_name_too_long")
    return name


def _resolve_source_ip_for_interface(
    adapters: list[dict[str, Any]] | None,
    source_interface: str,
) -> str | None:
    if adapters is None or not source_interface:
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


async def _async_resolve_pairing_network(
    flow: config_entries.ConfigFlow,
    config_data: dict[str, Any],
) -> dict[str, Any]:
    adapters = await _async_get_adapters(flow)
    source_interface = str(config_data.get(CONF_SOURCE_INTERFACE, "")).strip()
    legacy_source_ip = str(config_data.get(LEGACY_CONF_SOURCE_IP, "")).strip()
    target_mode = _normalize_target_mode(
        config_data.get(CONF_TARGET_MODE, DEFAULT_TARGET_MODE)
    )
    unicast_target = str(
        config_data.get(CONF_UNICAST_TARGET, DEFAULT_UNICAST_TARGET)
    ).strip()

    source_ip_cidr: str | None = None
    source_mode = "os_route"
    if source_interface:
        resolved = _resolve_source_ip_for_interface(adapters, source_interface)
        if resolved:
            source_ip_cidr = resolved
            source_mode = "interface"
        elif legacy_source_ip:
            source_ip_cidr = legacy_source_ip
            source_mode = "interface_fallback_legacy_source_ip"
        else:
            source_mode = "interface_unresolved"
    elif legacy_source_ip:
        source_ip_cidr = legacy_source_ip
        source_mode = "legacy_source_ip"

    source_ip: str | None = None
    directed_broadcast: str | None = None
    if source_ip_cidr:
        try:
            iface = ipaddress.ip_interface(source_ip_cidr)
            if isinstance(iface, ipaddress.IPv4Interface):
                source_ip = str(iface.ip)
                directed_broadcast = str(iface.network.broadcast_address)
        except ValueError:
            _LOGGER.debug(
                "Pairing network ignored invalid source IP CIDR: %s",
                source_ip_cidr,
            )
            pass

    if target_mode == TARGET_MODE_UNICAST and unicast_target:
        targets: list[dict[str, Any]] = [
            {"address": unicast_target, "port": 5001, "kind": "unicast"}
        ]
    else:
        targets = [{"address": "224.0.0.1", "port": 5001, "kind": "multicast"}]
        if directed_broadcast:
            targets.append(
                {
                    "address": directed_broadcast,
                    "port": 5001,
                    "kind": "directed_broadcast",
                }
            )

    network = {
        "source_interface": source_interface or None,
        "source_ip": source_ip,
        "source_mode": source_mode,
        "target_mode": target_mode,
        "unicast_target": unicast_target or None,
        "targets": targets,
    }
    _LOGGER.debug(
        "Resolved pairing network: source_interface=%s, source_ip=%s, "
        "source_mode=%s, target_mode=%s, unicast_target=%s, targets=%s",
        network["source_interface"],
        network["source_ip"],
        network["source_mode"],
        network["target_mode"],
        network["unicast_target"],
        _target_summary(network["targets"]),
    )
    return network


def _send_udp_payload_sync(payload: bytes, network: dict[str, Any]) -> dict[str, Any]:
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
                _LOGGER.debug("Pairing socket source bind failed: %s", err)
            try:
                multicast_if = socket.inet_aton(source_ip)
            except OSError as err:
                multicast_if = None
                result["set_multicast_interface"] = f"error:{err}"
            if multicast_if is None:
                pass
            else:
                try:
                    sock.setsockopt(
                        socket.IPPROTO_IP,
                        socket.IP_MULTICAST_IF,
                        multicast_if,
                    )
                    result["set_multicast_interface"] = "ok"
                except OSError as err:
                    result["set_multicast_interface"] = f"error:{err}"

        if isinstance(source_interface, str) and source_interface:
            bind_to_device = getattr(socket, "SO_BINDTODEVICE", None)
            if bind_to_device is not None:
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET,
                        bind_to_device,
                        source_interface.encode("utf-8") + b"\x00",
                    )
                    result["bind_interface"] = "ok"
                except OSError as err:
                    result["bind_interface"] = f"error:{err}"
            else:
                result["bind_interface"] = "unsupported"

        for target in targets:
            address = str(target.get("address", "")).strip()
            kind = str(target.get("kind", "unknown"))
            try:
                port = int(target.get("port", 0))
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


def _build_pairing_payloads(
    config_data: dict[str, Any],
    *,
    key_b64: str,
    base_sequence: int,
    temperature_c: float,
) -> tuple[bytes, bytes]:
    mac = str(config_data.get(CONF_SENSOR_MAC, ""))
    try:
        mac = normalize_mac(mac)
    except ValueError:
        mac = _generate_default_mac()

    sensor_type = SENSOR_TYPE_NAME_TO_VALUE.get(
        str(config_data.get(CONF_SENSOR_TYPE, DEFAULT_SENSOR_TYPE)),
        SENSOR_TYPE_NAME_TO_VALUE[DEFAULT_SENSOR_TYPE],
    )
    temp_idx = temp_c_to_index(temperature_c)

    common_kwargs = {
        "mac": mac,
        "unit_id": int(config_data.get(CONF_UNIT_ID, DEFAULT_UNIT_ID)),
        "sensor_name": str(config_data.get(CONF_SENSOR_NAME, DEFAULT_SENSOR_NAME)),
        "sensor_type": int(sensor_type),
        "temp_idx": temp_idx,
        "battery_percent": DEFAULT_BATTERY_PERCENT,
    }

    pair_info = build_info(sequence=base_sequence, **common_kwargs)
    pair_payload = build_message(
        message_type=43,
        info_bytes=pair_info,
        auth_b64=key_b64,
    )

    update_info = build_info(sequence=base_sequence + 1, **common_kwargs)
    key = base64.b64decode(key_b64)
    update_payload = build_message(
        message_type=42,
        info_bytes=update_info,
        auth_b64=hmac_b64(key, update_info),
    )
    return pair_payload, update_payload


def _create_schema(
    defaults: dict[str, Any],
    source_interface_options: list[selector.SelectOptionDict] | None,
) -> vol.Schema:
    if source_interface_options:
        source_interface_field: Any = _source_interface_selector(
            source_interface_options
        )
    else:
        source_interface_field = str

    schema: dict[Any, Any] = {
        vol.Required(CONF_NAME, default=defaults[CONF_NAME]): str,
        vol.Required(
            CONF_SOURCE_INTERFACE, default=defaults[CONF_SOURCE_INTERFACE]
        ): source_interface_field,
        vol.Required(CONF_SENSOR_NAME, default=defaults[CONF_SENSOR_NAME]): str,
        vol.Required(CONF_UNIT_ID, default=defaults[CONF_UNIT_ID]): _unit_id_selector(),
        vol.Required(CONF_SENSOR_TYPE, default=defaults[CONF_SENSOR_TYPE]): _sensor_type_selector(),
        vol.Required(
            CONF_TEMPERATURE_UNIT, default=defaults[CONF_TEMPERATURE_UNIT]
        ): _temperature_unit_selector(),
        vol.Required(
            CONF_UPDATE_INTERVAL_SEC, default=defaults[CONF_UPDATE_INTERVAL_SEC]
        ): vol.All(
            vol.Coerce(int),
            vol.Range(min=MIN_UPDATE_INTERVAL_SEC, max=MAX_UPDATE_INTERVAL_SEC),
        ),
    }

    temp_entity_default = defaults.get(CONF_TEMPERATURE_ENTITY)
    if temp_entity_default:
        schema[
            vol.Optional(CONF_TEMPERATURE_ENTITY, default=temp_entity_default)
        ] = _temperature_entity_selector()
    else:
        schema[vol.Optional(CONF_TEMPERATURE_ENTITY)] = _temperature_entity_selector()

    schema[vol.Required(SECTION_ADVANCED)] = _advanced_section_schema(defaults)

    return vol.Schema(schema)


def _reconfigure_schema(
    defaults: dict[str, Any],
    source_interface_options: list[selector.SelectOptionDict] | None,
    *,
    include_pair_again: bool = False,
) -> vol.Schema:
    if source_interface_options:
        source_interface_field: Any = _source_interface_selector(
            source_interface_options
        )
    else:
        source_interface_field = str

    schema: dict[Any, Any] = {
        vol.Required(CONF_NAME, default=defaults[CONF_NAME]): str,
        vol.Required(
            CONF_SOURCE_INTERFACE, default=defaults[CONF_SOURCE_INTERFACE]
        ): source_interface_field,
        vol.Required(
            CONF_TEMPERATURE_UNIT, default=defaults[CONF_TEMPERATURE_UNIT]
        ): _temperature_unit_selector(),
        vol.Required(
            CONF_UPDATE_INTERVAL_SEC, default=defaults[CONF_UPDATE_INTERVAL_SEC]
        ): vol.All(
            vol.Coerce(int),
            vol.Range(min=MIN_UPDATE_INTERVAL_SEC, max=MAX_UPDATE_INTERVAL_SEC),
        ),
    }

    temp_entity_default = defaults.get(CONF_TEMPERATURE_ENTITY)
    if temp_entity_default:
        schema[
            vol.Optional(CONF_TEMPERATURE_ENTITY, default=temp_entity_default)
        ] = _temperature_entity_selector()
    else:
        schema[vol.Optional(CONF_TEMPERATURE_ENTITY)] = _temperature_entity_selector()

    if include_pair_again:
        schema[
            vol.Optional(CONF_PAIR_AGAIN, default=defaults.get(CONF_PAIR_AGAIN, False))
        ] = bool

    schema[vol.Required(SECTION_ADVANCED)] = _advanced_section_schema(defaults)

    return vol.Schema(schema)


class VenstarConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for WiFi Sensor Emulator for Venstar."""

    VERSION = 1

    def __init__(self) -> None:
        self._pending_title: str = DEFAULT_NAME
        self._pending_data: dict[str, Any] | None = None
        self._pairing_task: asyncio.Task[None] | None = None
        self._pairing_deadline: datetime | None = None
        self._pairing_key_b64: str | None = None
        self._pending_pairing_key_b64: str | None = None
        self._pending_pairing_sequence_base: int | None = None
        self._pending_reconfigure_entry_id: str | None = None
        self._pairing_sequence_base: int = DEFAULT_START_SEQUENCE
        self._pairing_temperature_c: float = 20.0

    def _reset_pairing_state(self) -> None:
        _LOGGER.debug("Resetting config-flow pairing state")
        self._pairing_deadline = None
        self._pairing_key_b64 = None
        self._pending_pairing_key_b64 = None
        self._pending_pairing_sequence_base = None
        self._pairing_sequence_base = DEFAULT_START_SEQUENCE
        self._pairing_temperature_c = 20.0

    def _reset_reconfigure_pairing_context(self) -> None:
        self._pending_reconfigure_entry_id = None

    def _pending_reconfigure_entry(self) -> config_entries.ConfigEntry | None:
        if self._pending_reconfigure_entry_id is None:
            return None
        for entry in self._async_current_entries():
            if entry.entry_id == self._pending_reconfigure_entry_id:
                return entry
        return None

    async def _async_pause_reconfigure_runtime(
        self, entry: config_entries.ConfigEntry
    ) -> None:
        runtime = _entry_runtime(entry)
        if runtime is None:
            return
        _LOGGER.debug(
            "Putting runtime for entry %s into pairing pause during re-pairing",
            entry.entry_id,
        )
        await runtime.async_enter_pairing_mode()

    async def _async_resume_reconfigure_runtime(
        self, entry: config_entries.ConfigEntry
    ) -> None:
        runtime = _entry_runtime(entry)
        if runtime is None:
            return
        _LOGGER.debug(
            "Clearing runtime pairing pause for entry %s after re-pairing flow",
            entry.entry_id,
        )
        await runtime.async_exit_pairing_mode()

    async def _async_stop_pairing_task(self) -> None:
        if self._pairing_task is None:
            return
        _LOGGER.debug("Stopping config-flow pairing sender task")
        self._pairing_task.cancel()
        try:
            await self._pairing_task
        except asyncio.CancelledError:
            pass
        self._pairing_task = None
        _LOGGER.debug("Config-flow pairing sender task stopped")

    def _pairing_timed_out(self) -> bool:
        if self._pairing_deadline is None:
            return True
        return datetime.now(timezone.utc) >= self._pairing_deadline

    async def _async_pairing_sender_loop(self) -> None:
        try:
            while (
                self._pending_data is not None
                and self._pairing_key_b64 is not None
                and self._pairing_deadline is not None
                and datetime.now(timezone.utc) < self._pairing_deadline
            ):
                network = await _async_resolve_pairing_network(self, self._pending_data)
                pair_payload, update_payload = _build_pairing_payloads(
                    self._pending_data,
                    key_b64=self._pairing_key_b64,
                    base_sequence=self._pairing_sequence_base,
                    temperature_c=self._pairing_temperature_c,
                )

                pair_result = await self.hass.async_add_executor_job(
                    _send_udp_payload_sync, pair_payload, network
                )
                update_result = await self.hass.async_add_executor_job(
                    _send_udp_payload_sync, update_payload, network
                )
                _LOGGER.debug(
                    "Sent pairing flow packets: pair_sequence=%s, "
                    "update_sequence=%s, target_mode=%s, pair_sent=%s, "
                    "update_sent=%s, pair_targets=%s, update_targets=%s",
                    self._pairing_sequence_base,
                    self._pairing_sequence_base + 1,
                    network.get("target_mode"),
                    pair_result.get("sent_count"),
                    update_result.get("sent_count"),
                    _target_summary(pair_result.get("targets")),
                    _target_summary(update_result.get("targets")),
                )
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            _LOGGER.debug("Config-flow pairing sender loop cancelled")
            return

    async def _async_start_pairing_task(self) -> None:
        if self._pending_data is None:
            return
        await self._async_stop_pairing_task()
        self._pairing_key_b64 = self._pending_pairing_key_b64 or base64.b64encode(
            secrets.token_bytes(32)
        ).decode("ascii")
        self._pairing_sequence_base = (
            self._pending_pairing_sequence_base
            if self._pending_pairing_sequence_base is not None
            else DEFAULT_START_SEQUENCE
        )
        self._pairing_temperature_c = random.uniform(10.0, 30.0)
        timeout = DEFAULT_PAIRING_WINDOW_SEC
        self._pairing_deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
        self._pairing_task = self.hass.async_create_task(self._async_pairing_sender_loop())
        _LOGGER.debug(
            "Started config-flow pairing sender: timeout=%ss, deadline=%s, "
            "base_sequence=%s, target_mode=%s, unicast_target=%s",
            timeout,
            self._pairing_deadline,
            self._pairing_sequence_base,
            self._pending_data.get(CONF_TARGET_MODE),
            self._pending_data.get(CONF_UNICAST_TARGET),
        )

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        source_interface_options = await _async_source_interface_options(self)
        existing_entries = self._async_current_entries()
        used_unit_ids = _existing_unit_ids_for_entries(existing_entries)
        _LOGGER.debug(
            "Showing user step: existing_entries=%s, used_unit_ids=%s",
            len(existing_entries),
            sorted(used_unit_ids),
        )

        defaults = {
            CONF_NAME: DEFAULT_NAME,
            CONF_SOURCE_INTERFACE: _default_source_interface(source_interface_options),
            CONF_TARGET_MODE: DEFAULT_TARGET_MODE,
            CONF_UNICAST_TARGET: DEFAULT_UNICAST_TARGET,
            CONF_SENSOR_NAME: DEFAULT_SENSOR_NAME,
            CONF_UNIT_ID: _next_available_unit_id(used_unit_ids),
            CONF_SENSOR_TYPE: DEFAULT_SENSOR_TYPE,
            CONF_TEMPERATURE_UNIT: DEFAULT_TEMPERATURE_UNIT,
            CONF_UPDATE_INTERVAL_SEC: DEFAULT_UPDATE_INTERVAL_SEC,
            CONF_TEMPERATURE_ENTITY: None,
        }

        if user_input is not None:
            cleaned = _flatten_advanced_input(user_input)
            cleaned[CONF_SENSOR_NAME] = str(cleaned.get(CONF_SENSOR_NAME, ""))
            _clean_target_settings(cleaned, errors)
            _LOGGER.debug(
                "Received user step input: source_interface=%s, "
                "target_mode=%s, unicast_target=%s, sensor_type=%s, "
                "unit_id=%s, temp_unit=%s, update_interval=%s, "
                "temperature_entity=%s",
                str(cleaned.get(CONF_SOURCE_INTERFACE, "")).strip(),
                cleaned.get(CONF_TARGET_MODE),
                cleaned.get(CONF_UNICAST_TARGET),
                cleaned.get(CONF_SENSOR_TYPE),
                cleaned.get(CONF_UNIT_ID),
                cleaned.get(CONF_TEMPERATURE_UNIT),
                cleaned.get(CONF_UPDATE_INTERVAL_SEC),
                cleaned.get(CONF_TEMPERATURE_ENTITY),
            )

            try:
                cleaned[CONF_SENSOR_NAME] = _normalize_sensor_name(
                    cleaned[CONF_SENSOR_NAME]
                )
            except ValueError as err:
                errors["base"] = str(err)

            cleaned[CONF_SOURCE_INTERFACE] = str(
                cleaned.get(CONF_SOURCE_INTERFACE, "")
            ).strip()
            if not cleaned[CONF_SOURCE_INTERFACE]:
                errors["base"] = "network_interface_required"

            if not errors:
                try:
                    selected_unit_id = int(cleaned[CONF_UNIT_ID])
                except (TypeError, ValueError):
                    selected_unit_id = DEFAULT_UNIT_ID
                if selected_unit_id in used_unit_ids:
                    errors["base"] = "unit_id_in_use"

            if not errors:
                existing_macs = _existing_macs_for_entries(existing_entries)
                generated_mac = _generate_unique_mac(existing_macs)
                if generated_mac is None:
                    errors["base"] = "cannot_generate_mac"
                else:
                    cleaned[CONF_SENSOR_MAC] = generated_mac

            if not errors:
                await self.async_set_unique_id(cleaned[CONF_SENSOR_MAC])
                self._abort_if_unique_id_configured()

                title = cleaned[CONF_NAME]
                data = dict(cleaned)
                data.pop(CONF_NAME, None)
                if data.get(CONF_SENSOR_TYPE) not in SENSOR_TYPE_NAME_TO_VALUE:
                    data[CONF_SENSOR_TYPE] = DEFAULT_SENSOR_TYPE

                self._pending_title = title
                self._pending_data = data
                await self._async_stop_pairing_task()
                self._reset_pairing_state()
                self._reset_reconfigure_pairing_context()
                _LOGGER.debug(
                    "User step accepted; generated emulated sensor identity: "
                    "unit_id=%s, sensor_type=%s, target_mode=%s, unicast_target=%s",
                    data.get(CONF_UNIT_ID),
                    data.get(CONF_SENSOR_TYPE),
                    data.get(CONF_TARGET_MODE),
                    data.get(CONF_UNICAST_TARGET),
                )
                return await self.async_step_pair_ready()

            defaults.update(cleaned)
            _LOGGER.debug("User step validation failed: errors=%s", errors)

        return self.async_show_form(
            step_id="user",
            data_schema=_create_schema(defaults, source_interface_options),
            errors=errors,
        )

    async def async_step_pair_ready(self, user_input: dict[str, Any] | None = None):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        _LOGGER.debug("Showing pair-ready step")
        return self.async_show_menu(
            step_id="pair_ready",
            menu_options={"pair_start": "Pair"},
        )

    async def async_step_pair_start(self, user_input: dict[str, Any] | None = None):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        _LOGGER.debug("Pair button pressed")
        if self._pending_reconfigure_entry_id is not None:
            entry = self._pending_reconfigure_entry()
            if entry is not None:
                await self._async_pause_reconfigure_runtime(entry)
        await self._async_start_pairing_task()
        return await self.async_step_pairing_active()

    async def _async_finish_reconfigure_pairing(self):
        entry = self._pending_reconfigure_entry()
        if entry is None:
            return self.async_abort(reason="reconfigure_entry_not_found")
        if not self._pairing_key_b64:
            return self.async_abort(reason="pairing_context_missing")

        start_sequence = (self._pairing_sequence_base + 1) % (MAX_SEQUENCE + 1)
        data_updates = {
            CONF_SENSOR_KEY_B64: self._pairing_key_b64,
            CONF_START_SEQUENCE: start_sequence,
        }
        entry_id = entry.entry_id
        runtime = _entry_runtime(entry)
        if runtime is not None:
            await runtime.async_apply_pairing_state(
                self._pairing_key_b64,
                start_sequence,
            )
        else:
            await self._async_resume_reconfigure_runtime(entry)

        self._pending_data = None
        self._reset_pairing_state()
        self._reset_reconfigure_pairing_context()
        _LOGGER.debug(
            "Re-pairing flow completed for entry %s; reloading entry with "
            "start_sequence=%s",
            entry_id,
            start_sequence,
        )

        if hasattr(self, "async_update_reload_and_abort"):
            return self.async_update_reload_and_abort(entry, data_updates=data_updates)

        data = dict(entry.data)
        data.update(data_updates)
        self.hass.config_entries.async_update_entry(entry, data=data)
        await self.hass.config_entries.async_reload(entry.entry_id)
        return self.async_abort(reason="reconfigure_successful")

    async def async_step_pairing_active(
        self, user_input: dict[str, Any] | None = None
    ):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        if self._pairing_timed_out():
            await self._async_stop_pairing_task()
            _LOGGER.debug("Pairing flow timed out")
            return self.async_show_menu(
                step_id="pair_timeout",
                menu_options={
                    "pair_start": "Pair Again",
                    "pair_cancel": "Cancel Pairing",
                },
            )

        remaining = 0
        if self._pairing_deadline is not None:
            remaining = max(
                0, int((self._pairing_deadline - datetime.now(timezone.utc)).total_seconds())
            )

        return self.async_show_menu(
            step_id="pairing_active",
            menu_options={
                "pair_success": "Pairing Successful",
                "pair_cancel": "Cancel Pairing",
            },
            description_placeholders={"remaining_seconds": str(remaining)},
        )

    async def async_step_pair_success(self, user_input: dict[str, Any] | None = None):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        if self._pairing_timed_out():
            _LOGGER.debug("Pairing success requested after timeout")
            return await self.async_step_pairing_active()

        await self._async_stop_pairing_task()
        if not self._pairing_key_b64:
            return self.async_abort(reason="pairing_context_missing")
        if self._pending_reconfigure_entry_id is not None:
            return await self._async_finish_reconfigure_pairing()

        data = dict(self._pending_data)
        data[CONF_SENSOR_KEY_B64] = self._pairing_key_b64
        data[CONF_START_SEQUENCE] = (self._pairing_sequence_base + 1) % (
            MAX_SEQUENCE + 1
        )
        title = self._pending_title

        self._pending_data = None
        self._reset_pairing_state()
        _LOGGER.debug(
            "Pairing flow completed; creating entry title=%s, start_sequence=%s",
            title,
            data[CONF_START_SEQUENCE],
        )
        return self.async_create_entry(title=title, data=data)

    async def async_step_pair_cancel(self, user_input: dict[str, Any] | None = None):
        _LOGGER.debug("Pairing flow cancel requested")
        await self._async_stop_pairing_task()
        if self._pending_reconfigure_entry_id is not None:
            entry = self._pending_reconfigure_entry()
            if entry is not None:
                await self._async_resume_reconfigure_runtime(entry)
            self._pending_data = None
            self._reset_pairing_state()
            self._reset_reconfigure_pairing_context()
            if hasattr(self, "async_update_reload_and_abort"):
                return self.async_update_reload_and_abort(entry, data_updates={})
            await self.hass.config_entries.async_reload(entry.entry_id)
            return self.async_abort(reason="reconfigure_successful")
        self._reset_pairing_state()
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        return await self.async_step_pair_ready()

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ):
        errors: dict[str, str] = {}
        source_interface_options = await _async_source_interface_options(self)

        entry = self._get_reconfigure_entry()
        if entry is None:
            return self.async_abort(reason="reconfigure_entry_not_found")
        if entry.unique_id:
            await self.async_set_unique_id(entry.unique_id)
            self._abort_if_unique_id_mismatch()
        _LOGGER.debug("Showing reconfigure step for entry %s", entry.entry_id)

        defaults = {
            CONF_NAME: entry.title,
            CONF_SOURCE_INTERFACE: entry.options.get(
                CONF_SOURCE_INTERFACE,
                entry.data.get(CONF_SOURCE_INTERFACE, DEFAULT_SOURCE_INTERFACE),
            ),
            CONF_TARGET_MODE: entry.options.get(
                CONF_TARGET_MODE,
                entry.data.get(CONF_TARGET_MODE, DEFAULT_TARGET_MODE),
            ),
            CONF_UNICAST_TARGET: entry.options.get(
                CONF_UNICAST_TARGET,
                entry.data.get(CONF_UNICAST_TARGET, DEFAULT_UNICAST_TARGET),
            ),
            CONF_TEMPERATURE_UNIT: entry.options.get(
                CONF_TEMPERATURE_UNIT,
                entry.data.get(CONF_TEMPERATURE_UNIT, DEFAULT_TEMPERATURE_UNIT),
            ),
            CONF_UPDATE_INTERVAL_SEC: entry.options.get(
                CONF_UPDATE_INTERVAL_SEC,
                entry.data.get(CONF_UPDATE_INTERVAL_SEC, DEFAULT_UPDATE_INTERVAL_SEC),
            ),
            CONF_TEMPERATURE_ENTITY: entry.options.get(
                CONF_TEMPERATURE_ENTITY, entry.data.get(CONF_TEMPERATURE_ENTITY)
            ),
            CONF_PAIR_AGAIN: False,
        }

        if user_input is not None:
            cleaned = _flatten_advanced_input(user_input)
            _clean_target_settings(cleaned, errors)
            cleaned[CONF_SOURCE_INTERFACE] = str(
                cleaned.get(CONF_SOURCE_INTERFACE, "")
            ).strip()
            if not cleaned[CONF_SOURCE_INTERFACE]:
                errors["base"] = "network_interface_required"
            pair_again = bool(cleaned.pop(CONF_PAIR_AGAIN, False))
            _LOGGER.debug(
                "Received reconfigure input for entry %s: source_interface=%s, "
                "target_mode=%s, unicast_target=%s, temp_unit=%s, "
                "update_interval=%s, temperature_entity=%s, pair_again=%s",
                entry.entry_id,
                cleaned.get(CONF_SOURCE_INTERFACE),
                cleaned.get(CONF_TARGET_MODE),
                cleaned.get(CONF_UNICAST_TARGET),
                cleaned.get(CONF_TEMPERATURE_UNIT),
                cleaned.get(CONF_UPDATE_INTERVAL_SEC),
                cleaned.get(CONF_TEMPERATURE_ENTITY),
                pair_again,
            )

        if user_input is not None and not errors:
            title = str(cleaned[CONF_NAME])
            options = dict(entry.options)
            options.update(
                {
                    CONF_SOURCE_INTERFACE: cleaned[CONF_SOURCE_INTERFACE],
                    CONF_TARGET_MODE: cleaned[CONF_TARGET_MODE],
                    CONF_UNICAST_TARGET: cleaned[CONF_UNICAST_TARGET],
                    CONF_TEMPERATURE_UNIT: cleaned[CONF_TEMPERATURE_UNIT],
                    CONF_UPDATE_INTERVAL_SEC: cleaned[CONF_UPDATE_INTERVAL_SEC],
                    CONF_TEMPERATURE_ENTITY: cleaned.get(CONF_TEMPERATURE_ENTITY),
                }
            )

            self.hass.config_entries.async_update_entry(
                entry,
                title=title,
                options=options,
            )
            _LOGGER.debug(
                "Updated reconfigure options for entry %s: title=%s, "
                "source_interface=%s, target_mode=%s, unicast_target=%s, "
                "update_interval=%s",
                entry.entry_id,
                title,
                options.get(CONF_SOURCE_INTERFACE),
                options.get(CONF_TARGET_MODE),
                options.get(CONF_UNICAST_TARGET),
                options.get(CONF_UPDATE_INTERVAL_SEC),
            )
            if pair_again:
                key_b64 = _entry_pairing_key_b64(entry)
                if key_b64 is None:
                    key_b64 = base64.b64encode(secrets.token_bytes(32)).decode(
                        "ascii"
                    )
                    _LOGGER.debug(
                        "Generated replacement pairing key for entry %s "
                        "because no valid existing key was available",
                        entry.entry_id,
                    )
                pending_data = dict(entry.data)
                pending_data.update(options)
                self._pending_title = title
                self._pending_data = pending_data
                self._pending_pairing_key_b64 = key_b64
                self._pending_pairing_sequence_base = DEFAULT_START_SEQUENCE
                self._pending_reconfigure_entry_id = entry.entry_id
                await self._async_pause_reconfigure_runtime(entry)
                _LOGGER.debug(
                    "Reconfigure requested re-pairing for entry %s: "
                    "reset_sequence_base=%s, target_mode=%s, unicast_target=%s",
                    entry.entry_id,
                    self._pending_pairing_sequence_base,
                    pending_data.get(CONF_TARGET_MODE),
                    pending_data.get(CONF_UNICAST_TARGET),
                )
                return await self.async_step_pair_ready()
            if hasattr(self, "async_update_reload_and_abort"):
                return self.async_update_reload_and_abort(entry, data_updates={})
            await self.hass.config_entries.async_reload(entry.entry_id)
            return self.async_abort(reason="reconfigure_successful")
        if user_input is not None:
            _LOGGER.debug(
                "Reconfigure validation failed for entry %s: errors=%s",
                entry.entry_id,
                errors,
            )
            defaults.update(cleaned)
            defaults[CONF_PAIR_AGAIN] = pair_again

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_reconfigure_schema(
                defaults,
                source_interface_options,
                include_pair_again=True,
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return VenstarOptionsFlow()


class VenstarOptionsFlow(OptionsFlowBase):
    """Handle options flow for the integration."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        source_interface_options = await _async_source_interface_options(self)

        defaults = {
            CONF_NAME: self.config_entry.title,
            CONF_SOURCE_INTERFACE: self.config_entry.options.get(
                CONF_SOURCE_INTERFACE,
                self.config_entry.data.get(CONF_SOURCE_INTERFACE, DEFAULT_SOURCE_INTERFACE),
            ),
            CONF_TARGET_MODE: self.config_entry.options.get(
                CONF_TARGET_MODE,
                self.config_entry.data.get(CONF_TARGET_MODE, DEFAULT_TARGET_MODE),
            ),
            CONF_UNICAST_TARGET: self.config_entry.options.get(
                CONF_UNICAST_TARGET,
                self.config_entry.data.get(CONF_UNICAST_TARGET, DEFAULT_UNICAST_TARGET),
            ),
            CONF_TEMPERATURE_UNIT: self.config_entry.options.get(
                CONF_TEMPERATURE_UNIT,
                self.config_entry.data.get(CONF_TEMPERATURE_UNIT, DEFAULT_TEMPERATURE_UNIT),
            ),
            CONF_UPDATE_INTERVAL_SEC: self.config_entry.options.get(
                CONF_UPDATE_INTERVAL_SEC,
                self.config_entry.data.get(
                    CONF_UPDATE_INTERVAL_SEC, DEFAULT_UPDATE_INTERVAL_SEC
                ),
            ),
            CONF_TEMPERATURE_ENTITY: self.config_entry.options.get(
                CONF_TEMPERATURE_ENTITY,
                self.config_entry.data.get(CONF_TEMPERATURE_ENTITY),
            ),
        }

        if user_input is not None:
            cleaned = _flatten_advanced_input(user_input)
            _clean_target_settings(cleaned, errors)
            cleaned[CONF_SOURCE_INTERFACE] = str(
                cleaned.get(CONF_SOURCE_INTERFACE, "")
            ).strip()
            if not cleaned[CONF_SOURCE_INTERFACE]:
                errors["base"] = "network_interface_required"
            _LOGGER.debug(
                "Received options input for entry %s: source_interface=%s, "
                "target_mode=%s, unicast_target=%s, temp_unit=%s, "
                "update_interval=%s, temperature_entity=%s",
                self.config_entry.entry_id,
                cleaned.get(CONF_SOURCE_INTERFACE),
                cleaned.get(CONF_TARGET_MODE),
                cleaned.get(CONF_UNICAST_TARGET),
                cleaned.get(CONF_TEMPERATURE_UNIT),
                cleaned.get(CONF_UPDATE_INTERVAL_SEC),
                cleaned.get(CONF_TEMPERATURE_ENTITY),
            )
            if errors:
                defaults.update(cleaned)
                _LOGGER.debug(
                    "Options validation failed for entry %s: errors=%s",
                    self.config_entry.entry_id,
                    errors,
                )
                return self.async_show_form(
                    step_id="init",
                    data_schema=_reconfigure_schema(defaults, source_interface_options),
                    errors=errors,
                )
            title = cleaned.pop(CONF_NAME)
            if title != self.config_entry.title:
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    title=title,
                )
                _LOGGER.debug(
                    "Updated entry title from options flow for entry %s: %s",
                    self.config_entry.entry_id,
                    title,
                )
            _LOGGER.debug(
                "Updated options for entry %s: source_interface=%s, "
                "target_mode=%s, unicast_target=%s, update_interval=%s",
                self.config_entry.entry_id,
                cleaned.get(CONF_SOURCE_INTERFACE),
                cleaned.get(CONF_TARGET_MODE),
                cleaned.get(CONF_UNICAST_TARGET),
                cleaned.get(CONF_UPDATE_INTERVAL_SEC),
            )
            return self.async_create_entry(title="", data=cleaned)

        _LOGGER.debug("Showing options step for entry %s", self.config_entry.entry_id)
        return self.async_show_form(
            step_id="init",
            data_schema=_reconfigure_schema(defaults, source_interface_options),
            errors=errors,
        )
