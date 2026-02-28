"""Config flow for Venstar WiFi Sensor Emulator."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import random
import secrets
import socket
from datetime import datetime, timedelta, timezone
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
    DEFAULT_BATTERY_PERCENT,
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
    DEFAULT_NAME,
    DEFAULT_PAIRING_WINDOW_SEC,
    DEFAULT_SENSOR_NAME,
    DEFAULT_SENSOR_TYPE,
    DEFAULT_SOURCE_INTERFACE,
    DEFAULT_SOURCE_IP,
    DEFAULT_START_SEQUENCE,
    DEFAULT_TEMPERATURE_UNIT,
    DEFAULT_UNIT_ID,
    DEFAULT_UPDATE_INTERVAL_SEC,
    DOMAIN,
    SENSOR_TYPE_NAME_TO_VALUE,
)
from .protocol import build_info, build_message, hmac_b64, normalize_mac, temp_c_to_index

OptionsFlowBase = getattr(
    config_entries, "OptionsFlowWithReload", config_entries.OptionsFlow
)


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

    # Backward compatibility fallback.
    if adapters is None:
        try:
            from homeassistant.components.network.util import async_get_adapters
        except Exception:  # noqa: BLE001
            return None

        try:
            adapters = await async_get_adapters(flow.hass)
        except Exception:  # noqa: BLE001
            return None

    return adapters


async def _async_source_interface_options(
    flow: config_entries.ConfigFlow,
) -> list[selector.SelectOptionDict] | None:
    adapters = await _async_get_adapters(flow)
    if adapters is None:
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
    return options or None


def _normalize_source_ip(value: str) -> str:
    source = value.strip()
    if "/" not in source:
        raise ValueError("CIDR prefix is required")
    interface = ipaddress.ip_interface(source)
    if interface.version != 4:
        raise ValueError("IPv4 source IP required")
    if interface.network.prefixlen >= 31:
        raise ValueError("CIDR prefix too narrow for broadcast")
    return str(interface)


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
    configured_source_ip = str(config_data.get(CONF_SOURCE_IP, "")).strip()

    source_ip_cidr = configured_source_ip
    source_mode = "static"
    if source_interface:
        resolved = _resolve_source_ip_for_interface(adapters, source_interface)
        if resolved:
            source_ip_cidr = resolved
            source_mode = "interface"
        elif configured_source_ip:
            source_mode = "interface_fallback_static"
        else:
            source_mode = "interface_unresolved"

    source_ip: str | None = None
    directed_broadcast: str | None = None
    if source_ip_cidr:
        try:
            iface = ipaddress.ip_interface(source_ip_cidr)
            if isinstance(iface, ipaddress.IPv4Interface):
                source_ip = str(iface.ip)
                directed_broadcast = str(iface.network.broadcast_address)
        except ValueError:
            pass

    targets: list[dict[str, Any]] = [
        {"address": "224.0.0.1", "port": 5001, "kind": "multicast"}
    ]
    if directed_broadcast:
        targets.append(
            {
                "address": directed_broadcast,
                "port": 5001,
                "kind": "directed_broadcast",
            }
        )

    return {
        "source_interface": source_interface or None,
        "source_ip": source_ip,
        "source_mode": source_mode,
        "targets": targets,
    }


def _send_udp_payload_sync(payload: bytes, network: dict[str, Any]) -> None:
    source_ip = network.get("source_ip")
    source_interface = network.get("source_interface")
    targets = network.get("targets")
    if not isinstance(targets, list):
        targets = []

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except OSError:
            pass

        if isinstance(source_ip, str) and source_ip:
            try:
                sock.bind((source_ip, 0))
            except OSError:
                pass
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip)
                )
            except OSError:
                pass

        if isinstance(source_interface, str) and source_interface:
            bind_to_device = getattr(socket, "SO_BINDTODEVICE", None)
            if bind_to_device is not None:
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET,
                        bind_to_device,
                        source_interface.encode("utf-8") + b"\x00",
                    )
                except OSError:
                    pass

        for target in targets:
            address = str(target.get("address", "")).strip()
            try:
                port = int(target.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            if not address or port <= 0:
                continue
            try:
                sock.sendto(payload, (address, port))
            except OSError:
                continue


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
        vol.Optional(
            CONF_SOURCE_INTERFACE, default=defaults[CONF_SOURCE_INTERFACE]
        ): source_interface_field,
        vol.Optional(CONF_SOURCE_IP, default=defaults[CONF_SOURCE_IP]): str,
        vol.Required(CONF_SENSOR_NAME, default=defaults[CONF_SENSOR_NAME]): str,
        vol.Required(CONF_UNIT_ID, default=defaults[CONF_UNIT_ID]): _unit_id_selector(),
        vol.Required(CONF_SENSOR_TYPE, default=defaults[CONF_SENSOR_TYPE]): _sensor_type_selector(),
        vol.Required(
            CONF_TEMPERATURE_UNIT, default=defaults[CONF_TEMPERATURE_UNIT]
        ): _temperature_unit_selector(),
        vol.Required(
            CONF_UPDATE_INTERVAL_SEC, default=defaults[CONF_UPDATE_INTERVAL_SEC]
        ): vol.All(vol.Coerce(int), vol.Range(min=2, max=60)),
    }

    temp_entity_default = defaults.get(CONF_TEMPERATURE_ENTITY)
    if temp_entity_default:
        schema[
            vol.Optional(CONF_TEMPERATURE_ENTITY, default=temp_entity_default)
        ] = _temperature_entity_selector()
    else:
        schema[vol.Optional(CONF_TEMPERATURE_ENTITY)] = _temperature_entity_selector()

    return vol.Schema(schema)


def _reconfigure_schema(defaults: dict[str, Any]) -> vol.Schema:
    schema: dict[Any, Any] = {
        vol.Required(CONF_NAME, default=defaults[CONF_NAME]): str,
        vol.Required(
            CONF_TEMPERATURE_UNIT, default=defaults[CONF_TEMPERATURE_UNIT]
        ): _temperature_unit_selector(),
        vol.Required(
            CONF_UPDATE_INTERVAL_SEC, default=defaults[CONF_UPDATE_INTERVAL_SEC]
        ): vol.All(vol.Coerce(int), vol.Range(min=2, max=60)),
    }

    temp_entity_default = defaults.get(CONF_TEMPERATURE_ENTITY)
    if temp_entity_default:
        schema[
            vol.Optional(CONF_TEMPERATURE_ENTITY, default=temp_entity_default)
        ] = _temperature_entity_selector()
    else:
        schema[vol.Optional(CONF_TEMPERATURE_ENTITY)] = _temperature_entity_selector()

    return vol.Schema(schema)


class VenstarConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Venstar WiFi Sensor Emulator."""

    VERSION = 1

    def __init__(self) -> None:
        self._pending_title: str = DEFAULT_NAME
        self._pending_data: dict[str, Any] | None = None
        self._pairing_task: asyncio.Task[None] | None = None
        self._pairing_deadline: datetime | None = None
        self._pairing_key_b64: str | None = None
        self._pairing_sequence_base: int = DEFAULT_START_SEQUENCE
        self._pairing_temperature_c: float = 20.0

    def _reset_pairing_state(self) -> None:
        self._pairing_deadline = None
        self._pairing_key_b64 = None
        self._pairing_sequence_base = DEFAULT_START_SEQUENCE
        self._pairing_temperature_c = 20.0

    async def _async_stop_pairing_task(self) -> None:
        if self._pairing_task is None:
            return
        self._pairing_task.cancel()
        try:
            await self._pairing_task
        except asyncio.CancelledError:
            pass
        self._pairing_task = None

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

                await self.hass.async_add_executor_job(
                    _send_udp_payload_sync, pair_payload, network
                )
                await self.hass.async_add_executor_job(
                    _send_udp_payload_sync, update_payload, network
                )
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            return

    async def _async_start_pairing_task(self) -> None:
        if self._pending_data is None:
            return
        await self._async_stop_pairing_task()
        self._pairing_key_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self._pairing_sequence_base = DEFAULT_START_SEQUENCE
        self._pairing_temperature_c = random.uniform(10.0, 30.0)
        timeout = DEFAULT_PAIRING_WINDOW_SEC
        self._pairing_deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
        self._pairing_task = self.hass.async_create_task(self._async_pairing_sender_loop())

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        source_interface_options = await _async_source_interface_options(self)
        existing_entries = self._async_current_entries()
        used_unit_ids = _existing_unit_ids_for_entries(existing_entries)

        defaults = {
            CONF_NAME: DEFAULT_NAME,
            CONF_SOURCE_INTERFACE: DEFAULT_SOURCE_INTERFACE,
            CONF_SOURCE_IP: DEFAULT_SOURCE_IP,
            CONF_SENSOR_NAME: DEFAULT_SENSOR_NAME,
            CONF_UNIT_ID: _next_available_unit_id(used_unit_ids),
            CONF_SENSOR_TYPE: DEFAULT_SENSOR_TYPE,
            CONF_TEMPERATURE_UNIT: DEFAULT_TEMPERATURE_UNIT,
            CONF_UPDATE_INTERVAL_SEC: DEFAULT_UPDATE_INTERVAL_SEC,
            CONF_TEMPERATURE_ENTITY: None,
        }

        if user_input is not None:
            cleaned = dict(user_input)
            cleaned[CONF_SENSOR_NAME] = str(cleaned.get(CONF_SENSOR_NAME, ""))

            try:
                cleaned[CONF_SENSOR_NAME] = _normalize_sensor_name(
                    cleaned[CONF_SENSOR_NAME]
                )
            except ValueError as err:
                errors["base"] = str(err)

            cleaned[CONF_SOURCE_INTERFACE] = str(
                cleaned.get(CONF_SOURCE_INTERFACE, "")
            ).strip()
            source_ip_raw = str(cleaned.get(CONF_SOURCE_IP, "")).strip()
            cleaned[CONF_SOURCE_IP] = source_ip_raw

            if source_ip_raw:
                if not errors:
                    try:
                        cleaned[CONF_SOURCE_IP] = _normalize_source_ip(source_ip_raw)
                    except ValueError:
                        errors["base"] = "invalid_source_ip"
            elif not cleaned[CONF_SOURCE_INTERFACE]:
                errors["base"] = "source_required"

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
                return await self.async_step_pair_ready()

            defaults.update(user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=_create_schema(defaults, source_interface_options),
            errors=errors,
        )

    async def async_step_pair_ready(self, user_input: dict[str, Any] | None = None):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        return self.async_show_menu(
            step_id="pair_ready",
            menu_options={"pair_start": "Pair"},
        )

    async def async_step_pair_start(self, user_input: dict[str, Any] | None = None):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        await self._async_start_pairing_task()
        return await self.async_step_pairing_active()

    async def async_step_pairing_active(
        self, user_input: dict[str, Any] | None = None
    ):
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        if self._pairing_timed_out():
            await self._async_stop_pairing_task()
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
            return await self.async_step_pairing_active()

        await self._async_stop_pairing_task()
        if not self._pairing_key_b64:
            return self.async_abort(reason="pairing_context_missing")

        data = dict(self._pending_data)
        data[CONF_SENSOR_KEY_B64] = self._pairing_key_b64
        data[CONF_START_SEQUENCE] = self._pairing_sequence_base + 1
        title = self._pending_title

        self._pending_data = None
        self._reset_pairing_state()
        return self.async_create_entry(title=title, data=data)

    async def async_step_pair_cancel(self, user_input: dict[str, Any] | None = None):
        await self._async_stop_pairing_task()
        self._reset_pairing_state()
        if self._pending_data is None:
            return self.async_abort(reason="pairing_context_missing")
        return await self.async_step_pair_ready()

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ):
        errors: dict[str, str] = {}

        entry = self._get_reconfigure_entry()
        if entry is None:
            return self.async_abort(reason="reconfigure_entry_not_found")
        if entry.unique_id:
            await self.async_set_unique_id(entry.unique_id)
            self._abort_if_unique_id_mismatch()

        defaults = {
            CONF_NAME: entry.title,
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
        }

        if user_input is not None:
            title = str(user_input[CONF_NAME])
            options = dict(entry.options)
            options.update(
                {
                    CONF_TEMPERATURE_UNIT: user_input[CONF_TEMPERATURE_UNIT],
                    CONF_UPDATE_INTERVAL_SEC: user_input[CONF_UPDATE_INTERVAL_SEC],
                    CONF_TEMPERATURE_ENTITY: user_input.get(CONF_TEMPERATURE_ENTITY),
                }
            )

            self.hass.config_entries.async_update_entry(
                entry,
                title=title,
                options=options,
            )
            if hasattr(self, "async_update_reload_and_abort"):
                return self.async_update_reload_and_abort(entry, data_updates={})
            await self.hass.config_entries.async_reload(entry.entry_id)
            return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_reconfigure_schema(defaults),
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

        defaults = {
            CONF_NAME: self.config_entry.title,
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
            cleaned = dict(user_input)
            title = cleaned.pop(CONF_NAME)
            if title != self.config_entry.title:
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    title=title,
                )
            return self.async_create_entry(title="", data=cleaned)

        return self.async_show_form(
            step_id="init",
            data_schema=_reconfigure_schema(defaults),
            errors=errors,
        )
