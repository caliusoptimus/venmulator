"""Sensor entities for WiFi sensor emulator for Venstar."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import IntegrationData
from .entity import VenstarBaseEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    if not isinstance(data, IntegrationData):
        raise RuntimeError("Runtime data missing on config entry")
    async_add_entities([VenstarTemperatureSensor(data, entry)])


class VenstarTemperatureSensor(VenstarBaseEntity, SensorEntity):
    """Current emulated sensor temperature."""

    _unrecorded_attributes = frozenset(
        {
            "sequence",
            "last_packet",
            "last_send",
            "last_send_status",
            "packets_generated_since_start",
            "udp_packets_sent_since_start",
        }
    )
    _attr_name = None
    _attr_translation_key = "emulated_temperature"
    _attr_unique_id = None
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, data: IntegrationData, entry: ConfigEntry) -> None:
        super().__init__(data, entry)
        self._attr_unique_id = f"{entry.entry_id}_temperature"

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data.get(
            "broadcast_enabled", True
        )

    @property
    def native_value(self) -> float | None:
        if not self.coordinator.data.get("broadcast_enabled", True):
            return None

        source = self.coordinator.data.get("source_temperature_c")
        if source is not None:
            return round(float(source), 2)

        last = self.coordinator.data.get("last_temperature_c")
        if last is not None:
            return round(float(last), 2)

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "temperature_entity": self.coordinator.data.get("temperature_entity"),
            "temperature_source_status": self.coordinator.data.get(
                "temperature_source_status"
            ),
            "temperature_unit_mode": self.coordinator.data.get("temperature_unit_mode"),
            "broadcast_enabled": self.coordinator.data.get("broadcast_enabled"),
            "temperature_random_fallback_active": self.coordinator.data.get(
                "temperature_random_fallback_active"
            ),
            "sensor_name": self.coordinator.data.get("sensor_name"),
            "sensor_mac": self.coordinator.data.get("sensor_mac"),
            "sensor_type": self.coordinator.data.get("sensor_type"),
            "unit_id": self.coordinator.data.get("unit_id"),
            "battery_percent": self.coordinator.data.get("battery_percent"),
            "sequence": self.coordinator.data.get("sequence"),
            "pairing_active": self.coordinator.data.get("pairing_active"),
            "pairing_until": self.coordinator.data.get("pairing_until"),
            "source_interface": self.coordinator.data.get("source_interface"),
            "source_ip": self.coordinator.data.get("source_ip"),
            "source_ip_cidr": self.coordinator.data.get("source_ip_cidr"),
            "source_mode": self.coordinator.data.get("source_mode"),
            "target_mode": self.coordinator.data.get("target_mode"),
            "unicast_target": self.coordinator.data.get("unicast_target"),
            "directed_broadcast": self.coordinator.data.get("directed_broadcast"),
            "multicast_target": self.coordinator.data.get("multicast_target"),
            "udp_port": self.coordinator.data.get("udp_port"),
            "targets": self.coordinator.data.get("targets"),
            "last_packet": self.coordinator.data.get("last_packet"),
            "last_send": self.coordinator.data.get("last_send"),
            "last_send_status": self.coordinator.data.get("last_send_status"),
            "packets_generated_since_start": self.coordinator.data.get(
                "packets_generated_since_start"
            ),
            "udp_packets_sent_since_start": self.coordinator.data.get(
                "udp_packets_sent_since_start"
            ),
        }
