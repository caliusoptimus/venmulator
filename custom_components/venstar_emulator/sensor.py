"""Sensor entities for WiFi sensor emulator for Venstar."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
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
    def native_value(self) -> float | None:
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
            "temperature_unit_mode": self.coordinator.data.get("temperature_unit_mode"),
            "sensor_type": self.coordinator.data.get("sensor_type"),
            "unit_id": self.coordinator.data.get("unit_id"),
        }
