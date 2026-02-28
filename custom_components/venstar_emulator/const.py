"""Constants for Venstar WiFi Sensor Emulator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from .coordinator import VenstarCoordinator
    from .runtime import VenstarRuntime

DOMAIN: Final = "venstar_emulator"

CONF_SOURCE_INTERFACE: Final = "source_interface"
CONF_SOURCE_IP: Final = "source_ip"
CONF_UNIT_ID: Final = "unit_id"
CONF_SENSOR_TYPE: Final = "sensor_type"
CONF_SENSOR_NAME: Final = "sensor_name"
CONF_SENSOR_MAC: Final = "sensor_mac"
CONF_TEMPERATURE_ENTITY: Final = "temperature_entity"
CONF_TEMPERATURE_UNIT: Final = "temperature_unit"
CONF_UPDATE_INTERVAL_SEC: Final = "update_interval_sec"
CONF_SENSOR_KEY_B64: Final = "sensor_key_b64"
CONF_START_SEQUENCE: Final = "start_sequence"

DEFAULT_NAME: Final = "Venstar Emulated Sensor"
DEFAULT_SOURCE_INTERFACE: Final = ""
DEFAULT_SOURCE_IP: Final = ""
DEFAULT_SENSOR_NAME: Final = "HASensor"
DEFAULT_SENSOR_TYPE: Final = "remote"
DEFAULT_TEMPERATURE_UNIT: Final = "fahrenheit"
DEFAULT_UNIT_ID: Final = 1
DEFAULT_UPDATE_INTERVAL_SEC: Final = 30
DEFAULT_PAIRING_WINDOW_SEC: Final = 300
DEFAULT_BATTERY_PERCENT: Final = 100
DEFAULT_START_SEQUENCE: Final = 3

STORAGE_VERSION: Final = 1

ATTR_KEY_B64: Final = "key_b64"
ATTR_SEQUENCE: Final = "sequence"
ATTR_LAST_TEMP_C: Final = "last_temp_c"
ATTR_PAIRING_UNTIL: Final = "pairing_until"
ATTR_BATTERY: Final = "battery"

PLATFORMS: Final = ["sensor"]

SENSOR_TYPE_NAME_TO_VALUE: Final = {
    "outdoor": 1,
    "return": 2,
    "remote": 3,
    "supply": 4,
}
SENSOR_TYPE_VALUE_TO_NAME: Final = {v: k for k, v in SENSOR_TYPE_NAME_TO_VALUE.items()}


@dataclass
class IntegrationData:
    """Runtime objects associated with a config entry."""

    runtime: VenstarRuntime
    coordinator: VenstarCoordinator
