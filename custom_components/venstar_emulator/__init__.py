"""Venstar WiFi Sensor Emulator integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.storage import Store

from .const import DOMAIN, IntegrationData, PLATFORMS, STORAGE_VERSION
from .coordinator import VenstarCoordinator
from .runtime import VenstarRuntime

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up from YAML (not used)."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the integration from a config entry."""
    runtime = VenstarRuntime(hass, entry)

    try:
        await runtime.async_initialize()
    except Exception as err:  # noqa: BLE001
        raise ConfigEntryNotReady(f"Failed to initialize runtime: {err}") from err
    coordinator = VenstarCoordinator(hass, runtime)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = IntegrationData(
        runtime=runtime,
        coordinator=coordinator,
    )

    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        await runtime.async_start_periodic_updates()
    except Exception:
        await runtime.async_shutdown()
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    runtime: VenstarRuntime | None = None
    entry_data = entry.runtime_data
    if isinstance(entry_data, IntegrationData):
        runtime = entry_data.runtime

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok and runtime is not None:
        await runtime.async_shutdown()
    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove persisted storage for a deleted config entry."""
    await Store[dict](hass, STORAGE_VERSION, f"{DOMAIN}_{entry.entry_id}").async_remove()
