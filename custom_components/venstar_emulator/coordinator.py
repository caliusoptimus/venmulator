"""Coordinator for WiFi sensor emulator for Venstar state."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    CONF_UPDATE_INTERVAL_SEC,
    DEFAULT_UPDATE_INTERVAL_SEC,
    DOMAIN,
    MAX_UPDATE_INTERVAL_SEC,
    MIN_UPDATE_INTERVAL_SEC,
)
from .runtime import VenstarRuntime

_LOGGER = logging.getLogger(__name__)


class VenstarCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Poll runtime snapshot for UI state updates."""

    def __init__(
        self,
        hass: HomeAssistant,
        runtime: VenstarRuntime,
    ) -> None:
        raw_interval = runtime.entry.options.get(
            CONF_UPDATE_INTERVAL_SEC,
            runtime.entry.data.get(CONF_UPDATE_INTERVAL_SEC, DEFAULT_UPDATE_INTERVAL_SEC),
        )
        try:
            interval = min(
                MAX_UPDATE_INTERVAL_SEC,
                max(MIN_UPDATE_INTERVAL_SEC, int(raw_interval)),
            )
        except (TypeError, ValueError):
            interval = DEFAULT_UPDATE_INTERVAL_SEC

        _LOGGER.debug(
            "Creating coordinator for entry %s with update interval %ss",
            runtime.entry.entry_id,
            interval,
        )

        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN}_{runtime.entry.entry_id}",
            update_interval=timedelta(seconds=interval),
        )

        self.runtime = runtime

    async def _async_update_data(self) -> dict[str, Any]:
        data = await self.runtime.async_snapshot()
        _LOGGER.debug(
            "Coordinator snapshot for entry %s: sequence=%s, "
            "source_status=%s, broadcast_enabled=%s, targets=%s",
            self.runtime.entry.entry_id,
            data.get("sequence"),
            data.get("temperature_source_status"),
            data.get("broadcast_enabled"),
            data.get("targets"),
        )
        return data
