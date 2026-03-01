"""Coordinator for WiFi sensor emulator for Venstar state."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import CONF_UPDATE_INTERVAL_SEC, DEFAULT_UPDATE_INTERVAL_SEC, DOMAIN
from .runtime import VenstarRuntime


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
            interval = min(60, max(2, int(raw_interval)))
        except (TypeError, ValueError):
            interval = DEFAULT_UPDATE_INTERVAL_SEC

        super().__init__(
            hass,
            logger=logging.getLogger(__name__),
            name=f"{DOMAIN}_{runtime.entry.entry_id}",
            update_interval=timedelta(seconds=interval),
        )

        self.runtime = runtime

    async def _async_update_data(self) -> dict[str, Any]:
        return await self.runtime.async_snapshot()
