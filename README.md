# Venmulator (Home Assistant Venstar Sensor Emulator)

This integration emulates a Venstar `ACC-TSENWIFI` wireless sensor so a Venstar ColorTouch thermostat (including `T8850`) can pair with it and receive periodic temperature updates.

## What It Does

1. Creates one emulated wireless sensor per integration entry.
2. Runs a pairing flow in Home Assistant.
3. Sends Venstar sensor packets on UDP/5001 to:
   1. `224.0.0.1`
   2. The directed broadcast of the selected interface subnet
4. Sends timed update packets after pairing is confirmed.
5. Persists sensor key and sequence state across HA restarts.

## Requirements

1. Home Assistant with HACS.
2. Venstar thermostat that supports wireless sensors (`T8850` / ColorTouch family).
3. Thermostat and Home Assistant on the same reachable Layer-2/LAN path.
4. Thermostat firmware compatible with wireless sensor support.

## Install With HACS (Custom Repository)

1. Open HACS.
2. Go to `Integrations`.
3. Open the menu and select `Custom repositories`.
4. Add repository URL:
   1. `https://github.com/caliusoptimus/venmulator`
   2. Category: `Integration`
5. Install `Venstar WiFi Sensor Emulator`.
6. Restart Home Assistant.

## Add and Pair an Emulated Sensor

1. In Home Assistant:
   1. Go to `Settings > Devices & Services`.
   2. Add integration: `Venstar WiFi Sensor Emulator`.
   3. Fill out setup fields.
2. On `Ready to pair?`, press `Pair` in Home Assistant.
3. On thermostat (`T8850`/ColorTouch), follow wireless sensor pairing menu path:
   1. `Menu`
   2. `Settings`
   3. `Installation Settings`
   4. `Sensor Settings`
   5. `Wireless Sensors`
   6. `Add New Sensor`
4. After thermostat reports the sensor was added, click `Pairing Successful` in Home Assistant.
5. The integration starts timed updates automatically.

## Setup Fields (Plain Language)

1. `Entry Name`
   1. Friendly name in Home Assistant.
2. `Source Interface`
   1. Network interface used for packet transmission.
3. `Source IP (Optional Fallback, CIDR)`
   1. Optional fallback source IP and prefix (example: `192.168.1.100/24`).
4. `Sensor Name`
   1. Name carried inside Venstar packets during pairing/updates.
5. `Unit ID`
   1. Sensor unit number (must be `1` to `20`).
6. `Sensor Type`
   1. `Outdoor`, `Return`, `Remote`, or `Supply`.
7. `Temperature Unit`
   1. `Fahrenheit` or `Celsius` for input entity interpretation.
   2. Venstar sensor protocol is native Celsius (0.5C index steps); Fahrenheit values are converted and may be rounded.
8. `Update Interval (Seconds)`
   1. How often update packets are sent after pairing (`2` to `60` seconds).
9. `Temperature Source Entity` (optional)
   1. If set, this entity drives transmitted temperature.
   2. If empty, emulator sends random values.
10. Pairing timeout
   1. Fixed at `5` minutes.

## Reconfigure (After Creation)

You can change:

1. Entry name
2. Temperature unit
3. Update interval
4. Temperature source entity

Identity fields remain fixed after setup (MAC, unit ID, sensor type, source interface/source IP, sensor key).

## Data and Persistence

1. Key protocol state is persisted:
   1. Sensor key (`key_b64`)
   2. Sequence counter

## Troubleshooting

1. `invalid_source_ip`
   1. Use CIDR format (example: `192.168.1.100/24`).
2. Pairing times out
   1. Start thermostat pairing first, then retry.
3. No interface dropdown values
   1. Ensure HA can see host adapters (container/network mode can affect this).
4. Thermostat not seeing packets
   1. Verify HA and thermostat are on reachable network segments.
   2. Verify host/firewall allows outbound UDP/5001 and broadcast/multicast.

## Manual References

1. Venstar ColorTouch T8850 Owner's Manual (PDF):  
   `https://files.venstar.com/accessories/thermostats/colortouch/T8850_owners_manual.pdf`
2. Venstar `ACC-TSENWIFI` Installation Instructions (PDF):  
   `https://files.venstar.com/accessories/ACC-TSENWIFI_Manual_Rev1.pdf`
3. Venstar ColorTouch product/docs page:  
   `https://venstar.com/thermostats/colortouch/`
