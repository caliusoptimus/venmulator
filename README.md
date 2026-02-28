# Venstar WiFi Sensor Emulator - User Guide

This integration emulates a Venstar `ACC-TSENWIFI` wireless sensor so a compatible Venstar thermostat can pair with it and receive temperature updates from Home Assistant.

## Tested Hardware

- Thermostat tested: `Venstar T8850` (ColorTouch family)

## What It Does

- Creates one emulated wireless sensor per integration entry
- Broadcasts sensor packets on your local network
- Lets you drive sensor temperature from a Home Assistant entity (optional)
- Keeps sensor identity/state persistent across Home Assistant restarts

## Basic Setup

1. Install the integration with HACS.
2. Add the integration in Home Assistant.
3. Fill in setup fields (name, unit ID, type, network source, update interval).
4. Start pairing from Home Assistant.
5. Put thermostat in wireless sensor pairing mode and complete pairing.

## Notes on Temperature Units

- Venstar wireless sensor protocol is native Celsius.
- Fahrenheit values are converted before transmission, so rounding will occur.

## Behavior Observed During Testing

- Single sensor on a thermostat worked reliably.
- Multiple thermostats on the same network, with one emulated sensor per thermostat, worked without issues.
- Strange behavior was observed when using more than one emulated sensor on a single thermostat (tested on T8850).

## Recommendation

- For best stability, use one emulated sensor per thermostat.
- If you need more than one sensor on the same thermostat, validate behavior on your exact thermostat model/firmware.

## Use Case Example

- Combine multiple Zigbee room temperature sensors in Home Assistant (for example, average living room + hallway + bedroom).
- Feed that computed average into this integration as the thermostat sensor source.
- Use an error+gain control factor in Home Assistant to adjust the thermostat setpoint through the official Venstar integration.
- Result: tighter whole-space temperature control than relying only on the thermostat's local sensor.






## Requirements

1. Venstar thermostat that supports wireless sensors (`T8850` / ColorTouch family).
2. Thermostat and Home Assistant on the same reachable Layer-2/LAN path.

## Install Without HACS

1. Copy the custom_components folder to the Home Assistant directory containing "configuration.yaml".

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
   1. Name displayed on thermostat.
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


## Reconfigure (After Creation)

You can change:

1. Entry name
2. Temperature unit
3. Update interval
4. Temperature source entity

Identity fields remain fixed after setup (MAC, unit ID, sensor type, source interface/source IP, sensor key).

No charge, no refunds. Will try to fix it if it breaks.


