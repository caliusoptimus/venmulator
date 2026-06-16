# WiFi Sensor Emulator for Venstar - User Guide

This integration emulates an `ACC-TSENWIFI` wireless sensor so compatible Venstar thermostats can pair with it and receive temperature updates from Home Assistant.

## Related Projects

- Receiver counterpart (`venceiver`): https://github.com/caliusoptimus/venceiver

## Tested Hardware

- Thermostat tested: `Venstar T8850` (ColorTouch family)

## What It Does

- Creates one emulated wireless sensor per integration entry
- Sends sensor packets by local broadcast/multicast or direct unicast
- Lets you drive sensor temperature from a Home Assistant entity (optional)
- Keeps sensor identity/state persistent across Home Assistant restarts

## Basic Setup

1. Install the integration with HACS.
2. Add the integration in Home Assistant.
3. Fill in setup fields (name, unit ID, type, network source, update interval).
4. Start pairing from Home Assistant so the emulated sensor begins sending pairing packets.
5. Add the wireless sensor from the thermostat menu and complete pairing.

## Notes on Temperature Units

- Venstar wireless sensor protocol is native Celsius.
- Fahrenheit values are converted before transmission, so rounding will occur.

## Behavior Observed During Testing

- Single sensor on a thermostat worked reliably.
- Multiple thermostats on the same network, with one emulated sensor per thermostat, worked without issues.
- Strange behavior was observed when using more than one emulated sensor on a single thermostat (tested on T8850).
- Sending updates quickly doesn't make the thermostat screen update any faster. A 15 second update interval is sensible.

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
2. For auto broadcast mode: thermostat and Home Assistant on the same reachable Layer-2/LAN path.
3. For unicast mode: thermostat IP reachable from the Home Assistant host/container.
4. Docker users: host networking is recommended, especially for broadcast/multicast discovery and predictable UDP routing.

## Install Without HACS

1. Copy the custom_components folder to the Home Assistant directory containing "configuration.yaml".

## Install With HACS (Custom Repository)

1. Open HACS.
2. Go to `Integrations`.
3. Open the menu and select `Custom repositories`.
4. Add repository URL:
   1. `https://github.com/caliusoptimus/venmulator`
   2. Category: `Integration`
5. Install `WiFi Sensor Emulator for Venstar`.
6. Restart Home Assistant.

## Add and Pair an Emulated Sensor

1. In Home Assistant:
   1. Go to `Settings > Devices & Services`.
   2. Add integration: `WiFi Sensor Emulator for Venstar`.
   3. Fill out setup fields.
2. On `Ready to pair?`, press `Pair` in Home Assistant. This starts sending pairing packets.
3. After Home Assistant shows `Pairing in progress`, go to the thermostat (`T8850`/ColorTouch) and follow the wireless sensor pairing menu path:
   1. `Menu`
   2. `Settings`
   3. `Installation Settings`
   4. `Sensor Settings`
   5. `Wireless Sensors`
   6. `Add New Sensor`
4. After the thermostat reports the sensor was added, click `Pairing Successful` in Home Assistant.
5. The integration starts timed updates automatically.

## Setup Fields (Plain Language)

1. `Entry Name`
   1. Friendly name in Home Assistant.
2. `Network Interface`
   1. Network interface used for packet transmission.
   2. Select the interface that can reach the thermostat.
3. `Sensor Name`
   1. Name displayed on thermostat.
4. `Unit ID`
   1. Sensor unit number (must be `1` to `20`).
5. `Sensor Type`
   1. `Outdoor`, `Return`, `Remote`, or `Supply`.
6. `Temperature Unit`
   1. `Fahrenheit` or `Celsius` for input entity interpretation.
   2. Venstar sensor protocol is native Celsius (0.5C index steps); Fahrenheit values are converted and may be rounded.
7. `Update Interval (Seconds)`
   1. How often update packets are sent after pairing (`15` to `300` seconds).
   2. Note: Sending updates quickly does not make the thermostat screen update at the same rate.
8. `Temperature Source Entity` (optional)
   1. If set, this entity drives transmitted temperature.
   2. If empty, emulator sends random values.
9. Advanced: `Mode (Advanced)`
   1. `Broadcast`: sends to `224.0.0.1` and the local directed broadcast address when available.
   2. `Unicast`: sends only to the configured thermostat IP on UDP port `5001`.
10. Advanced: `Thermostat IP for Unicast (Advanced)`
   1. Only needed when `Mode (Advanced)` is `Unicast`.
   2. Unicast can work across routed subnets if the Home Assistant host/container can route to this IP.
   3. Leave empty for `Broadcast` mode.
   4. Broadcast mode is for thermostats using DHCP or a static IP, and the thermostat must be on the same subnet as your selected interface.


## Reconfigure (After Creation)

You can change:

1. Entry name
2. Network interface
3. Temperature unit
4. Update interval
5. Temperature source entity
6. Advanced mode and thermostat IP
7. Pair again

Identity fields remain fixed after setup (MAC, unit ID, sensor type, sensor key).
If `Pair again?` is selected, the integration saves the reconfigure changes, resets the packet sequence counter, and opens the pairing flow for the existing emulated sensor. Press `Pair` in Home Assistant first, then add the wireless sensor from the thermostat menu.


No charge, no refunds. Will try to fix it if it breaks.
