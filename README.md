# ESPNoted

**ESPNoted** is a compact ESP8266-based OLED network console designed for passive Wi-Fi scanning, signal tracking, channel analysis, and defensive wireless monitoring.

It is built for small ESP8266 boards with a built-in 0.96" SSD1306 OLED display, such as the IdeaSpark ESP8266 OLED board. The interface is controlled using the BOOT button, making it usable as a tiny portable network tool.

## Features

* Passive Wi-Fi network scanning
* Access point browser
* AP details including SSID, BSSID, RSSI, channel, and security type
* Signal tracker
* Channel analyzer
* Open network finder
* Hidden network finder
* Rogue AP watch
* Packet monitor
* Deauth/disassociation monitor
* Probe request monitor
* Evidence log screen
* OLED display test
* Device information screen
* Raw battery/ADC reading screen
* One-button navigation

## Controls

* Short press: move down / next item / next channel
* Double press: enter / select / rescan / toggle
* Long press: back / exit

## Hardware

Designed for:

* ESP8266 board
* Built-in 0.96" SSD1306 OLED display
* BOOT/FLASH button on GPIO0

Default OLED pins:

* SDA: GPIO12 / D6
* SCL: GPIO14 / D5

## Purpose

ESPNoted is made for learning, homelab use, wireless diagnostics, and defensive monitoring on your own networks and devices.

It does not include attack transmission modules. It is focused on scanning, detection, and visibility.

## Disclaimer

Use this tool only on networks and devices you own or have permission to test. ESPNoted is intended for education, diagnostics, and defensive monitoring.
