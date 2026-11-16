\# NX-HLB Hardware (ESP32-S3 Firmware)



This repository contains the official hardware firmware for the \*\*NX-HLB (NX-Hardware LAN Bridge)\*\* project. It is designed to run on the ESP32-S3 microcontroller to provide a secure, authenticated UDP bridge between a Nintendo Switch and a PC client over a local area network.



\## Features

\- Secure UDP data bridging between PC and Nintendo Switch.

\- HMAC-SHA256 signature verification for all network communications.

\- Anti-replay protection using a rolling nonce cache.

\- Base64 payload encoding to support special characters and spaces in WiFi credentials.

\- Serial console interface for local configuration and debugging.



\## Flashing Guide

1\. Download the latest `.bin` firmware file from the \[Releases](https://github.com/mmhbpvp/NX-HLB-Hardware/releases) page.

2\. Flash the firmware to your ESP32-S3 board using ESP Web Tools, Espressif Flash Download Tool, or Arduino IDE.

3\. Open your preferred serial monitor (e.g., Arduino IDE Serial Monitor) at `115200` baud rate.



\## Serial Console Commands

Once connected, you can use the following commands via the serial port:

\- `/help` : Display the command list.

\- `/status` : Check current WiFi and network status.

\- `/getkey` : Display the current key fingerprint (SHA256).

\- `/setkey <32-64\_char\_secret>` : Set a new security key. (Only allowed via serial for security reasons).

\- `/set lan link <ssid> <password>` : Configure the WiFi credentials directly.

\- `/reboot` : Restart the ESP32 device.



\## Security Architecture

\- The PC client and the ESP32 firmware establish a secure channel using a pre-shared secret key.

\- The `/setkey` command is strictly limited to local serial input. This prevents remote attackers from hijacking the device by overwriting the key over the network.

\- Initial pairing uses a fallback default key. Users are strongly advised to change this key via `/setkey` after the first successful connection.



\## Related Repositories

\- Desktop Client (PC): \[NX-HLB](https://github.com/mmhbpvp/NX-HLB)



\## License

This project is licensed under the MIT License. See the LICENSE file for details.

