# Network Interface Rotator

Randomizes a network interface's MAC address so public networks (cafés, airports, hotels) can't link your visits by your device's hardware address. It works on macOS and Linux.

The tool always saves the address in use before its first change, so you can return to it with one command.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # optional: set NETWORK_INTERFACE, ROTATE_INTERVAL, POLL_SECONDS
```

## Usage

```bash
python main.py status                 # current / hardware / saved MAC and network (no sudo)
sudo python main.py rotate            # apply a new random MAC now
sudo python main.py rotate --mac 02:11:22:33:44:55
sudo python main.py restore           # back to the MAC saved before the first rotation
sudo python main.py restore --hardware
sudo python main.py watch             # rotate whenever you disconnect or change network
sudo python main.py watch --interval 1800 --restore-on-exit
```

Pass `-i <interface>` before the command to target an interface other than the default (`en0` on macOS, `wlan0` on Linux).

### How `watch` behaves

- **On disconnect** it rotates the address, so the next network you join sees an address it hasn't seen before. This is the main privacy protection.
- **On a network change** it also rotates, as a fallback for when a fast roam happens between two checks.
- **With `--interval N`** it also rotates every N seconds while you stay connected. Each rotation briefly drops the connection, and captive portals may ask you to log in again.
- **After each rotation** it ignores network changes for `--cooldown` seconds (default 30). Without this, the reconnect that a rotation causes would trigger another rotation.

Networks are identified by their default gateway's IP and MAC address. macOS 15+ hides the Wi-Fi network name (SSID) from apps that lack location permission, so the name can't be used.

Generated addresses are random, unicast and *locally administered*. They never match a real vendor prefix, and drivers accept them.

## Platform notes

- **macOS:** For Wi-Fi, the tool turns the radio off and on, then applies the address before the interface rejoins a network. macOS already offers *Private Wi-Fi Address* (Fixed or Rotating) per network in System Settings. This tool adds manual control, rotation on a timer or on disconnect, and support for Ethernet adapters.
- **Linux:** The tool uses `ip link`. NetworkManager may reset the address on reconnect. To prevent that, use this tool with NetworkManager's own `wifi.cloned-mac-address=random`, or set the connection's cloned address to `preserve`.
- Some drivers don't allow the address to change. In that case `rotate` reports an error and leaves the interface untouched.

## Disclaimer

Changing your MAC address is legal in most places and is a standard privacy measure. Use this tool only on devices you own, and follow the terms of the networks you use.
