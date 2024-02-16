# Network Interface Rotator

Protects one person's session on an untrusted public network with an encrypted WireGuard tunnel, a kill switch, a randomized hardware address and host name, and detection of hostile-network activity. When the session ends, it puts the machine back exactly as it was; it runs on macOS and Linux.

## What it protects against, and what it doesn't

| An attacker on the network can | With a session |
|---|---|
| Read unencrypted traffic, see DNS lookups | No. All traffic and DNS go through a WireGuard tunnel. |
| Redirect traffic (ARP spoofing, rogue DHCP or DNS, fake access point) | No. Redirected packets are still encrypted and authenticated, so the attacker gains nothing. The tool also detects and reports it. |
| Recognize the device by hardware address, hostname or open services | No. The address and host name are random for the session, and inbound connections are blocked. |
| Catch traffic that leaks when the tunnel drops | No. A firewall kill switch blocks everything outside the tunnel. |
| See that a device is present, how much data it sends, and that it uses a VPN | **Yes. This cannot be hidden.** |
| Fingerprint the Wi-Fi radio hardware | **Yes. Out of scope.** |

The network can still see that your device is there, roughly how much data it sends, and that you use a VPN. The tool does not hide you from the websites you use. If you log in to a site, that site still knows who you are.

## Choosing a VPN

You choose the VPN provider. The tool does not depend on any provider. It accepts any standard WireGuard config file, from a commercial provider or a self-hosted server, and checks it against the requirements in [Setup](#setup).

Look for these things:

- An independent no-logs audit.
- Plain WireGuard config files for `wg-quick`, not only a vendor app.
- Endpoints given as IP addresses, not hostnames.
- An in-tunnel DNS resolver.
- IPv6 inside the tunnel.
- A choice of ports, in case the default port is blocked.

Two providers that meet these. **As of 2026-11-14, from third-party reviews; confirm on the provider's site.**

| | Mullvad | Proton VPN Free |
|---|---|---|
| Cost | Flat €5/month, no long-term plan needed | Free |
| Sign-up | No email or personal details; an account number only | Email address required |
| WireGuard config files | Yes, for use with `wg-quick` | Yes, downloaded from the account page |
| Protocol | WireGuard only | WireGuard among others |
| Audits | Repeated independent audits, most recently of its WireGuard implementation in early 2026 | Independently audited, open-source apps |
| Limits | 5 devices | Few countries, one device, slower at busy times |

Any provider that meets the requirements works. The table is a starting point, not a recommendation.

A self-hosted WireGuard server also works. It costs only the server. Its address is tied to its owner, so it keeps the local network from seeing your traffic, but it does not hide who you are from the sites you visit.

Your VPN provider takes the place of the public network as the party that can see where your traffic goes. That is the right trade against attackers on the local network. It is also the reason to pick an audited no-logs provider rather than the cheapest one.

## Setup

### Install

Install the tool's Python dependencies:

```bash
pip install -r requirements.txt
cp .env.example .env    # then fill in the WireGuard settings below
```

Install WireGuard's command-line tools:

```bash
# macOS
brew install wireguard-tools

# Linux (Debian or Ubuntu; use your distribution's package otherwise)
sudo apt install wireguard-tools
```

The tool runs with `sudo python main.py ...`. If `sudo python` cannot find the dependencies, use the Python from your virtual environment instead, for example `sudo venv/bin/python main.py ...`.

### One-time key and config steps

1. Create the key on this machine, so the private key never leaves it:

   ```bash
   wg genkey | tee nir.key | wg pubkey
   ```

   The command prints the **public** key.

2. With your provider, register that public key. Download the config for one nearby server, and a second config for a server on a different port to use as a fallback. Some providers give you ready-made configs with their own key. For those, skip this step and step 3.

3. Put the private key from `nir.key` into both configs, then delete `nir.key`.

4. Save the configs as `nir.conf` and `nir-fallback.conf`, owned by root with mode `0600`. Put them in `/etc/wireguard/` on Linux, or in `/opt/homebrew/etc/wireguard/` on Apple silicon Macs:

   ```bash
   sudo mv nir.conf nir-fallback.conf /etc/wireguard/
   sudo chown root:root /etc/wireguard/nir.conf /etc/wireguard/nir-fallback.conf
   sudo chmod 0600 /etc/wireguard/nir.conf /etc/wireguard/nir-fallback.conf
   ```

5. Set `WG_CONFIG` and `WG_CONFIG_FALLBACK` in `.env` to those paths. The private key never goes in `.env` or in the repository.

### Config requirements

The tool checks each config before it starts a session. It refuses to start, and lists every problem, if any of these fail:

- `AllowedIPs` includes both `0.0.0.0/0` and `::/0`. A narrower route lets some traffic bypass the tunnel.
- `DNS` is set, and is not an address on the local network.
- `Endpoint` is an IP address, not a hostname.
- `PersistentKeepalive` is set. Use `25`.
- There are no `PreUp`, `PostUp`, `PreDown` or `PostDown` lines.
- There is no `SaveConfig` line.
- `Table` is absent or set to `auto`.
- The file has mode `0600` and is owned by root or by you.

A sample config. Replace every placeholder with the values from your provider:

```ini
[Interface]
PrivateKey = <private key from nir.key>
Address    = <IPv4 address from provider>/32, <IPv6 address from provider>/128
DNS        = <in-tunnel resolver from provider>

[Peer]
PublicKey           = <server public key from provider>
AllowedIPs          = 0.0.0.0/0, ::/0
Endpoint            = 192.0.2.10:51820
PersistentKeepalive = 25
```

If the tunnel does not connect within 15 seconds, the tool tries the fallback config once. Some networks block UDP port 51820. Use a server and port that your provider lists as an alternative. A network that blocks all UDP traffic cannot be used with this tool.

### Settings in `.env`

| Setting | What it does |
|---|---|
| `WG_CONFIG` | Path to your WireGuard config. Required for `session start`. |
| `WG_CONFIG_FALLBACK` | Optional second config, tried once if the first does not connect within 15 seconds. |
| `STRICT` | `1` (default) turns strict mode on. `0` makes it warn only. See [Strict mode](#strict-mode). |
| `STRICT_ON` | Comma-separated findings that trigger strict mode. Empty means the default set. |
| `NETWORK_INTERFACE` | Interface to use. Defaults to `en0` on macOS and `wlan0` on Linux. |

## Using a session

Start a session for two hours:

```bash
sudo python main.py session start --duration 2h
```

`--duration` is required. Use `90s`, `15m` or `2h`. The session ends when the time is up, on Ctrl-C, or on `session stop`.

Options:

| Option | What it does |
|---|---|
| `--portal` | Opens a short window that is **not protected**, so you can log in to a captive portal. |
| `--portal-seconds N` | Longest the portal window may stay open. Default 120. Press Enter to close it early. |
| `--strict` / `--no-strict` | Turn strict mode on or off for this session. |
| `--keep-hostname` | Do not randomize the host name. |
| `--keep-firewall` | Do not change the inbound firewall settings. On Linux this has no effect, because the kill switch already blocks inbound connections. |
| `--poll N` | Seconds between network and tunnel checks. Default 3. |

With `--portal`, web traffic (TCP 80 and 443) and DNS on the current network are **not protected** while the window is open. Log in to the portal page and nothing else. The protected rules come back when the window closes. If the tunnel is not up at that point, the session stops.

### What happens when you start

1. The tool checks everything first and changes nothing: it runs as root, `wg-quick` and `wg` are installed, both configs are valid, no other VPN holds the default route, and no changes from an earlier session are left over.
2. The kill switch goes up first. Only DHCP and the VPN server's address can leave the machine.
3. Inbound connections are blocked, and the host name is randomized (unless you opted out).
4. The MAC address changes. This drops the Wi-Fi connection, so the network only ever sees the new address. The tool waits for the rejoin. The portal window opens here, if you asked for it.
5. The tunnel comes up, and the kill switch is reloaded to allow traffic through the tunnel only. The tool runs a leak audit. If the audit fails, every change is undone.
6. The session holds for the duration, checking the network and the tunnel every few seconds.
7. When the session ends, every change is undone, newest first. The kill switch comes down last.

### Other session commands

```bash
sudo python main.py session status
sudo python main.py session stop
sudo python main.py audit
```

- `session status` shows the time left, the tunnel state, the kill switch state and any findings so far.
- `session stop` asks the running session to undo everything, and waits for it to finish.
- `audit` runs read-only leak checks and prints a pass or fail table. It exits with status 1 if any check fails. It checks the MAC address, host name, inbound firewall, kill switch, tunnel handshake, default route, DNS and IPv6.

### Strict mode

Strict mode is on by default. Detection looks for these findings:

| Finding | Meaning | Default |
|---|---|---|
| `arp_spoof_suspected` | The gateway's hardware address changed. | Strict |
| `arp_conflict` | Two devices answer for the gateway address. | Strict |
| `network_reconfigured` | The gateway or DNS servers changed during the session. | Strict |
| `possible_evil_twin` | The access point changed while the network name stayed the same. Linux only. | Warn only |

A warning appears on the first sighting. A finding in the strict set must appear on two checks in a row before strict mode acts. This stops one garbled reading from triggering it.

When strict mode acts, the tool stops the tunnel and tightens the kill switch. All traffic is blocked. The session stays in that state until you run `session stop`. This is deliberate: the tool does not reopen a hostile network on a timer. `session status` shows the session as held in silent mode.

To change strict mode:

- For one session, use `--strict` or `--no-strict`.
- For all sessions, set `STRICT=0` in `.env` to warn only.
- To choose which findings trigger it, set `STRICT_ON` in `.env`, for example `STRICT_ON=arp_spoof_suspected,possible_evil_twin`. The list replaces the default set.

The command line overrides `.env`, and `.env` overrides the default.

## Before you stop

Stopping a session restores your real hardware address and host name. The tool prints this notice when it does:

> Restoring your real hardware address and hostname. If you are still connected to the public network, it will see them: leave the network or turn Wi-Fi off first if that matters.

If you are still connected, the network sees your real identity again as soon as the restore runs. Leave the network or turn Wi-Fi off first if that matters.

## If something goes wrong

```bash
sudo python main.py panic
```

`panic` stops any running session, then undoes every recorded change. It works after a crash, a killed process or a reboot. If it reports a failure, run it again.

A new session will not start while changes from an earlier session are still recorded. The error tells you to run `panic` first.

## Everything a session changes

| Change | How it is undone | Opt out |
|---|---|---|
| Hardware (MAC) address of the interface | Set the saved address back | No (core feature) |
| Host name (`ComputerName`, `LocalHostName`, `HostName`; on Linux, the transient host name) | Set the saved names back | `--keep-hostname` |
| macOS application firewall: on, block-all, stealth | Set the three saved values back | `--keep-firewall` |
| The tool's own pf anchor (macOS) or nft table (Linux) | Unload that anchor or delete that table only | No |
| WireGuard tunnel interface | `wg-quick down` | No |

Nothing else is changed. Saved Wi-Fi networks, auto-join settings, the keychain, network service order and other system settings are left alone.

That choice has a cost. Because auto-join is left alone, your device may still broadcast the names of saved networks while it searches for Wi-Fi. The random address stops those broadcasts being tied to your hardware. A rare network name can still hint at who you are. If that matters to you, remove unusual saved networks yourself.

## MAC-only commands

These commands change only the MAC address. They do not use WireGuard or the kill switch.

```bash
python main.py status                        # current, hardware and saved MAC, and network (no sudo)
sudo python main.py rotate                   # apply a new random MAC now
sudo python main.py rotate --mac <mac-address>
sudo python main.py restore                  # back to the MAC saved before the first rotation
sudo python main.py restore --hardware       # back to the burned-in address
sudo python main.py watch                    # rotate on disconnect or network change
sudo python main.py watch --interval 1800 --restore-on-exit
```

Put `-i <interface>` before the command to use an interface other than the default.

`watch` rotates in these cases:

- **On disconnect**: the next network you join sees a new address. This is the main protection.
- **On a network change**: a fallback for fast roams between two checks.
- **With `--interval N`**: every N seconds while connected. Each rotation briefly drops the connection, and captive portals may ask you to log in again.

After each rotation, `watch` ignores network changes for `--cooldown` seconds (default 30). Without this, the reconnect caused by a rotation would trigger another rotation.

Generated addresses are random, unicast and locally administered. They never match a real vendor prefix, and drivers accept them.

## Platform notes

- **macOS:** For Wi-Fi, the tool turns the radio off and on, then applies the address before the interface rejoins a network. macOS also offers *Private Wi-Fi Address* per network in System Settings. This tool adds manual control, rotation on a timer or on disconnect, and support for Ethernet adapters.
- **macOS kill switch:** The kill switch loads its rules into the system packet filter (pf). Your main pf ruleset must contain the stock `anchor "com.apple/*"` line. The tool refuses to start without it, and it does not replace the main ruleset.
- **Linux:** The tool uses `ip link`. NetworkManager may reset the address on reconnect. To prevent that, use NetworkManager's `wifi.cloned-mac-address=random`, or set the connection's cloned address to `preserve`.
- **Linux notifications:** Desktop notifications use `notify-send`. Under `sudo`, they may not reach your desktop session. Warnings are always printed in the terminal.
- Some drivers don't allow the address to change. In that case `rotate` reports an error and leaves the interface untouched.

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

The tests run without root and without a network connection. They never run real system commands: every system call is replaced by a fake.

## Disclaimer

Changing your MAC address is legal in most places and is a standard privacy measure. Use this tool only on devices you own, and follow the terms of the networks you use.
