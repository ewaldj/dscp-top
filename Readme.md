# dscp-top

> Real-time DSCP traffic analyzer for network interfaces — like `top`, but for QoS markings.

`dscp-top` captures live packets on a network interface and displays a continuously updated breakdown of traffic by DSCP value, showing packet counts, bitrate, and percentage distribution per marking class.

---

## Installation / Update 

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/dscp-top/refs/heads/main/e-install.sh)"
```
or 

```bash
git clone https://github.com/ewaldj/dscp-top.git
cd dscp-top
chmod +x dscp-top.py
```

## Requirements

### Linux
No additional packages required (uses stdlib only).

```bash
# Python 3.9+ required
python3 --version
```

### macOS
```bash
pip install scapy
```

---

## Features

- Live per-DSCP statistics: packet count, bitrate (kbit/s / Mbit/s), percentage
- Configurable refresh interval (default: 1s)
- Direction filtering: `in`, `out`, or `both`
- All percentage and bar values are relative to the current interval (not cumulative)
- IPv4 and IPv6
- Tagged frames: 802.1Q, QinQ (802.1ad `0x88A8` / `0x9100`) and Cisco TrustSec / CTS metadata (`0x8909`, SGT) — in any order and combination, up to 4 stacked tags
- Cross-platform: Linux and macOS
- Lightweight terminal UI via `curses`
- Reset counters at runtime with `r`, show only DSCP values with traffic with `u`
- Interface auto-detection (interface with the default route) if none is given
- Re-starts itself via `sudo` if privileges for raw capture are missing

### DSCP classes tracked

`BE/CS0` `CS1` `AF11` `AF12` `AF13` `CS2` `AF21` `AF22` `AF23` `CS3` `AF31` `AF32` `AF33` `CS4` `AF41` `AF42` `AF43` `CS5` `EF` `CS6` `CS7` + `UNDEFINED` (orange) for any other DSCP value

---

## Platform backends

| Platform | Backend | Max reliable pps |
|----------|---------|-----------------|
| Linux | `AF_PACKET` raw socket + `SO_RCVBUF 16MB`, promiscuous mode | ~50k pps |
| macOS | scapy `L2bpfSocket` direct `recv_raw()`, promiscuous mode | ~15k pps |

---




---

## Usage

```
sudo python3 dscp-top.py [interface] [-i SECONDS] [-d in|out|both]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `interface` | Network interface to capture on | interface with default route |
| `-i`, `--interval` | Refresh interval in seconds | `1.0` |
| `-d`, `--direction` | Direction filter: `in`, `out`, `both` | `both` |

### Direction filter

| Value | Behavior |
|-------|----------|
| `in` | Packets received from others (src MAC ≠ interface MAC) |
| `out` | Packets sent by this host (src MAC = interface MAC) |
| `both` | All packets on the interface |

### Examples

```bash
# Monitor all traffic on eth0, 1s interval
sudo python3 dscp-top.py eth0

# Inbound traffic only, 5s interval
sudo python3 dscp-top.py eth0 -i 5 -d in

# Outbound traffic on macOS, 2s interval
sudo python3 dscp-top.py en7 -i 2 -d out
```

---

## Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Reset all counters |
| `u` | Toggle used-only view (only DSCP values with traffic) |

---

## Screenshot

```
 DSCP-TOP   iface: eth0  interval: 1.0s  direction: BOTH                    uptime: 00:12:41
 Total pkts:       45,231  Total bytes:     67,846,500  PPS:    6,667  Rate:   80.00 Mbit/s
──────────────────────────────────────────────────────────────────────────────────────────────
  DSCP   Label             Pkts           Bytes        Rate/1.0s        %  Bar
──────────────────────────────────────────────────────────────────────────────────────────────
  0      BE/CS0           1,192       1,451,860     0.44 Mbit/s     0.55%  ░░░░░░░░░░░░░░░░░░░░
  46     EF              44,027      66,393,620    79.56 Mbit/s    99.45%  ███████████████████░
  5      UNDEFINED           12           1,020     0.00 kbit/s     0.00%  ░░░░░░░░░░░░░░░░░░░░
──────────────────────────────────────────────────────────────────────────────────────────────
 'q' quit  |  'r' reset  |  'u' used-only                       | Version 0.44  by Ewald Jeitler
```

---

## Notes

- Requires **root** / `sudo` on both Linux and macOS (raw socket access)
- The interface is put into promiscuous mode (like `tcpdump`), so traffic on SPAN / mirror ports is counted too; on Linux the kernel removes it again when `dscp-top` exits
- Direction filtering uses L2 (Ethernet src MAC) — requires frames with Ethernet headers
- Only IPv4 and IPv6 packets are counted; non-IP frames are ignored
- 802.1Q / QinQ / CTS tags are skipped before the IP header is read; the DSCP is always taken from the IP header itself
- On Linux, many NIC drivers strip the outer 802.1Q tag before the frame reaches `AF_PACKET` (VLAN offload); those frames are counted as untagged frames — the DSCP result is the same
- `UNDEFINED` rows capture any DSCP value not in the standard set above
- Minimum terminal size: 80 x 10

---
