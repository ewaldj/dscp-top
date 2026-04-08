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
git clone https://github.com/youruser/dscp-top.git
cd dscp-top
chmod +x dscp-top.py
```

## Features

- Live per-DSCP statistics: packet count, bitrate (kbit/s / Mbit/s), percentage
- Configurable refresh interval (default: 1s)
- Direction filtering: `in`, `out`, or `both`
- All percentage and bar values are relative to the current interval (not cumulative)
- Cross-platform: Linux and macOS
- Lightweight terminal UI via `curses`
- Reset counters at runtime with `r`

### DSCP classes tracked

`BE/CS0` `CS1` `AF11` `AF12` `AF13` `CS2` `AF21` `AF22` `AF23` `CS3` `AF31` `AF32` `AF33` `CS4` `AF41` `AF42` `AF43` `CS5` `EF` `CS6` `CS7` + `OTHER` for any unrecognized marking

---

## Platform backends

| Platform | Backend | Max reliable pps |
|----------|---------|-----------------|
| Linux | `AF_PACKET` raw socket + `SO_RCVBUF 16MB` | ~50k pps |
| macOS | scapy `L2bpfSocket` direct `recv_raw()` | ~15k pps |

---

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


---

## Usage

```
sudo python3 dscp-top.py <interface> [-i SECONDS] [-d in|out|both]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `interface` | Network interface to capture on | required |
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

---

## Screenshot

```
 DSCP Analyzer  iface: eth0  interval: 1.0s  direction: BOTH  backend: AF_PACKET  MAC: 88:a2:9e:32:8e:b9  16:31:57
 Total pkts:       45,231  Total bytes:       67,846,500  PPS:    6,667  Rate:   80.00 Mbit/s
──────────────────────────────────────────────────────────────────────────────────────────────
  DSCP   Label         Pkts      Rate/1.0s        %  Bar
──────────────────────────────────────────────────────────────────────────────────────────────
  0      BE/CS0           0       0.00 kbit/s   0.00%  ░░░░░░░░░░░░░░░░░░░░
  46     EF            6667      80.00 Mbit/s  99.45%  ████████████████████
  ?      OTHER            0       0.00 kbit/s   0.00%  ░░░░░░░░░░░░░░░░░░░░
```

---

## Notes

- Requires **root** / `sudo` on both Linux and macOS (raw socket access)
- Direction filtering uses L2 (Ethernet src MAC) — requires frames with Ethernet headers
- Only IPv4 and IPv6 packets are counted; non-IP frames are ignored
- `OTHER` row captures any DSCP value not in the standard set above

---
