#!/usr/bin/env python3

#!/usr/bin/env python3
# - - - - - - - - - - - - - - - - - - - - - - - -
# dscp-top.py  by ewald@jeitler.cc 2026 https://www.jeitler.guru
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only God and I knew how it worked.
# Now only God and the AI know it.
# And since the AI helped write it… good luck to all of us.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

"""
DSCP-TOP Traffic Analyzer - high-performance, cross-platform
  Linux : AF_PACKET raw socket (reliable, ~50k pps)
  IPv4 + IPv6 supported
  macOS : scapy L2socket + direct recv() loop  (no sniff() overhead)

Direction filtering via interface MAC (L2):
  in   -> src MAC != iface MAC  (traffic received from others)
  out  -> src MAC == iface MAC  (traffic sent by us)
  both -> all frames (default)

Dependencies:
  Linux : no extra packages
  macOS : pip install scapy

Usage:
  sudo python3 dscp-top.py <interface> [-i SECONDS] [-d in|out|both]
  sudo python3 dscp-top.py eth0 -i 2 -d in
  sudo python3 dscp-top.py en7  -i 1 -d out
"""

import argparse
import logging
import os
import warnings
import socket
import struct
import subprocess
import sys
import threading
import time
import curses
import signal
from collections import defaultdict

VERSION="0.22"

# Suppress scapy warnings before any scapy import (avoids curses corruption)
logging.getLogger("scapy").setLevel(logging.CRITICAL)
warnings.filterwarnings("ignore")
os.environ.setdefault("SCAPY_IFACE_PACKET_IGNORE_NONFOUND", "1")

# ── DSCP table ────────────────────────────────────────────────────────────────
DSCP_MAP: dict[int, str] = {
    0:  "BE/CS0", 8:  "CS1",
    10: "AF11",   12: "AF12",   14: "AF13",
    16: "CS2",    18: "AF21",   20: "AF22",   22: "AF23",
    24: "CS3",    26: "AF31",   28: "AF32",   30: "AF33",
    32: "CS4",    34: "AF41",   36: "AF42",   38: "AF43",
    40: "CS5",    46: "EF",     48: "CS6",    56: "CS7",
}
DSCP_ORDER: list[int] = [0, 8, 10, 12, 14, 16, 18, 20, 22, 24,
                          26, 28, 30, 32, 34, 36, 38, 40, 46, 48, 56]

# ── Shared counters ───────────────────────────────────────────────────────────
_lock         = threading.Lock()
_pkt_count:   dict[int, int] = defaultdict(int)
_byte_count:  dict[int, int] = defaultdict(int)
_other_pkts:  int = 0
_other_bytes: int = 0
_total_pkts:  int = 0
_total_bytes: int = 0
_snap:        dict = {}
_running:     bool = True
_backend:     str  = ""


def _account(dscp: int, size: int) -> None:
    global _other_pkts, _other_bytes, _total_pkts, _total_bytes
    with _lock:
        _total_pkts  += 1
        _total_bytes += size
        if dscp in DSCP_MAP:
            _pkt_count[dscp]  += 1
            _byte_count[dscp] += size
        else:
            _other_pkts  += 1
            _other_bytes += size


# ══════════════════════════════════════════════════════════════════════════════
#  Backend A – Linux: AF_PACKET raw socket
# ══════════════════════════════════════════════════════════════════════════════
_ETH_P_ALL = 0x0003


def _get_mac_linux(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()



def _dscp_from_frame(raw: bytes) -> int:
    """
    Extract DSCP from raw Ethernet frame.
    IPv4 : EtherType 0x0800 — TOS byte at offset 15, DSCP = tos >> 2
    IPv6 : EtherType 0x86DD — Traffic Class spans bytes 14-15:
           TC = ((raw[14] & 0x0F) << 4) | (raw[15] >> 4)
           DSCP = TC >> 2
    Returns DSCP value (0-63) or -1 if not IPv4/IPv6.
    """
    if len(raw) < 34:
        return -1
    etype = struct.unpack_from("!H", raw, 12)[0]
    if etype == 0x0800:           # IPv4
        return (raw[15] >> 2) & 0x3F
    if etype == 0x86DD:           # IPv6 — need at least 54 bytes (14+40)
        if len(raw) < 54:
            return -1
        tc = ((raw[14] & 0x0F) << 4) | (raw[15] >> 4)
        return (tc >> 2) & 0x3F
    return -1

def capture_linux(iface: str, direction: str, iface_mac: str) -> None:
    """AF_PACKET raw socket — simple, reliable, good up to ~50k pps."""
    import select as _select
    mac_bytes = bytes(int(x, 16) for x in iface_mac.split(":"))

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(_ETH_P_ALL))
        # Large kernel recv buffer to reduce drops under load
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        sock.bind((iface, _ETH_P_ALL))
    except Exception as e:
        print(f"\nAF_PACKET setup failed: {e}", file=sys.stderr)
        _stop(); return

    while _running:
        ready, _, _ = _select.select([sock], [], [], 0.5)
        if not ready:
            continue
        try:
            raw = sock.recv(65535)
        except Exception:
            continue

        if len(raw) < 34:
            continue
        # Direction filter (L2)
        if direction == "in"  and raw[6:12] == mac_bytes:
            continue
        if direction == "out" and raw[6:12] != mac_bytes:
            continue

        dscp = _dscp_from_frame(raw)
        if dscp < 0:
            continue
        _account(dscp, len(raw))

    sock.close()



# ══════════════════════════════════════════════════════════════════════════════
#  Backend B – macOS: scapy L2socket direct recv() loop
#  Bypasses sniff() dispatcher entirely — tight recv loop in Python,
#  raw bytes parsed with struct (no Scapy packet object construction).
# ══════════════════════════════════════════════════════════════════════════════
def _get_mac_macos(iface: str) -> str:
    out = subprocess.check_output(["ifconfig", iface], text=True)
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("ether "):
            return s.split()[1]
    raise RuntimeError(f"Cannot determine MAC for {iface}")


def capture_macos(iface: str, direction: str, iface_mac: str) -> None:
    import io
    # Redirect stderr during scapy import + socket open to suppress BPF warnings
    _devnull = open(os.devnull, "w")
    try:
        import contextlib
        with contextlib.redirect_stderr(_devnull):
            from scapy.arch.bpf.supersocket import L2bpfSocket
            from scapy.config import conf as scapy_conf
            scapy_conf.verb = 0
    except ImportError:
        print("ERROR: scapy not installed. Run: pip install scapy",
              file=sys.stderr)
        _stop(); return

    mac_bytes = bytes(int(x, 16) for x in iface_mac.split(":"))

    try:
        with contextlib.redirect_stderr(_devnull):
            sock = L2bpfSocket(iface=iface, promisc=True)
    except Exception as e:
        print(f"\nL2bpfSocket error: {e}", file=sys.stderr)
        _stop(); return

    while _running:
        try:
            # recv_raw always returns a single tuple: (cls, raw_bytes, timestamp)
            _, raw, _ = sock.recv_raw(65535)
        except Exception:
            continue

        if raw is None or len(raw) < 34:
            continue
        # Direction filter (L2)
        if direction == "in"  and raw[6:12] == mac_bytes:
            continue
        if direction == "out" and raw[6:12] != mac_bytes:
            continue

        dscp = _dscp_from_frame(raw)
        if dscp < 0:
            continue
        _account(dscp, len(raw))

    sock.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Snapshot thread
# ══════════════════════════════════════════════════════════════════════════════
def snapshot_loop(interval: float) -> None:
    global _snap
    prev_tp = prev_tb = prev_op = prev_ob = 0
    prev_dp: dict[int, int] = defaultdict(int)
    prev_db: dict[int, int] = defaultdict(int)

    while _running:
        time.sleep(interval)
        with _lock:
            cur_tp = _total_pkts;  cur_tb = _total_bytes
            cur_dp = dict(_pkt_count); cur_db = dict(_byte_count)
            cur_op = _other_pkts;  cur_ob = _other_bytes

        d_tp = cur_tp - prev_tp;  d_tb = cur_tb - prev_tb
        dscp_dp = {d: cur_dp.get(d,0) - prev_dp.get(d,0) for d in DSCP_ORDER}
        dscp_db = {d: cur_db.get(d,0) - prev_db.get(d,0) for d in DSCP_ORDER}
        d_op = cur_op - prev_op;  d_ob = cur_ob - prev_ob

        _snap = {
            "total_pkts":       cur_tp,
            "total_bytes":      cur_tb,
            "delta_total_pkts": d_tp,
            "pps":              int(d_tp / interval),
            "bps":              int(d_tb * 8 / interval),
            "dscp_total_pkts":  cur_dp,       # cumulative since start
            "dscp_delta_pkts":  dscp_dp,
            "dscp_delta_bytes": dscp_db,
            "other_total_pkts": cur_op,       # cumulative since start
            "other_delta_pkts": d_op,
            "other_delta_bps":  int(d_ob * 8 / interval),
        }
        prev_tp = cur_tp; prev_tb = cur_tb
        prev_dp = cur_dp; prev_db = cur_db
        prev_op = cur_op; prev_ob = cur_ob


# ══════════════════════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════════════════════
_DIR_COLOR = {"in": 2, "out": 3, "both": 1}


def _fmt_rate(bps: int) -> str:
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:>7.2f} Mbit/s"
    return f"{bps / 1_000:>7.2f} kbit/s"


def draw_ui(stdscr, iface: str, interval: float,
            direction: str, iface_mac: str) -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN,  -1)
    curses.init_pair(2, curses.COLOR_CYAN,   -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_RED,    -1)
    curses.init_pair(5, curses.COLOR_WHITE,  -1)

    BAR_WIDTH = 20
    dir_cpair = _DIR_COLOR.get(direction, 1)

    while _running:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        row  = 0
        s    = _snap

        stdscr.addstr(row, 0,
            f" DSCP-TOP  iface: {iface}  interval: {interval}s  direction: ",
            curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(direction.upper(),
            curses.color_pair(dir_cpair) | curses.A_BOLD)
        stdscr.addstr(
            f"  backend: {_backend}  MAC: {iface_mac}  {time.strftime('%H:%M:%S')} ",
            curses.color_pair(1) | curses.A_BOLD)
        row += 1

        stdscr.addstr(row, 0,
            f" Total pkts: {s.get('total_pkts',0):>12,}  "
            f"Total bytes: {s.get('total_bytes',0):>14,}  "
            f"PPS: {s.get('pps',0):>8,}  "
            f"Rate: {_fmt_rate(s.get('bps',0))}",
            curses.color_pair(5))
        row += 1
        stdscr.addstr(row, 0, "─" * (w - 1), curses.color_pair(5))
        row += 1

        stdscr.addstr(row, 0,
            f"  {'DSCP':<6} {'Label':<8} "
            f"{'Pkts':>12}  {f'Rate/{interval}s':>15}  {'%':>7}  Bar",
            curses.color_pair(1))
        row += 1
        stdscr.addstr(row, 0, "─" * (w - 1), curses.color_pair(5))
        row += 1

        delta_total  = s.get("delta_total_pkts", 0)
        dscp_tot_p   = s.get("dscp_total_pkts",  {})
        dscp_dp      = s.get("dscp_delta_pkts",  {})
        dscp_db      = s.get("dscp_delta_bytes",  {})

        for dscp in DSCP_ORDER:
            if row >= h - 4:
                break
            tot_pkts = dscp_tot_p.get(dscp, 0)   # absolute since start
            d_pkts   = dscp_dp.get(dscp, 0)       # delta for % / bar
            d_bytes  = dscp_db.get(dscp, 0)
            bps_row  = int(d_bytes * 8 / interval) if interval > 0 else 0
            pct      = (d_pkts / delta_total * 100.0) if delta_total > 0 else 0.0
            filled   = int(pct / 100.0 * BAR_WIDTH)
            bar      = "█" * filled + "░" * (BAR_WIDTH - filled)
            stdscr.addstr(row, 0,
                f"  {dscp:<6} {DSCP_MAP[dscp]:<8} "
                f"{tot_pkts:>12,}  {_fmt_rate(bps_row)}  {pct:>7.2f}%  ",
                curses.color_pair(2))
            stdscr.addstr(bar, curses.color_pair(3))
            row += 1

        if row < h - 4:
            o_p   = s.get("other_total_pkts", 0)   # absolute since start
            o_dp  = s.get("other_delta_pkts", 0)
            o_bps = s.get("other_delta_bps",  0)
            o_pct = (o_dp / delta_total * 100.0) if delta_total > 0 else 0.0
            filled = int(o_pct / 100.0 * BAR_WIDTH)
            bar    = "█" * filled + "░" * (BAR_WIDTH - filled)
            stdscr.addstr(row, 0,
                f"  {'?':<6} {'OTHER':<8} "
                f"{o_p:>12,}  {_fmt_rate(o_bps)}  {o_pct:>7.2f}%  ",
                curses.color_pair(4))
            stdscr.addstr(bar, curses.color_pair(4))
            row += 1

        stdscr.addstr(h - 2, 0, "─" * (w - 1), curses.color_pair(5))
        stdscr.addstr(h - 1, 0, " 'q' quit  |  'r' reset counters                            | by Ewald Jeitler",
                      curses.color_pair(5))
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            _stop(); break
        elif key in (ord('r'), ord('R')):
            _reset()
        time.sleep(0.1)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _reset() -> None:
    global _other_pkts, _other_bytes, _total_pkts, _total_bytes
    with _lock:
        _pkt_count.clear(); _byte_count.clear()
        _other_pkts = _other_bytes = _total_pkts = _total_bytes = 0


def _stop() -> None:
    global _running
    _running = False


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    global _backend

    parser = argparse.ArgumentParser(
        description="DSCP-TOP Traffic Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("interface", help="Network interface (e.g. eth0, en7)")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        metavar="SECONDS", help="Refresh interval in seconds")
    parser.add_argument("-d", "--direction",
                        choices=["in", "out", "both"], default="both",
                        help="Packet direction filter")
    args = parser.parse_args()

    if args.interval <= 0:
        print("ERROR: interval must be > 0"); sys.exit(1)

    platform = sys.platform
    if platform.startswith("linux"):
        _backend = "AF_PACKET"
        try:
            iface_mac = _get_mac_linux(args.interface)
        except Exception as e:
            print(f"ERROR: {e}"); sys.exit(1)
        cap_fn = capture_linux

    elif platform == "darwin":
        _backend = "scapy/L2bpf"
        try:
            iface_mac = _get_mac_macos(args.interface)
        except Exception as e:
            print(f"ERROR: {e}"); sys.exit(1)
        cap_fn = capture_macos

    else:
        print(f"ERROR: unsupported platform '{platform}'"); sys.exit(1)

    print(f"Backend  : {_backend}")
    print(f"Interface: {args.interface}  MAC: {iface_mac}")
    print(f"Direction: {args.direction}  Interval: {args.interval}s")
    print("Starting capture... (press 'q' to quit)")
    time.sleep(1)

    signal.signal(signal.SIGINT,  lambda s, f: _stop())
    signal.signal(signal.SIGTERM, lambda s, f: _stop())

    cap_t  = threading.Thread(target=cap_fn,
                               args=(args.interface, args.direction, iface_mac),
                               daemon=True)
    snap_t = threading.Thread(target=snapshot_loop,
                               args=(args.interval,), daemon=True)
    cap_t.start()
    snap_t.start()

    try:
        curses.wrapper(draw_ui, args.interface, args.interval,
                       args.direction, iface_mac)
    finally:
        _stop()
        cap_t.join(timeout=3)
        snap_t.join(timeout=3)


if __name__ == "__main__":
    main()
