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
  Linux : AF_PACKET raw socket, promiscuous (reliable, ~50k pps)
  IPv4 + IPv6 supported, also behind 802.1Q / QinQ and Cisco CTS (CMD) tags
  macOS : scapy L2socket + direct recv() loop, promiscuous (no sniff() overhead)

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

VERSION="0.52"

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
_pkt_in:      dict[int, int] = defaultdict(int)   # packets per DSCP, received (src MAC != iface MAC)
_pkt_out:     dict[int, int] = defaultdict(int)   # packets per DSCP, sent (src MAC == iface MAC)
_byte_in:     dict[int, int] = defaultdict(int)   # bytes per DSCP, received
_byte_out:    dict[int, int] = defaultdict(int)   # bytes per DSCP, sent
_total_pkts:  int = 0
_total_bytes: int = 0
_snap:        dict = {}
_running:     bool = True
_used_only:   bool = False   # show only DSCP values with traffic
_bar_bytes:   bool = False   # bars / % based on bytes instead of packets ('b' toggles)
_reset_flag:  bool = False    # signals snapshot_loop to clear prev counters
_interval:    float = 1.0      # refresh interval in seconds (changeable at runtime with 'i')
_start_time:  float = 0.0        # set at capture start
_backend:     str  = ""
_L2bpfSocket         = None   # set at startup on macOS


def _account(dscp: int, size: int, is_out: bool = False) -> None:
    global _total_pkts, _total_bytes
    with _lock:
        _total_pkts  += 1
        _total_bytes += size
        # Both known and unknown DSCP tracked per-value
        _pkt_count[dscp]  += 1
        _byte_count[dscp] += size
        if is_out:
            _pkt_out[dscp]  += 1
            _byte_out[dscp] += size
        else:
            _pkt_in[dscp]   += 1
            _byte_in[dscp]  += size


# ══════════════════════════════════════════════════════════════════════════════
#  Backend A – Linux: AF_PACKET raw socket
# ══════════════════════════════════════════════════════════════════════════════
_ETH_P_ALL = 0x0003
_SOL_PACKET            = 263   # linux/socket.h
_PACKET_ADD_MEMBERSHIP = 1     # linux/if_packet.h
_PACKET_MR_PROMISC     = 1


def _get_mac_linux(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()



# EtherTypes of tags that sit between the MAC addresses and the IP header
_ETH_VLAN_TAGS = (0x8100, 0x88A8, 0x9100)   # 802.1Q, 802.1ad (QinQ), legacy QinQ
_ETH_CTS_CMD   = 0x8909                     # Cisco TrustSec metadata (CMD / SGT)
_MAX_TAGS      = 4                          # safety limit for stacked tags


def _dscp_from_frame(raw: bytes) -> int:
    """
    Extract DSCP from raw Ethernet frame.

    Tags between the MAC addresses and the IP header are skipped, in any
    order and combination (up to _MAX_TAGS):
      802.1Q 0x8100 / 802.1ad 0x88A8 / 0x9100 : 4 bytes (TPID + TCI)
      Cisco CTS/CMD 0x8909                    : 2 + 2 + len*4 bytes
                                                (EtherType, version, length,
                                                 options incl. SGT)
    Then:
      IPv4 : EtherType 0x0800 — TOS byte, DSCP = tos >> 2
      IPv6 : EtherType 0x86DD — Traffic Class spans the first two bytes:
             TC = ((b0 & 0x0F) << 4) | (b1 >> 4), DSCP = TC >> 2
    Returns DSCP value (0-63) or -1 if not IPv4/IPv6 (or truncated).
    """
    n = len(raw)
    off = 12                                  # position of the EtherType
    if n < off + 2:
        return -1
    etype = (raw[off] << 8) | raw[off + 1]

    for _ in range(_MAX_TAGS):
        if etype in _ETH_VLAN_TAGS:
            off += 4
        elif etype == _ETH_CTS_CMD:
            if n < off + 4:
                return -1
            cmd_len = raw[off + 3]           # length in 4-byte option units
            if cmd_len == 0:
                return -1
            off += 4 + cmd_len * 4
        else:
            break
        if n < off + 2:
            return -1
        etype = (raw[off] << 8) | raw[off + 1]

    ip = off + 2                              # first byte of the IP header
    if etype == 0x0800:                       # IPv4 — full 20-byte header
        if n < ip + 20:
            return -1
        return (raw[ip + 1] >> 2) & 0x3F
    if etype == 0x86DD:                       # IPv6 — full 40-byte header
        if n < ip + 40:
            return -1
        tc = ((raw[ip] & 0x0F) << 4) | (raw[ip + 1] >> 4)
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
        # Promiscuous mode (like tcpdump) — needed on SPAN/mirror ports,
        # otherwise the NIC drops unicast frames not addressed to us.
        # Bound to the socket: the kernel removes it again on close/exit.
        mreq = struct.pack("iHH8s", socket.if_nametoindex(iface),
                           _PACKET_MR_PROMISC, 0, b"")
        sock.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP, mreq)
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
        _account(dscp, len(raw), raw[6:12] == mac_bytes)

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
    import contextlib
    # _L2bpfSocket is imported once at startup in main() — guaranteed available here
    mac_bytes = bytes(int(x, 16) for x in iface_mac.split(":"))
    _devnull = open(os.devnull, "w")
    try:
        with contextlib.redirect_stderr(_devnull):
            sock = _L2bpfSocket(iface=iface, promisc=True)
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
        _account(dscp, len(raw), raw[6:12] == mac_bytes)

    sock.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Snapshot thread
# ══════════════════════════════════════════════════════════════════════════════
def snapshot_loop(interval: float) -> None:
    global _snap, _interval
    _interval = interval
    prev_tp = prev_tb = 0
    prev_dp: dict[int, int] = defaultdict(int)
    prev_db: dict[int, int] = defaultdict(int)
    prev_di: dict[int, int] = defaultdict(int)
    prev_do: dict[int, int] = defaultdict(int)
    prev_dib: dict[int, int] = defaultdict(int)
    prev_dob: dict[int, int] = defaultdict(int)

    while _running:
        # Sleep in small steps so a changed interval ('i') takes effect quickly;
        # rates are calculated with the real elapsed time of this tick.
        t0 = time.time()
        while _running and time.time() - t0 < _interval:
            time.sleep(0.05)
        interval = max(time.time() - t0, 0.001)
        global _reset_flag
        if _reset_flag:
            prev_tp = prev_tb = 0
            prev_dp = defaultdict(int)
            prev_db = defaultdict(int)
            prev_di = defaultdict(int)
            prev_do = defaultdict(int)
            prev_dib = defaultdict(int)
            prev_dob = defaultdict(int)
            _reset_flag = False
        with _lock:
            cur_tp = _total_pkts;  cur_tb = _total_bytes
            cur_dp = dict(_pkt_count); cur_db = dict(_byte_count)
            cur_di = dict(_pkt_in);    cur_do = dict(_pkt_out)
            cur_dib = dict(_byte_in);  cur_dob = dict(_byte_out)

        d_tp = cur_tp - prev_tp;  d_tb = cur_tb - prev_tb

        # Split known DSCP values from unknown ones
        all_dscp  = set(cur_dp.keys())
        known     = set(DSCP_ORDER)
        unknown   = sorted(all_dscp - known)

        dscp_dp = {d: cur_dp.get(d,0) - prev_dp.get(d,0) for d in DSCP_ORDER}
        dscp_db = {d: cur_db.get(d,0) - prev_db.get(d,0) for d in DSCP_ORDER}
        unk_dp  = {d: cur_dp.get(d,0) - prev_dp.get(d,0) for d in unknown}
        unk_db  = {d: cur_db.get(d,0) - prev_db.get(d,0) for d in unknown}
        dscp_di = {d: cur_di.get(d,0) - prev_di.get(d,0) for d in all_dscp}
        dscp_do = {d: cur_do.get(d,0) - prev_do.get(d,0) for d in all_dscp}
        dscp_dib = {d: cur_dib.get(d,0) - prev_dib.get(d,0) for d in all_dscp}
        dscp_dob = {d: cur_dob.get(d,0) - prev_dob.get(d,0) for d in all_dscp}

        _snap = {
            "total_pkts":        cur_tp,
            "total_bytes":       cur_tb,
            "delta_total_pkts":  d_tp,
            "delta_total_bytes": d_tb,
            "interval":          _interval,
            "pps":               int(d_tp / interval),
            "bps":               int(d_tb * 8 / interval),
            "dscp_total_pkts":   cur_dp,       # cumulative since start
            "dscp_total_bytes":  cur_db,       # cumulative bytes since start
            "dscp_delta_pkts":   dscp_dp,
            "dscp_delta_bytes":  dscp_db,
            "unknown_dscp":      unknown,
            "unk_total_pkts":    cur_dp,
            "unk_total_bytes":   cur_db,
            "unk_delta_pkts":    unk_dp,
            "unk_delta_bytes":   unk_db,
            "dscp_delta_in":     dscp_di,      # received packets in this interval
            "dscp_delta_out":    dscp_do,      # sent packets in this interval
            "dscp_total_in":     cur_di,       # received packets since start
            "dscp_total_out":    cur_do,       # sent packets since start
            "dscp_delta_in_b":   dscp_dib,     # received bytes in this interval
            "dscp_delta_out_b":  dscp_dob,     # sent bytes in this interval
            "dscp_total_in_b":   cur_dib,      # received bytes since start
            "dscp_total_out_b":  cur_dob,      # sent bytes since start
        }
        prev_tp = cur_tp; prev_tb = cur_tb
        prev_dp = cur_dp; prev_db = cur_db
        prev_di = cur_di; prev_do = cur_do
        prev_dib = cur_dib; prev_dob = cur_dob


# ══════════════════════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════════════════════
_IN_PAIR, _OUT_PAIR = 7, 8          # bar colors: IN = blue, OUT = magenta
_DIR_COLOR = {"in": _IN_PAIR, "out": _OUT_PAIR, "both": 1}


def _split_bar(filled: int, d_in: int, d_out: int, width: int):
    """Split the filled part of the bar into IN / OUT segments (proportional)."""
    d_all = d_in + d_out
    n_in  = int(round(filled * d_in / d_all)) if d_all > 0 else 0
    n_in  = min(n_in, filled)
    return n_in, filled - n_in, width - filled


def _fmt_rate(bps: int) -> str:
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:>7.2f} Mbit/s"
    return f"{bps / 1_000:>7.2f} kbit/s"


def draw_ui(stdscr, iface: str, interval: float,
            direction: str, iface_mac: str) -> None:

    def S(*args, **kwargs):
        """Safe stdscr.addstr — ignore curses errors, clip text at the right
        window edge so nothing wraps into the next line."""
        try:
            args = list(args)
            if isinstance(args[0], int):
                x, i = args[1], 2
            else:
                x, i = stdscr.getyx()[1], 0
            args[i] = args[i][:max(stdscr.getmaxyx()[1] - 1 - x, 0)]
            stdscr.addstr(*args, **kwargs)
        except curses.error:
            pass

    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN,  -1)
    curses.init_pair(2, curses.COLOR_CYAN,   -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_RED,    -1)
    curses.init_pair(5, curses.COLOR_WHITE,  -1)
    if curses.can_change_color() and curses.COLORS >= 256:
        curses.init_color(16, 1000, 500, 0)   # RGB orange
        curses.init_pair(6, 16, -1)
    else:
        curses.init_pair(6, curses.COLOR_YELLOW, -1)
    curses.init_pair(_IN_PAIR,  curses.COLOR_BLUE,    -1)
    curses.init_pair(_OUT_PAIR, curses.COLOR_MAGENTA, -1)

    PREFIX    = 76   # width of the columns left of the bar(s)
    AVG_GAP   = 2    # spaces between the current bar and the average bar
    BAR_MIN   = 12   # minimum width of one bar when two bars are shown
    BAR_MAX   = 100  # maximum width of one bar
    dir_cpair = _DIR_COLOR.get(direction, 1)
    MIN_W, MIN_H = 85, 10
    input_buf = None          # None = normal mode, str = typing a new interval
    try:
        curses.set_escdelay(25)   # make ESC react immediately
    except Exception:
        pass

    while _running:
        interval = _snap.get("interval", _interval)   # always matches the snapshot rates
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        # Bars adapt to the terminal width: two bars (current + average since
        # start) if there is room for two bars of at least BAR_MIN, else one.
        avail    = w - PREFIX - 1
        show_avg = avail >= 2 * BAR_MIN + AVG_GAP
        if show_avg:
            bar_w = min((avail - AVG_GAP) // 2, BAR_MAX)
        else:
            bar_w = max(min(avail, BAR_MAX), 1)
        bar_end  = PREFIX + bar_w + (AVG_GAP + bar_w if show_avg else 0)

        if w < MIN_W or h < MIN_H:
            S(0, 0,
              f" Terminal too small ({w}x{h}) — minimum {MIN_W}x{MIN_H} "[:w],
              curses.color_pair(4) | curses.A_BOLD)
            stdscr.refresh()
            time.sleep(0.2)
            continue

        row = 0
        s   = _snap

        # ── Header ──
        elapsed  = int(time.time() - _start_time)
        runtime  = f"{elapsed//3600:02d}:{(elapsed%3600)//60:02d}:{elapsed%60:02d}"
        h1_left  = f" DSCP-TOP   iface: {iface}  interval: {interval}s  direction: "
        h1_dir   = direction.upper()
        h1_mid   = "  bars: "
        h1_mode  = "BYTES" if _bar_bytes else "PACKETS"
        h1_right = f"  uptime: {runtime}"
        h1_pad   = " " * max(2, bar_end - len(h1_left) - len(h1_dir) - len(h1_mid)
                                - len(h1_mode) - len(h1_right))
        S(row, 0, h1_left, curses.color_pair(1) | curses.A_BOLD)
        S(h1_dir, curses.color_pair(dir_cpair) | curses.A_BOLD)
        S(h1_mid, curses.color_pair(1) | curses.A_BOLD)
        S(h1_mode, curses.color_pair(3) | curses.A_BOLD)
        S(h1_pad + h1_right, curses.color_pair(1) | curses.A_BOLD)
        row += 1

        # ── Totals ──
        S(row, 0,
            f" Total pkts: {s.get('total_pkts',0):>12,}  "
            f"Total bytes: {s.get('total_bytes',0):>14,}  "
            f"PPS: {s.get('pps',0):>8,}  "
            f"Rate: {_fmt_rate(s.get('bps',0))}",
            curses.color_pair(5))
        row += 1
        S(row, 0, "─" * (w - 1), curses.color_pair(5))
        row += 1

        # ── Column headers ──
        S(row, 0,
            f"  {'DSCP':<6} {'Label':<9} "
            f"{'Pkts':>12}  {'Bytes':>14}  {f'Rate/{interval}s':>15}  {'%':>8}  ",
            curses.color_pair(1))
        # "█in █out" centered over the current bar, "Avg since start" over the average bar
        if bar_w >= 8:
            x = PREFIX + (bar_w - 8) // 2
            S(row, x,     "█",   curses.color_pair(_IN_PAIR)  | curses.A_BOLD)
            S("in ",             curses.color_pair(1))
            S("█",               curses.color_pair(_OUT_PAIR) | curses.A_BOLD)
            S("out",             curses.color_pair(1))
        if show_avg:
            avg_lbl = "Avg since start" if bar_w >= 15 else "Avg"
            x = PREFIX + bar_w + AVG_GAP + (bar_w - len(avg_lbl)) // 2
            S(row, x, avg_lbl, curses.color_pair(1))
        row += 1
        S(row, 0, "─" * (w - 1), curses.color_pair(5))
        row += 1

        # ── DSCP rows ──
        delta_total = s.get("delta_total_pkts", 0)
        dscp_tot_p  = s.get("dscp_total_pkts",  {})
        dscp_tot_b  = s.get("dscp_total_bytes",  {})
        dscp_dp     = s.get("dscp_delta_pkts",   {})
        dscp_db     = s.get("dscp_delta_bytes",  {})
        # bars and % follow the selected unit (packets or bytes)
        sfx         = "_b" if _bar_bytes else ""
        dscp_di     = s.get("dscp_delta_in"  + sfx, {})
        dscp_do     = s.get("dscp_delta_out" + sfx, {})
        tot_in      = s.get("dscp_total_in"  + sfx, {})
        tot_out     = s.get("dscp_total_out" + sfx, {})
        delta_val   = s.get("delta_total_bytes" if _bar_bytes else "delta_total_pkts", 0)
        total_pkts  = s.get("total_pkts", 0)

        def avg_bar(dscp, pair_rest):
            """Second bar: in/out ratio of this DSCP since start over the FULL bar
            width (so even a few packets show whether they are in or out).
            A direction with at least one packet always gets >= 1 cell."""
            if not show_avg:
                return
            a_i = tot_in.get(dscp, 0)
            a_o = tot_out.get(dscp, 0)
            S(" " * AVG_GAP)
            if a_i + a_o == 0:
                S("░" * bar_w, curses.color_pair(pair_rest))
                return
            n_i = int(round(bar_w * a_i / (a_i + a_o)))
            if a_i > 0 and n_i == 0:
                n_i = 1
            if a_o > 0 and n_i == bar_w:
                n_i = bar_w - 1
            S("█" * n_i,           curses.color_pair(_IN_PAIR))
            S("█" * (bar_w - n_i), curses.color_pair(_OUT_PAIR))

        unknown_list = s.get("unknown_dscp", [])
        d_pk = {**dscp_dp, **s.get("unk_delta_pkts",  {})}
        d_by = {**dscp_db, **s.get("unk_delta_bytes", {})}

        # Entries to show: (dscp, label, text color, empty-bar color)
        entries = [(d, DSCP_MAP[d], 2, 5) for d in DSCP_ORDER
                   if not (_used_only and dscp_tot_p.get(d, 0) == 0)]
        entries += [(d, "UNDEFINED", 6, 6) for d in unknown_list]

        # Not enough rows for everything -> never hide traffic silently:
        # first drop DSCP values without any traffic, then the smallest ones.
        avail = h - 3 - row
        if len(entries) > avail:
            entries = [e for e in entries if dscp_tot_p.get(e[0], 0) > 0]
        hidden = []
        if len(entries) > avail:
            keep = set(e[0] for e in sorted(entries, key=lambda e: dscp_tot_p.get(e[0], 0),
                                            reverse=True)[:max(avail - 1, 0)])
            hidden  = [e for e in entries if e[0] not in keep]
            entries = [e for e in entries if e[0] in keep]

        for dscp, label, c_txt, c_rest in entries:
            tot_pkts  = dscp_tot_p.get(dscp, 0)
            tot_bytes = dscp_tot_b.get(dscp, 0)
            d_pkts    = (d_by if _bar_bytes else d_pk).get(dscp, 0)
            bps_row   = int(d_by.get(dscp, 0) * 8 / interval) if interval > 0 else 0
            pct       = (d_pkts / delta_val * 100.0) if delta_val > 0 else 0.0
            filled    = int(pct / 100.0 * bar_w)
            n_in, n_out, n_rest = _split_bar(filled, dscp_di.get(dscp, 0),
                                             dscp_do.get(dscp, 0), bar_w)
            S(row, 0,
                f"  {dscp:<6} {label:<9} "
                f"{tot_pkts:>12,}  {tot_bytes:>14,}  {_fmt_rate(bps_row)}  {pct:>7.2f}%  ",
                curses.color_pair(c_txt))
            S("█" * n_in,   curses.color_pair(_IN_PAIR))
            S("█" * n_out,  curses.color_pair(_OUT_PAIR))
            S("░" * n_rest, curses.color_pair(c_rest))
            avg_bar(dscp, c_rest)
            row += 1

        if hidden:
            h_pct = sum((d_by if _bar_bytes else d_pk).get(e[0], 0) for e in hidden) \
                    / delta_val * 100.0 if delta_val > 0 else 0.0
            S(row, 0,
              f"  ... {len(hidden)} more DSCP values hidden (terminal too small): "
              f"{h_pct:.2f}% of the interval",
              curses.color_pair(4) | curses.A_BOLD)
            row += 1

        # ── Footer ──
        S(h - 2, 0, "─" * (w - 1), curses.color_pair(5))
        if input_buf is not None:
            prompt = f" New interval in seconds [{_interval:g}]: "
            S(h - 1, 0, prompt, curses.color_pair(1) | curses.A_BOLD)
            S(input_buf, curses.color_pair(5))
            S("   (Enter = apply, ESC = keep)", curses.color_pair(5))
            try:
                curses.curs_set(1)
                stdscr.move(h - 1, min(len(prompt) + len(input_buf), w - 1))
            except curses.error:
                pass
        else:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            right = f"Version {VERSION}  by Ewald Jeitler"
            left1 = " 'q' quit  |  'r' reset  |  'i' interval  |  'b' pkts/bytes  |  "
            if len(left1) + 13 + len(right) + 4 > w:    # narrow terminal: drop credits
                right = ""
            left2 = "'u' used-only"
            pad   = " " * max(1, bar_end - len(left1) - len(left2) - len(right) - 2)
            S(h - 1, 0, left1, curses.color_pair(5))
            S(h - 1, len(left1), left2,
              curses.color_pair(1) | curses.A_BOLD if _used_only else curses.color_pair(5))
            if right:
                S(h - 1, len(left1) + len(left2), pad + "| " + right, curses.color_pair(5))
        stdscr.refresh()

        key = stdscr.getch()
        if input_buf is not None:
            # ── Interval input mode ──
            if key in (10, 13, curses.KEY_ENTER):
                try:
                    val = float(input_buf.replace(",", "."))
                    if val > 0:
                        _set_interval(max(val, 0.1))
                except ValueError:
                    pass                      # empty/invalid -> keep old value
                input_buf = None
            elif key == 27:                   # ESC -> keep old value
                input_buf = None
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                input_buf = input_buf[:-1]
            elif 0 <= key < 256 and chr(key) in "0123456789.," and len(input_buf) < 8:
                input_buf += chr(key)
        elif key in (ord('i'), ord('I')):
            input_buf = ""
        elif key in (ord('q'), ord('Q')):
            _stop(); break
        elif key in (ord('r'), ord('R')):
            _reset()
        elif key in (ord('u'), ord('U')):
            _toggle_used_only()
        elif key in (ord('b'), ord('B')):
            _toggle_bar_bytes()
        time.sleep(0.1)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _reset() -> None:
    global _total_pkts, _total_bytes, _reset_flag
    with _lock:
        _pkt_count.clear(); _byte_count.clear()
        _pkt_in.clear();    _pkt_out.clear()
        _byte_in.clear();   _byte_out.clear()
        _total_pkts = _total_bytes = 0
    _reset_flag = True   # tell snapshot_loop to zero prev counters next tick


def _set_interval(value: float) -> None:
    global _interval
    _interval = value


def _toggle_bar_bytes() -> None:
    global _bar_bytes
    _bar_bytes = not _bar_bytes


def _toggle_used_only() -> None:
    global _used_only
    _used_only = not _used_only


def _stop() -> None:
    global _running
    _running = False


# ── Entry point ───────────────────────────────────────────────────────────────

def _default_iface() -> str:
    """
    Return interface with default gateway, or first interface with an IPv4
    address as fallback. Raises RuntimeError if nothing found.
    """
    import socket as _socket

    # Try: parse routing table for default gateway interface
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    fields = line.split()
                    # Destination==00000000 means default route
                    if fields[1] == "00000000":
                        return fields[0]
        except Exception:
            pass

    elif sys.platform == "darwin":
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("interface:"):
                    return line.split()[-1]
        except Exception:
            pass

    # Fallback: first interface with an IPv4 address (skip loopback)
    try:
        import socket as _socket
        ifaces = subprocess.check_output(
            ["ip", "route"] if sys.platform.startswith("linux") else ["ifconfig"],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Generic fallback via getaddrinfo trick
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Find interface with this IP
        if sys.platform.startswith("linux"):
            import fcntl, struct, array
            SIOCGIFCONF = 0x8912
            buf = array.array('B', b'\x00' * 1024)
            ifc = struct.pack('iL', buf.buffer_info()[1], buf.buffer_info()[0])
            import ctypes
            s2 = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            fcntl.ioctl(s2.fileno(), SIOCGIFCONF, ifc)
            s2.close()
        # Simpler: use /proc/net/if_inet6 or just return first non-lo from /sys
        if sys.platform.startswith("linux"):
            for iface in os.listdir("/sys/class/net"):
                if iface == "lo":
                    continue
                try:
                    addr = open(f"/proc/net/fib_trie").read()
                    if ip in addr:
                        return iface
                except Exception:
                    pass
            # Last resort: first non-loopback in /sys/class/net
            for iface in sorted(os.listdir("/sys/class/net")):
                if iface != "lo":
                    return iface
        elif sys.platform == "darwin":
            out = subprocess.check_output(["ifconfig"], text=True)
            current = None
            for line in out.splitlines():
                if not line.startswith("\t") and not line.startswith(" "):
                    current = line.split(":")[0]
                if "inet " in line and ip in line and current and current != "lo0":
                    return current
    except Exception:
        pass

    raise RuntimeError("Cannot determine default interface. Please specify one explicitly.")


def _check_and_escalate() -> None:
    """
    Verify we have the privileges needed for raw packet capture.
    Test by attempting to open the required socket/device.
    If insufficient: re-exec via sudo, prompting for password.
    """
    platform = sys.platform

    def _has_perms() -> bool:
        if platform.startswith("linux"):
            try:
                import socket as _s
                s = _s.socket(_s.AF_PACKET, _s.SOCK_RAW, 0)
                s.close()
                return True
            except PermissionError:
                return False
            except Exception:
                return True   # other error — not a permission issue
        elif platform == "darwin":
            # Check read access to any /dev/bpf* device
            import glob
            for dev in sorted(glob.glob("/dev/bpf*")):
                try:
                    with open(dev, "rb"):
                        pass
                    return True
                except PermissionError:
                    return False
                except Exception:
                    continue
            return False   # no bpf devices found
        return True   # unknown platform — let it proceed

    if _has_perms():
        return   # already sufficient

    # Re-exec via sudo, preserving PYTHONPATH so user-installed packages are visible
    print("Insufficient privileges for raw packet capture.")
    print("Re-starting with sudo...")
    try:
        # Merge current sys.path into PYTHONPATH so sudo python3 finds same packages
        env = os.environ.copy()
        env["PYTHONPATH"] = ":".join(sys.path)
        # sudo -E preserves environment; pass env explicitly for reliability
        os.execvpe("sudo", ["sudo", "-E", sys.executable] + sys.argv, env)
    except Exception as e:
        print(f"ERROR: failed to escalate via sudo: {e}")
        print(f"       Run manually: sudo {sys.executable} {' '.join(sys.argv)}")
        sys.exit(1)

def main() -> None:
    _check_and_escalate()
    global _backend

    parser = argparse.ArgumentParser(
        description="DSCP-TOP Traffic Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("interface", nargs="?", default=None,
                        help="Network interface (e.g. eth0, en7). Default: interface with default gateway.")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        metavar="SECONDS", help="Refresh interval in seconds")
    parser.add_argument("-d", "--direction",
                        choices=["in", "out", "both"], default="both",
                        help="Packet direction filter")
    args = parser.parse_args()

    if args.interface is None:
        try:
            args.interface = _default_iface()
            print(f"Auto-detected interface: {args.interface}")
        except RuntimeError as e:
            print(f"ERROR: {e}"); sys.exit(1)

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
        # Import scapy once at startup — hard fail with clear message if missing
        global _L2bpfSocket
        try:
            import contextlib, io
            with contextlib.redirect_stderr(open(os.devnull, "w")):
                from scapy.arch.bpf.supersocket import L2bpfSocket as _L2bpfSocket
                from scapy.config import conf as _scapy_conf
                _scapy_conf.verb = 0
        except ImportError:
            print("ERROR: scapy is not installed.")
            print("       Install it with:  pip install scapy")
            print("       Then re-run dscp-top.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: scapy import failed: {e}")
            sys.exit(1)
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

    global _start_time
    _start_time = time.time()

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
