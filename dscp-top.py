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

VERSION="0.42"

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
_total_pkts:  int = 0
_total_bytes: int = 0
_snap:        dict = {}
_running:     bool = True
_used_only:   bool = False   # show only DSCP values with traffic
_reset_flag:  bool = False    # signals snapshot_loop to clear prev counters
_start_time:  float = 0.0        # set at capture start
_backend:     str  = ""
_L2bpfSocket         = None   # set at startup on macOS


def _account(dscp: int, size: int) -> None:
    global _total_pkts, _total_bytes
    with _lock:
        _total_pkts  += 1
        _total_bytes += size
        # Both known and unknown DSCP tracked per-value
        _pkt_count[dscp]  += 1
        _byte_count[dscp] += size


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
        _account(dscp, len(raw))

    sock.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Snapshot thread
# ══════════════════════════════════════════════════════════════════════════════
def snapshot_loop(interval: float) -> None:
    global _snap
    prev_tp = prev_tb = 0
    prev_dp: dict[int, int] = defaultdict(int)
    prev_db: dict[int, int] = defaultdict(int)

    while _running:
        time.sleep(interval)
        global _reset_flag
        if _reset_flag:
            prev_tp = prev_tb = 0
            prev_dp = defaultdict(int)
            prev_db = defaultdict(int)
            _reset_flag = False
        with _lock:
            cur_tp = _total_pkts;  cur_tb = _total_bytes
            cur_dp = dict(_pkt_count); cur_db = dict(_byte_count)

        d_tp = cur_tp - prev_tp;  d_tb = cur_tb - prev_tb

        # Split known DSCP values from unknown ones
        all_dscp  = set(cur_dp.keys())
        known     = set(DSCP_ORDER)
        unknown   = sorted(all_dscp - known)

        dscp_dp = {d: cur_dp.get(d,0) - prev_dp.get(d,0) for d in DSCP_ORDER}
        dscp_db = {d: cur_db.get(d,0) - prev_db.get(d,0) for d in DSCP_ORDER}
        unk_dp  = {d: cur_dp.get(d,0) - prev_dp.get(d,0) for d in unknown}
        unk_db  = {d: cur_db.get(d,0) - prev_db.get(d,0) for d in unknown}

        _snap = {
            "total_pkts":        cur_tp,
            "total_bytes":       cur_tb,
            "delta_total_pkts":  d_tp,
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
        }
        prev_tp = cur_tp; prev_tb = cur_tb
        prev_dp = cur_dp; prev_db = cur_db


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

    def S(*args, **kwargs):
        """Safe stdscr.addstr — ignore curses errors (terminal too small etc.)."""
        try:
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

    BAR_WIDTH = 20
    BAR_END   = 96   # prefix(76) + bar(20)
    dir_cpair = _DIR_COLOR.get(direction, 1)
    MIN_W, MIN_H = 80, 10

    while _running:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

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
        h1_right = f"  uptime: {runtime}"
        h1_pad   = " " * max(2, BAR_END - len(h1_left) - len(h1_dir) - len(h1_right))
        S(row, 0, h1_left, curses.color_pair(1) | curses.A_BOLD)
        S(h1_dir, curses.color_pair(dir_cpair) | curses.A_BOLD)
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
            f"{'Pkts':>12}  {'Bytes':>14}  {f'Rate/{interval}s':>15}  {'%':>7}  Bar",
            curses.color_pair(1))
        row += 1
        S(row, 0, "─" * (w - 1), curses.color_pair(5))
        row += 1

        # ── DSCP rows ──
        delta_total = s.get("delta_total_pkts", 0)
        dscp_tot_p  = s.get("dscp_total_pkts",  {})
        dscp_tot_b  = s.get("dscp_total_bytes",  {})
        dscp_dp     = s.get("dscp_delta_pkts",   {})
        dscp_db     = s.get("dscp_delta_bytes",  {})

        for dscp in DSCP_ORDER:
            if row >= h - 4:
                break
            tot_pkts  = dscp_tot_p.get(dscp, 0)
            tot_bytes = dscp_tot_b.get(dscp, 0)
            d_pkts    = dscp_dp.get(dscp, 0)
            if _used_only and tot_pkts == 0:
                continue
            d_bytes = dscp_db.get(dscp, 0)
            bps_row = int(d_bytes * 8 / interval) if interval > 0 else 0
            pct     = (d_pkts / delta_total * 100.0) if delta_total > 0 else 0.0
            filled  = int(pct / 100.0 * BAR_WIDTH)
            bar     = "█" * filled + "░" * (BAR_WIDTH - filled)
            S(row, 0,
                f"  {dscp:<6} {DSCP_MAP[dscp]:<9} "
                f"{tot_pkts:>12,}  {tot_bytes:>14,}  {_fmt_rate(bps_row)}  {pct:>7.2f}%  ",
                curses.color_pair(2))
            S(bar, curses.color_pair(3))
            row += 1

        # ── UNDEFINED rows (orange) ──
        unknown_list = s.get("unknown_dscp",    [])
        unk_tot_p    = s.get("unk_total_pkts",  {})
        unk_tot_b    = s.get("unk_total_bytes", {})
        unk_dp       = s.get("unk_delta_pkts",  {})
        unk_db       = s.get("unk_delta_bytes", {})
        for u_dscp in unknown_list:
            if row >= h - 4:
                break
            u_tot  = unk_tot_p.get(u_dscp, 0)
            u_tob  = unk_tot_b.get(u_dscp, 0)
            u_dp   = unk_dp.get(u_dscp, 0)
            u_db   = unk_db.get(u_dscp, 0)
            u_bps  = int(u_db * 8 / interval) if interval > 0 else 0
            u_pct  = (u_dp / delta_total * 100.0) if delta_total > 0 else 0.0
            filled = int(u_pct / 100.0 * BAR_WIDTH)
            bar    = "█" * filled + "░" * (BAR_WIDTH - filled)
            S(row, 0,
                f"  {u_dscp:<6} {'UNDEFINED':<9} "
                f"{u_tot:>12,}  {u_tob:>14,}  {_fmt_rate(u_bps)}  {u_pct:>7.2f}%  ",
                curses.color_pair(6))
            S(bar, curses.color_pair(6))
            row += 1

        # ── Footer ──
        S(h - 2, 0, "─" * (w - 1), curses.color_pair(5))
        right = f"Version {VERSION}  by Ewald Jeitler"
        left1 = " 'q' quit  |  'r' reset  |  "
        left2 = "'u' used-only"
        pad   = " " * max(1, BAR_END - len(left1) - len(left2) - len(right) - 2)
        S(h - 1, 0, left1, curses.color_pair(5))
        S(h - 1, len(left1), left2,
          curses.color_pair(1) | curses.A_BOLD if _used_only else curses.color_pair(5))
        S(h - 1, len(left1) + len(left2), pad + "| " + right, curses.color_pair(5))
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            _stop(); break
        elif key in (ord('r'), ord('R')):
            _reset()
        elif key in (ord('u'), ord('U')):
            _toggle_used_only()
        time.sleep(0.1)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _reset() -> None:
    global _total_pkts, _total_bytes, _reset_flag
    with _lock:
        _pkt_count.clear(); _byte_count.clear()
        _total_pkts = _total_bytes = 0
    _reset_flag = True   # tell snapshot_loop to zero prev counters next tick


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
