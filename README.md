# vlanhop

**By Syed Sadam Hussain Shah** — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)

A consolidated VLAN security assessment tool for penetration testers. It combines passive
discovery, bypass testing, and active impact-demonstration modules into a single script with
low false positives — every L2-hop verdict is backed by a real reply, not just an absence of
a block.

Requires root, Linux (Kali recommended), and Scapy.

---

## Commands

### Assessment

| Command | Purpose |
|---|---|
| `assess` | Full detection battery — runs all passive and active checks in sequence |
| `recon` | Passive discovery: native VLAN, VLAN IDs, switch platform, HSRP/VRRP/IPv6-RA surface |
| `reach` | Prove L2 vs L3 adjacency for specific target IPs |
| `map` | Nmap a confirmed-reachable VLAN using a spoofed source address |
| `hosts` | SYN-sweep subnets, group by TTL, flag hosts sitting behind a proxy-ARP gateway |

### Active / Red-Team

| Command | Purpose |
|---|---|
| `mitm` | ARP spoof MITM — poison victim/gateway views, forward traffic |
| `rogue-dhcp` | Rogue DHCP server with optional starvation — redirect gateway and DNS to attacker |
| `ipv6` | Rogue IPv6 router advertisement (SLAAC takeover) |
| `hsrp` | HSRP/VRRP first-hop spoof — inject active-role hellos at priority 255 |
| `snmp` | SNMP community brute + VLAN table enumeration via dot1qVlanStaticName |
| `neighbor-spoof` | Forge CDP/LLDP frames to impersonate a switch |

---

## Verdicts

| Verdict | Colour | Meaning |
|---|---|---|
| `L2-HOP` | red | Direct L2 adjacency confirmed — attacker can reach the VLAN without routing |
| `L3-SEG` | magenta | Reachable only through the gateway — L3 segmentation is intact |
| `ROUTED` | cyan | Traffic goes via the gateway MAC — expected, not a hop |
| `LIKELY` | yellow | Probable hop but not confirmed by a live reply |
| `INCONCLUSIVE` | yellow | Mixed or ambiguous evidence |
| `NOT-FOUND` | green | VLAN not reachable — segmentation appears effective |
| `SKIPPED` | dim | Test skipped (dependency missing or not applicable) |

---

## Installation

```bash
# Scapy (required for all commands)
pip install scapy

# nmap — required only for the `map` command
sudo apt install nmap

# net-snmp — required only for the `snmp` command
sudo apt install snmp
```

Requires Python 3 and root/sudo. Tested on Kali Linux.

---

## Usage

```bash
# Passive discovery first (learn the network)
sudo python3 vlanhop.py -i eth0 recon --seconds 30

# Full assessment battery
sudo python3 vlanhop.py -i eth0 assess
sudo python3 vlanhop.py -i eth0 assess --fast          # ~2x faster, slightly shorter listen windows
sudo python3 vlanhop.py -i eth0 assess --vlans 30 40 50 --native-vlan 1

# Prove reach to specific hosts
sudo python3 vlanhop.py -i eth0 reach --targets 10.30.0.1 10.40.0.1 10.50.0.1

# Map a confirmed-reachable VLAN
sudo python3 vlanhop.py -i eth0 map --vlan 30
sudo python3 vlanhop.py -i eth0 map --vlan 30 --ports 22,80,443,445

# Find real hosts behind a proxy-ARP gateway
sudo python3 vlanhop.py -i eth0 hosts
sudo python3 vlanhop.py -i eth0 hosts --subnets 10.30.0.0/24 10.40.0.0/24

# Impact demonstration (authorized targets only)
sudo python3 vlanhop.py -i eth0 mitm --targets 10.10.0.5 --duration 120
sudo python3 vlanhop.py -i eth0 rogue-dhcp --starvation 500
sudo python3 vlanhop.py -i eth0 ipv6 --prefix fd00::
sudo python3 vlanhop.py -i eth0 hsrp --vip 10.10.0.1 --group 1
sudo python3 vlanhop.py -i eth0 snmp --target 10.10.0.1
sudo python3 vlanhop.py -i eth0 neighbor-spoof --mode both
```

See [vlanhop-commands.txt](vlanhop-commands.txt) for the full flag reference per command.

---

## Shared flags

| Flag | Default | Meaning |
|---|---|---|
| `-i / --interface` | auto (default route) | Interface to use |
| `--gateway IP` | auto-detected | Default gateway |
| `--vlans N …` | CDP recon | VLAN IDs to test |
| `--native-vlan N` | CDP recon, else 1 | Port native VLAN |
| `--timeout SEC` | 8 | Capture window per test |
| `--octet N` | 240 | Last octet of spoofed IP `10.<vlan>.0.<octet>` |
| `--fast` | off | ~2x shorter listen windows across assess |

The tool assumes VLAN `<id>` maps to `10.<id>.0.0/24` / gateway `10.<id>.0.1`. Pass
`--gateway` and `--octet` when the network uses a different scheme; use `reach` and `map`
with explicit `--targets` for non-standard addressing.

---

## Techniques covered by `assess`

| Category | Techniques |
|---|---|
| Trunking negotiation | DTP auto-trunk negotiation |
| VLAN registration | GVRP dynamic VLAN join |
| VLAN database | VTP domain join |
| Spanning tree | STP root bridge takeover |
| VLAN bypass | 802.1Q double-tagging per discovered VLAN |
| Spoofed reach | IP spoof from inside each VLAN + ICMP probe |
| CAM overflow | MAC flood (configurable frame count) |
| DHCP | DHCP starvation (configurable DISCOVER count) |
| First-hop (passive) | HSRP/VRRP hello detection |
| IPv6 surface (passive) | IPv6 Router Advertisement detection |

---

## Legal

Authorized penetration testing only. Run only on networks you own or have written
permission to test. Active commands (`mitm`, `rogue-dhcp`, `ipv6`, `hsrp`) affect
live traffic on the segment and must only be used within the scope of an authorized
engagement.

---

## License

MIT — see [LICENSE](LICENSE).
