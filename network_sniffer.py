"""
Basic Network Sniffer — CodeAlpha Cyber Security Internship (Task 1)
---------------------------------------------------------------------
Captures live network packets and displays useful information about
each one: source/destination IP, protocol, ports, and payload size.

Requirements:
    pip install scapy

IMPORTANT:
    - You must run this script with administrator/root privileges,
      because capturing raw packets requires elevated access.
      - Windows: run your terminal "as Administrator" and install Npcap
        first (https://npcap.com/)
      - Linux/macOS: run with `sudo python3 network_sniffer.py`

Usage examples:
    python3 network_sniffer.py                # capture all traffic
    python3 network_sniffer.py -p tcp         # only TCP packets
    python3 network_sniffer.py -c 20          # stop after 20 packets
"""

import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def describe_packet(packet):
    """Extract and print the useful details of a single captured packet."""

    if not packet.haslayer(IP):
        return  # skip non-IP traffic (e.g. ARP) for this basic version

    ip_layer = packet[IP]
    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Figure out the protocol name and any port numbers
    if packet.haslayer(TCP):
        proto = "TCP"
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport, dport = packet[UDP].sport, packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        sport, dport = "-", "-"
    else:
        proto = f"Other ({ip_layer.proto})"
        sport, dport = "-", "-"

    payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0

    print(f"[{timestamp}] {proto:<12} {src_ip}:{sport}  ->  {dst_ip}:{dport}  "
          f"| Total len: {len(packet)} bytes | Payload: {payload_size} bytes")


def main():
    parser = argparse.ArgumentParser(description="Basic Python network sniffer")
    parser.add_argument("-p", "--protocol", default=None,
                         help="Filter by protocol: tcp, udp, or icmp")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    args = parser.parse_args()

    # Build a BPF filter string for scapy if a protocol was specified
    bpf_filter = args.protocol.lower() if args.protocol else None

    print("Starting packet capture... Press Ctrl+C to stop.\n")
    print(f"{'TIME':<10}{'PROTOCOL':<14}{'SOURCE -> DESTINATION':<45}{'SIZE INFO'}")
    print("-" * 100)

    try:
        sniff(filter=bpf_filter, prn=describe_packet, store=False, count=args.count)
    except PermissionError:
        print("\nPermission denied. Try running this script as Administrator/root.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
