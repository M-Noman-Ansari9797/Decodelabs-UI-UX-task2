# CodeAlpha_NetworkSniffer

A basic Python-based network packet sniffer built as part of the **CodeAlpha Cyber Security Internship** (Task 1).

This tool captures live network traffic on a machine and displays key details about each packet — source and destination IP addresses, protocol type, port numbers, and payload size — helping to understand how data flows across a network and the basics of common protocols (TCP, UDP, ICMP).

## 📋 Features

- Captures live packets in real time using `scapy`
- Identifies and displays protocol type (TCP / UDP / ICMP / Other)
- Shows source and destination IP addresses and ports
- Displays total packet size and payload size
- Optional protocol filtering (e.g., capture only TCP traffic)
- Optional packet count limit (auto-stop after N packets)

## 🛠 Tech Stack

- **Language:** Python 3
- **Library:** [Scapy](https://scapy.net/) — for packet capturing and parsing

## ⚙️ Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/M-Noman-Ansari9797/CodeAlpha_NetworkSniffer
   cd CodeAlpha_NetworkSniffer
   ```

2. Install dependencies:
   ```bash
   pip install scapy
   ```

3. **Windows only:** install [Npcap](https://npcap.com/) — required by Scapy to access network interfaces.

## ▶️ Usage

> ⚠️ Packet capturing requires administrator/root privileges.

**Windows** (run terminal as Administrator):
```bash
python network_sniffer.py
```

**Linux / macOS:**
```bash
sudo python3 network_sniffer.py
```

### Optional arguments

| Flag | Description | Example |
|------|-------------|---------|
| `-p`, `--protocol` | Filter by protocol (`tcp`, `udp`, `icmp`) | `python network_sniffer.py -p tcp` |
| `-c`, `--count` | Stop after capturing N packets | `python network_sniffer.py -c 20` |

Combine both:
```bash
sudo python3 network_sniffer.py -p tcp -c 20
```

## 🖥 Sample Output

```
Starting packet capture... Press Ctrl+C to stop.

TIME      PROTOCOL      SOURCE -> DESTINATION                        SIZE INFO
----------------------------------------------------------------------------------------------------
14:32:10  TCP           192.168.1.5:52344  ->  142.250.183.14:443    | Total len: 66 bytes | Payload: 0 bytes
14:32:10  UDP           192.168.1.5:60321  ->  8.8.8.8:53             | Total len: 74 bytes | Payload: 32 bytes
14:32:11  ICMP          192.168.1.5:-      ->  1.1.1.1:-              | Total len: 98 bytes | Payload: 56 bytes
```

## 📚 What I Learned

- How network packets are structured (headers vs. payload)
- The difference between TCP, UDP, and ICMP traffic
- How IP addresses and ports identify the source and destination of communication
- How to use Scapy to capture and parse live network traffic in Python
- The basics of applying filters to isolate specific types of traffic

## ⚠️ Disclaimer

This tool is built strictly for **educational purposes** as part of a cyber security internship task. Only run it on networks and devices you own or have explicit permission to monitor. Unauthorized packet sniffing may violate privacy laws and organizational policies.

## 🙌 Acknowledgements

Built as part of the **CodeAlpha Cyber Security Internship** — Task 1: Basic Network Sniffer.

- Website: [www.codealpha.tech](https://www.codealpha.tech)
