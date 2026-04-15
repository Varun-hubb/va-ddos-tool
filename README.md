# VA DDoS Tool

## Overview

VA DDoS Tool is a Python-based network security tool that detects and mitigates **DoS (Denial of Service)** and **DDoS (Distributed Denial of Service)** attacks.

It uses **Scapy** for packet sniffing and **iptables** for real-time traffic blocking and rate limiting.

---

## Features

* Real-time packet monitoring using Scapy
* Detects DoS attacks (single attacker)
* Detects DDoS attacks (multiple attackers)
* Automatically blocks malicious IP addresses
* Applies rate limiting during DDoS attacks
* Simple and lightweight IDS/IPS system

---

## Lab Setup

This project was tested in a virtual lab environment:

* Ubuntu → Defender (running blocker)
* Kali Linux → Attacker (running flooders)
* VirtualBox Host-only network

---

## How It Works

1. Captures network packets using Scapy
2. Calculates packets per second per IP
3. Detects:

   * **DoS** → High traffic from single IP
   * **DDoS** → High total traffic from multiple IPs
4. Takes action:

   * Blocks IP using iptables (DoS)
   * Applies rate limiting (DDoS)

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/va-ddos-tool.git
cd va-ddos-tool
pip install .
```

---

## Usage

### Run the blocker (Defender)

```bash
sudo va-ddos --mode block
```

---

### Simulate DoS attack (Kali)

```bash
sudo python3 va_ddos_tool/dos_flooder.py
```

---

### Simulate DDoS attack (Kali)

```bash
sudo python3 va_ddos_tool/ddos_flooder.py
```

---

## Demo / Output

### DoS Detection (Single Attacker)

![DoS Detection](https://github.com/Varun-hubb/va-ddos-tool/blob/main/dos_output.png?raw=true)

---

### DDoS Detection (Multiple Attackers)

![DDoS Detection](https://github.com/Varun-hubb/va-ddos-tool/blob/main/ddos_output.png?raw=true)

---

### Firewall Rules Applied (iptables)

![iptables Rules](https://github.com/Varun-hubb/va-ddos-tool/blob/main/iptables_output.png?raw=true)

---

## Technologies Used

* Python
* Scapy
* iptables
* Linux Networking
* VirtualBox

---

## Future Improvements

* Auto-remove rate limiting after a timeout
* Real-time dashboard for monitoring
* Logging system for attacks
* Detection of SYN flood attacks
* Configurable thresholds via CLI

---

## Disclaimer

This project is for **educational purposes only**.

Do NOT use this tool on networks or systems without proper authorization.

---

## Author

Varun

---

## Support

If you found this project useful, consider giving it a ⭐ on GitHub!
