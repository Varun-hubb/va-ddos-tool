import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

# ===== CONFIG =====
LOCAL_IP = "192.168.56.101"
THRESHOLD = 5
TOTAL_THRESHOLD = 2
INTERFACE = "enp0s8"

print(f"[INFO] DOS Threshold: {THRESHOLD}")
print(f"[INFO] DDOS Threshold: {TOTAL_THRESHOLD}")


def show_banner():
    print("""
================ VA D3FF3ND =================
 █████   █████   █████████      ██████████    ████████  ███████████ ███████████  ████████  ██████   █████ ██████████  
░░███   ░░███   ███░░░░░███    ░░███░░░░███  ███░░░░███░░███░░░░░░█░░███░░░░░░█ ███░░░░███░░██████ ░░███ ░░███░░░░███ 
 ░███    ░███  ░███    ░███     ░███   ░░███░░░    ░███ ░███   █ ░  ░███   █ ░ ░░░    ░███ ░███░███ ░███  ░███   ░░███
 ░███    ░███  ░███████████     ░███    ░███   ██████░  ░███████    ░███████      ██████░  ░███░░███░███  ░███    ░███
 ░░███   ███   ░███░░░░░███     ░███    ░███  ░░░░░░███ ░███░░░█    ░███░░░█     ░░░░░░███ ░███ ░░██████  ░███    ░███
  ░░░█████░    ░███    ░███     ░███    ███  ███   ░███ ░███  ░     ░███  ░     ███   ░███ ░███  ░░█████  ░███    ███ 
    ░░███      █████   █████    ██████████  ░░████████  █████       █████      ░░████████  █████  ░░█████ ██████████  
     ░░░      ░░░░░   ░░░░░    ░░░░░░░░░░    ░░░░░░░░  ░░░░░       ░░░░░        ░░░░░░░░  ░░░░░    ░░░░░ ░░░░░░░░░░   
                                                                                                                      
                                                                                                                      
                                                                                                                      
============================================
""")


def apply_rate_limit():
    print("[ACTION] Applying rate limiting...")

    os.system(
        "iptables -C INPUT -p tcp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT 2>/dev/null || "
        "iptables -A INPUT -p tcp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT"
    )

    os.system(
        "iptables -C INPUT -p tcp -j DROP 2>/dev/null || "
        "iptables -A INPUT -p tcp -j DROP"
    )


# ===== GLOBAL VARIABLES =====
packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = set()
total_packets = 0
ddos_active = [False]


def packet_callback(packet):
    global packet_count, start_time, blocked_ips, total_packets, ddos_active

    if IP not in packet:
        return

    src_ip = packet[IP].src

    # ignore own traffic
    if src_ip == LOCAL_IP:
        return

    # ignore blocked IPs
    if src_ip in blocked_ips:
        return

    packet_count[src_ip] += 1
    total_packets += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:

        # ===== DOS CHECK =====
        for ip, count in list(packet_count.items()):
            rate = count / time_interval
            print(f"[INFO] {ip} -> {rate:.2f} packets/sec")

            if rate > THRESHOLD and ip not in blocked_ips:
                print(f"[ALERT] DoS detected from {ip}")
                print(f"[ACTION] Blocking {ip}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        # ===== DDOS CHECK =====
        total_rate = total_packets / time_interval
        print(f"[INFO] TOTAL traffic -> {total_rate:.2f} packets/sec")

        if total_rate > TOTAL_THRESHOLD and not ddos_active[0]:
            print("[ALERT] DDoS detected -> Applying rate limit")
            apply_rate_limit()
            ddos_active[0] = True

        # ===== RESET =====
        packet_count.clear()
        start_time[0] = current_time
        total_packets = 0


def main():
    show_banner()

    print("Starting VA D3FF3ND Engine...")
    print("[+] Monitoring traffic...\n")

    if os.geteuid() != 0:
        print("[ERROR] Run as root")
        sys.exit(1)

    print(f"[INFO] Monitoring network traffic on interface {INTERFACE}...")

    sniff(filter="ip", prn=packet_callback, iface=INTERFACE)


if __name__ == "__main__":
    main()
