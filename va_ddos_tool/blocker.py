import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

def show_banner():
    print("""
==================================================
 █████   █████   █████████      ██████████    ████████  ███████████ ███████████  ████████  ██████   █████ ██████████    ████████  ███████████  
░░███   ░░███   ███░░░░░███    ░░███░░░░███  ███░░░░███░░███░░░░░░█░░███░░░░░░█ ███░░░░███░░██████ ░░███ ░░███░░░░███  ███░░░░███░░███░░░░░███ 
 ░███    ░███  ░███    ░███     ░███   ░░███░░░    ░███ ░███   █ ░  ░███   █ ░ ░░░    ░███ ░███░███ ░███  ░███   ░░███░░░    ░███ ░███    ░███ 
 ░███    ░███  ░███████████     ░███    ░███   ██████░  ░███████    ░███████      ██████░  ░███░░███░███  ░███    ░███   ██████░  ░██████████  
 ░░███   ███   ░███░░░░░███     ░███    ░███  ░░░░░░███ ░███░░░█    ░███░░░█     ░░░░░░███ ░███ ░░██████  ░███    ░███  ░░░░░░███ ░███░░░░░███ 
  ░░░█████░    ░███    ░███     ░███    ███  ███   ░███ ░███  ░     ░███  ░     ███   ░███ ░███  ░░█████  ░███    ███  ███   ░███ ░███    ░███ 
    ░░███      █████   █████    ██████████  ░░████████  █████       █████      ░░████████  █████  ░░█████ ██████████  ░░████████  █████   █████
     ░░░      ░░░░░   ░░░░░    ░░░░░░░░░░    ░░░░░░░░  ░░░░░       ░░░░░        ░░░░░░░░  ░░░░░    ░░░░░ ░░░░░░░░░░    ░░░░░░░░  ░░░░░   ░░░░░ 
                                                                                                                                               
                                                                                                                                               
                                                                                                                                                
==================================================

            VA D3F3ND SECURITY SYSTEM
--------------------------------------------------
Owner   : Varun
Engine  : Scapy Packet Analyzer
Mode    : Real-Time Intrusion Detection
Version : 1.0.0 LAB EDITION
--------------------------------------------------

[+] SYSTEM INITIALIZING...
""")

LOCAL_IP = "192.168.56.101" #Change this to your own blocker ip
THRESHOLD = 5 #per IP (DOS)
TOTAL_THRESHOLD = 2 #global (DDOS)
INTERFACE = "enp0s8"

print(f"[INFO] DOS Threshold: {THRESHOLD}")
print(f"[INFO] DDOS Threshold: {TOTAL_THRESHOLD}")

def apply_rate_limit():
	print("[ACTION] Applying rate limiting...")

	#Avoid duplicate rules
	os.system("iptables -C INPUT -p tcp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT 2>/dev/null || " "iptables -A INPUT -p tcp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT")
	os.system("iptables -C INPUT -p tcp -j DROP 2>/dev/null ||" "iptables -A INPUT -p tcp -j DROP")
def packet_callback(packet):
	global total_packets, ddos_active

	if IP not in packet:
		return

	src_ip = packet[IP].src

	#ignore own tarffic(outgoing traffic from ubuntu)
	if src_ip == LOCAL_IP:
		return

	#ignore already blocked ips
	if src_ip in blocked_ips:
		return

	packet_count[src_ip] += 1
	total_packets += 1

	current_time = time.time()
	time_interval = current_time - start_time[0]

	print(f"[DEBUG] Packet from {src_ip}")

	if time_interval >= 1:

	#For a single IP exceeding Threshold(DOS)
		for ip, count in list(packet_count.items()):
			packet_rate = count / time_interval

			print(f"[INFO] {ip} -> {packet_rate:.2f} packets/sec")

			if packet_rate > THRESHOLD and ip not in blocked_ips:
				print(f"[ALERT] DOS Detected from {ip}-> Blocking IP: {ip}")
				os.system(f"iptables -A INPUT -s {ip} -j DROP")
				blocked_ips.add(ip)
	#For a multiple IPs sending packets at same time(DDOS)
		total_rate = total_packets / time_interval
		print(f"[INFO] TOTAL traffic -> {total_rate:.2f} packets/sec")

		if total_rate > TOTAL_THRESHOLD and not ddos_active[0]:
			print("[ALERT]DDOS detected-> Applying Rate limit!")
			apply_rate_limit()
			ddos_active[0] = True
	#Resetting packet count
			packet_count.clear()
			start_time[0] = current_time


def main():
	show_banner()
	print("Starting VA D3F3ND Engine...")
    print("[+] Monitoring traffic...\n")
	if os.geteuid() != 0:
		print("[ERROR] Run this script as root!")
		sys.exit(1)

	packet_count = defaultdict(int)
	start_time = [time.time()]
	blocked_ips = set()
	total_packets = 0
	ddos_active = [False]

	print("[INFO] Monitoring network traffic on interface {INTERFACE}...")

	sniff(filter="ip", prn=packet_callback, iface=INTERFACE)
