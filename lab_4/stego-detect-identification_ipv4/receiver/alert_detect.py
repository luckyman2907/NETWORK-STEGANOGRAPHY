from scapy.all import *

detected_packets = []

def detect(pkt):
    if IP in pkt and (pkt[IP].id & 0xFF) == 0xAA:
        print(f"[**][ALERT][**] Hidden Packet Detected! IP ID: {pkt[IP].id}")
        detected_packets.append(pkt)

print("[*] Real-time detection started. Press Ctrl+C to stop...")
try:
    sniff(filter="icmp", prn=detect)
except KeyboardInterrupt:
    wrpcap("hidden_packets.pcap", detected_packets)
    print("\n[+] Detection stopped. Hidden packets saved to 'hidden_packets.pcap'")

