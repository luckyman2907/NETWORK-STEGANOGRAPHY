from scapy.all import *
import base64
import random

encoded_msg = "VE9J"
message = base64.b64decode(encoded_msg).decode()

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def build_packets():
    bits = text_to_bits(message)
    packets = []
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (Linux; Android 10; SM-A205U)"
    ]
    
    for i, bit in enumerate(bits):
        host_header = "host" if bit == '0' else "HOST"
        
        http_req = (
            f"GET /index.html HTTP/1.1\r\n"
            f"{host_header}: example.com\r\n"
            f"User-Agent: {random.choice(user_agents)}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
            f"Referer: https://www.google.com/\r\n"
            f"\r\n"
        ).encode()
        
        pkt = IP(src="192.168.1."+str(random.randint(100,200)), dst="203.0.113.1") / \
              TCP(sport=random.randint(49152,65535), dport=80, flags="PA") / \
              Raw(load=http_req)
        packets.append(pkt)
    return packets

packets = build_packets()
wrpcap("host_case.pcap", packets)
print("[+] Generated host_case.pcap successful!")
