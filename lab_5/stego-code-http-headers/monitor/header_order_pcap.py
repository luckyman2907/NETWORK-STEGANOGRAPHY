from scapy.all import *
import base64
import random

encoded_msg = "TEE="
message = base64.b64decode(encoded_msg).decode()

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def build_packets():
    bits = text_to_bits(message)
    packets = []
    paths = ["/", "/about", "/contact", "/products?id=123"]
    
    for i, bit in enumerate(bits):
        path = random.choice(paths)
        if bit == '0':
            http_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: example.com\r\n"
                f"User-Agent: curl/7.68.0\r\n"
                f"Accept: */*\r\n"
                f"X-Request-ID: {random.randint(1000,9999)}\r\n"
                f"\r\n"
            ).encode()
        else:
            http_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"User-Agent: curl/7.68.0\r\n"
                f"Host: example.com\r\n"
                f"Accept: */*\r\n"
                f"X-Request-ID: {random.randint(1000,9999)}\r\n"
                f"\r\n"
            ).encode()

        pkt = IP(src=f"10.0.{random.randint(1,5)}.{random.randint(10,50)}", dst="203.0.113.1") / \
              TCP(sport=random.randint(32768,60999), dport=80, flags="PA") / \
              Raw(load=http_req)
        packets.append(pkt)
    return packets

packets = build_packets()
wrpcap("header_order.pcap", packets)
print("[+] Generated header_order.pcap successful!")
