from scapy.all import *
import base64
import random

encoded_msg = "U0lOSA=="
message = base64.b64decode(encoded_msg).decode()

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def build_packets():
    bits = text_to_bits(message)
    packets = []
    cookies = [
        "session=abc123; expires=Wed, 09 Jun 2023 10:18:14 GMT",
        "user_token=xyz456; HttpOnly; Secure"
    ]
    
    for i, bit in enumerate(bits):
        host_header = "Host" if bit == '0' else "HOST"
        encoding = "gzip, br" if bit == '0' else "deflate, identity"
        
        http_req = (
            f"GET /wp-content/logo.png HTTP/1.1\r\n"
            f"{host_header}: example.com\r\n"
            f"Accept-Encoding: {encoding}\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64)\r\n"
            f"Accept: image/webp,*/*\r\n"
            f"Cookie: {random.choice(cookies)}\r\n"
            f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.1\r\n"
            f"\r\n"
        ).encode()
        
        pkt = IP(src=f"172.16.{random.randint(1,30)}.{random.randint(2,254)}", dst="198.51.100.1") / \
              TCP(sport=random.randint(1024,49151), dport=80, flags="PA") / \
              Raw(load=http_req)
        packets.append(pkt)
    return packets

packets = build_packets()
wrpcap("multi_header.pcap", packets)
print("[+] Generated  multi_header.pcap successful!")
