from scapy.all import *
import base64
import random

encoded_msg = "VklFTg=="
message = base64.b64decode(encoded_msg).decode()

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def build_packets():
    bits = text_to_bits(message)
    packets = []
    
    uris = ["/api/login", "/dashboard", "/api/data", "/user/profile", "/api/v1/users"]
    referers = [
        "https://google.com/search?q=login",
        "https://facebook.com/home",
        "https://example.org/",
        "https://news.site.com/article"
    ]

    for i, bit in enumerate(bits):
        method = "GET" if bit == '0' else "POST"
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0)" if bit == '0'
            else "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)"
        )
        uri = random.choice(uris)
        referer = random.choice(referers)

        headers = [
            f"{method} {uri} HTTP/1.1",
            "Host: api.example.com",
            f"User-Agent: {user_agent}",
            "Accept: application/json",
            "Connection: keep-alive",
            f"Referer: {referer}"
        ]

        body = ""
        if method == "POST":
            payload = f"username=user{random.randint(1,99)}&password=test{random.randint(1000,9999)}"
            headers.append("Content-Type: application/x-www-form-urlencoded")
            headers.append(f"Content-Length: {len(payload)}")
            body = "\r\n" + payload

        http_req = "\r\n".join(headers) + "\r\n\r\n" + body
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / \
              TCP(sport=40000+i, dport=80, flags="PA", seq=1000+i, ack=1) / \
              Raw(load=http_req.encode())
        
        packets.append(pkt)

    return packets

packets = build_packets()
wrpcap("combined_tech.pcap", packets)
print("[+] Generated combined_tech.pcap successful!")
