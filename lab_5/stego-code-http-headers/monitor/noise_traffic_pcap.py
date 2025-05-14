from scapy.all import *
import base64
import random

encoded_msg = "UFRJVA=="
message = base64.b64decode(encoded_msg).decode()

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "PostmanRuntime/7.29.0"
]

def random_headers(host, method="GET", content_length=0):
    ua = random.choice(user_agents)
    headers = [
        f"{method} / HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {ua}",
        "Accept: */*",
        "Connection: keep-alive",
        "Accept-Encoding: gzip, deflate",
        f"Referer: http://{host}/home"
    ]
    if method == "POST":
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {content_length}")
    return "\r\n".join(headers) + "\r\n\r\n"

def build_packets():
    bits = text_to_bits(message)
    packets = []
    sent_bits = ""

    for i, bit in enumerate(bits):
        if random.random() < 0.3:
            fake_method = random.choice(["GET", "PUT"])
            headers = random_headers("noise.com", method=fake_method)
            http_req = headers.encode()
            pkt = IP(src="10.0.0.1", dst="10.0.0.2") / \
                  TCP(sport=40000+i, dport=80, flags="PA") / \
                  Raw(load=http_req)
            packets.append(pkt)

        method = "GET" if bit == '0' else "POST"

        if method == "POST":
            body = "username=admin"
            headers = random_headers("example.com", method="POST", content_length=len(body))
            full_request = headers + body
        else:
            full_request = random_headers("example.com", method="GET")

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / \
              TCP(sport=50000+i, dport=80, flags="PA") / \
              Raw(load=full_request.encode())
        packets.append(pkt)
        sent_bits += bit

    return packets

packets = build_packets()
wrpcap("noise_traffic.pcap", packets)
print("[+] Generated noise_traffic.pcap successful!")
