from scapy.all import *
import random

# Đọc thông điệp từ file message.txt
try:
    with open("message.txt", "r") as file:
        message = file.read().strip()
except FileNotFoundError:
    print("Error: message.txt not found!")
    exit(1)
except Exception as e:
    print(f"Error reading message.txt: {e}")
    exit(1)

dst_ip = "172.20.0.10"  # IP của receiver
total_packets = 100

# Lựa chọn ngẫu nhiên các vị trí trong số 100 gói để giấu thông điệp
if len(message) > total_packets:
    print("Error: message too long to hide in 100 packets.")
    exit(1)

secret_indexes = sorted(random.sample(range(total_packets), len(message)))
packets = []

print("[+]Sending packets with hidden message......")
print("\n[+]...")
for i in range(total_packets):
    if i in secret_indexes:
        index = secret_indexes.index(i)
        char = message[index]
        ip_id = (ord(char) << 8) | 0xAA  # Giấu ký tự vào 8 bit cao, marker 0xAA vào 8 bit thấp
    else:
        ip_id = random.randint(0, 0xFFFF)  # Gói nhiễu

    pkt = IP(dst=dst_ip, id=ip_id) / ICMP()
    packets.append(pkt)

# Gửi tất cả 100 gói
for pkt in packets:
    send(pkt, verbose=False)

print("\n[+] Sent 100 packets with hidden message packets.")

