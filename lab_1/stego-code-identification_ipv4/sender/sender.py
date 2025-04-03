from scapy.all import *
import random

TARGET_IP = "172.20.0.3"  # IP máy nhận

def binary_to_ascii(binary_data):
    chars = [chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8)]
    return ''.join(chars)

def hide_message_in_ipid(filename="./binary.txt"):
    try:
        with open(filename, "r") as f:
            binary_data = f.read().strip()

        message = binary_to_ascii(binary_data)
        if len(message) % 2 != 0:
            message += "\0"  # Thêm ký tự NULL nếu số ký tự lẻ

        # Chia thông điệp thành từng cặp ký tự (16-bit mỗi gói)
        chunks = [message[i:i+2] for i in range(0, len(message), 2)]
        num_chunks = len(chunks)

        # Xác định số lượng gói tin tổng cộng (gồm cả gói nhiễu)
        num_packets = num_chunks * 2  # Thêm cả gói không chứa thông điệp

        # Chọn ngẫu nhiên các vị trí chứa thông điệp
        secret_indexes = sorted(random.sample(range(num_packets), num_chunks))  

        packets = []
        for i in range(num_packets):
            if i in secret_indexes:
                index = secret_indexes.index(i)  # Xác định thứ tự của cặp ký tự trong thông điệp
                first_char, second_char = chunks[index]
                ip_id = (ord(first_char) << 8) | ord(second_char)  # Nhúng thông điệp vào IP ID
                print(f"[+] Packet {i+1}: contains hidden message")
            else:
                ip_id = random.randint(0, 65535)  # Gói tin nhiễu
                print(f"[-] Packet {i+1}: does not contain hidden message")

            packet = IP(dst=TARGET_IP, id=ip_id) / ICMP()
            packets.append(packet)

        # Gửi gói tin đi
        for i, packet in enumerate(packets, 1):
            send(packet, verbose=False)
            print(f"\nSent packet {i}/{num_packets}")

    except FileNotFoundError:
        print("\nError: binary.txt not found.")

hide_message_in_ipid()

