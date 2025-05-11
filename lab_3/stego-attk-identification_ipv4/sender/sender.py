from scapy.all import *

TARGET_IP = "172.20.0.3"  # IP máy receiver
MAC = "02:42:ac:14:00:04" 

def binary_to_ascii(binary_data):
    chars = [chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8)]
    return ''.join(chars)

def hide_message_in_ipid(filename="./binary.txt"):
    try:
        with open(filename, "r") as f:
            binary_data = f.read().strip()

        message = binary_to_ascii(binary_data)
        if len(message) % 2 != 0:
            message += "\0"

        chunks = [message[i:i+2] for i in range(0, len(message), 2)]

        packets = []
        for i, chunk in enumerate(chunks):
            first_char, second_char = chunk
            ip_id = (ord(first_char) << 8) | ord(second_char)
            print(f"[+] Packet {i+1}: contains hidden message")

            packet = Ether(dst=MAC) / IP(dst=TARGET_IP, id=ip_id) / ICMP()
            packets.append(packet)

        for i, packet in enumerate(packets, 1):
            sendp(packet, iface="eth0", verbose=False)
            print(f"\nSent packet {i}/{len(packets)}")

    except FileNotFoundError:
        print("\nError: binary.txt not found.")

hide_message_in_ipid()
