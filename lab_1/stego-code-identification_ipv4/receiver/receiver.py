from scapy.all import *

# Nhập danh sách IP ID
ip_id_input = input("\nEnter the IP ID list containing hidden message (separated by commas): ")

ip_ids = ip_id_input.split(",")
hidden_message = ""

try:
    for ip_id_str in ip_ids:
        ip_id = int(ip_id_str.strip())  # Loại bỏ khoảng trắng và chuyển thành số nguyên
        first_char = chr((ip_id >> 8) & 0xFF)  # Lấy 8 bit cao
        second_char = chr(ip_id & 0xFF)  # Lấy 8 bit thấp
        hidden_message += first_char + second_char

    # Xóa ký tự NULL nếu có
    hidden_message = hidden_message.rstrip("\0")

    # Hiển thị thông điệp cuối cùng
    print("\nHidden message: {}".format(hidden_message))

except ValueError:
    print("Invalid input! Please enter numbers separated by commas.")

