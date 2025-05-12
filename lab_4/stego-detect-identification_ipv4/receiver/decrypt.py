from scapy.all import *

# Nhập danh sách IP ID
ip_id_input = input("\n[*]Enter the IP ID list containing hidden message (separated by commas): ")

ip_ids = [int(ip_id.strip()) for ip_id in ip_id_input.split(",") if ip_id.strip()]
hidden_message = ""

try:
    for ip_id in ip_ids:
        # Lấy 8 bit cao (phần chứa thông điệp)
        char_code = (ip_id >> 8) & 0xFF
        
        # Chuyển thành ký tự ASCII, chỉ lấy ký tự in được
        if 32 <= char_code <= 126:
            hidden_message += chr(char_code)
        else:
            hidden_message += "?"

    # Hiển thị thông điệp cuối cùng
    print("\n[*]Hidden message: {}".format(hidden_message))

except ValueError:
    print("[!]Invalid input! Please enter numbers separated by commas.")
except Exception as e:
    print(f"Error: {e}")
