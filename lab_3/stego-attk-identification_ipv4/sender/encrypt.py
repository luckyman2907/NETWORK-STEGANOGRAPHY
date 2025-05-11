def text_to_binary(message, filename="binary.txt"):
    binary_message = ''.join(format(ord(char), '08b') for char in message)  # Chuyển từng ký tự thành 8-bit

    with open(filename, "w") as f:
        f.write(binary_message)  # Ghi vào file

    print(f"{binary_message}")

# Nhập thông điệp và mã hóa
message = "SECRET"
text_to_binary(message)

