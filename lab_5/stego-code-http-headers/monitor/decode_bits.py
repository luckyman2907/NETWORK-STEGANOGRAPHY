def bits_to_text(bits):
    return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

student_bits = input("Nhap chuoi bits tim duoc: ")
print("[*]Thong diep giai ma:", bits_to_text(student_bits))
