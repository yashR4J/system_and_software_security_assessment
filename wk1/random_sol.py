#!/usr/bin/env python3

from pwn import *

#pr = process("6447.lol", PORT)
p1 = process("./random")
p2 = process("./random")

p1.sendlineafter(b"number!\n", b"10")
p1.recvuntil(b"was ")
guess = int(p1.recvline().strip())

p2.sendlineafter(b"number!\n", bytes(guess)) 
p2.interactive()
