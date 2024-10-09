#!/usr/bin/env python3

from pwn import *

p = process("./not-random")

p.sendlineafter("number!\n", b"246")
p.interactive()

