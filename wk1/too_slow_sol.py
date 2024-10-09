#!/usr/bin/env python3

from pwn import *

p = remote("6447.lol", 14292)
# p = process("./too-slow")

p.recvuntil(b"runs out!\n")
num1 = int(p.recvuntil(b' '))
p.recvuntil(b'+ ')
num2 = int(p.recvuntil(b' '))
p.sendlineafter(b"= ", str(num1 + num2).encode())

i = 1
while(i<10):
    p.recvuntil(b"Correct Answer!\n")
    num1 = int(p.recvuntil(b' '))
    p.recvuntil(b'+ ')
    num2 = int(p.recvuntil(b' '))
    p.sendlineafter(b"= ", str(num1 + num2).encode())
    i += 1

p.interactive()