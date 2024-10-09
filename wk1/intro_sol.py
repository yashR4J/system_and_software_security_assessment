#!/usr/bin/env python3

from pwn import *

p = remote("6447.lol", 18231)
# p = process("./intro")

p.recvuntil(b"address: ")
address = p.recvline().strip().decode()
address_value = int(address.replace('{', '').replace('}', ''), 16)
p.sendlineafter(b"form!\n", str(address_value).encode())

new_address = address_value-0x103
p.sendlineafter(b"MINUS 0x103!", hex(new_address).encode())

p.sendlineafter(b"little endian form!", p32(address_value))

p.recvuntil(b"(on the next line)\n")
little_endian_address = p.recvline().strip()
reversed_bytes = little_endian_address
little_endian_address = int.from_bytes(reversed_bytes, byteorder='little')
p.sendlineafter(b"decimal form!", str(little_endian_address).encode())

p.sendlineafter(b"hex form!", hex(little_endian_address).encode())

p.recvuntil(b'What is ')
num1 = int(p.recvuntil(b' '))
p.recvuntil(b'+ ')
num2 = int(p.recvuntil(b'?').strip(b'?'))
p.sendline(str(num1 + num2).encode())

p.recvuntil(b"decimal: ")
address = p.recvline().strip().decode()
address_value = int(address, 16) 
p.sendline(str(address_value).encode())

p.recvuntil(b"decimal: ")
address = p.recvline().strip()
address_value = int.from_bytes(address, byteorder='little')
p.sendline(str(address_value).encode())
p.sendlineafter(b"file?", b"password")

p.interactive()

