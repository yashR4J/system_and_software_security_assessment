intro
-----

This was a fairly straightforward CTF, since each step was communicated
to the user until the very end. Lab helped get a better understanding of
pwntools functions in interacting with the command line. Finding the 
secret "flag" hidden in the file required an understanding of how the 
underlying code was written - binary ninja helped reveal the flag was 
simply the string "password". 

```
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
```

too slow
--------
Similar setup to addition problem in intro CTF; a simple while loop helped
identify that this problem was posed 10 times after which shell access was
granted.

```
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
```