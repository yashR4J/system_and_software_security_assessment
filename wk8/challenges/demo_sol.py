#!/usr/bin/env python3

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

######################################
############## Exploit ###############
######################################

def exploit():
    ### Write exploit here...
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
