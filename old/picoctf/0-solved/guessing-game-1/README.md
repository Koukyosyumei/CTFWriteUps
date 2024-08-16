# guessing-game-1

```
gdb-peda$ b *0x400c7f
Breakpoint 1 at 0x400c7f
gdb-peda$ run
Starting program: /mnt/c/Users/kanka/Desktop/Dev/CTFWriteUps/picoctf/guessing-game-1/vuln
Welcome to my guessing game!

What number would you like to guess?
84
Congrats! You win! Your prize is this print statement!

New winner!
Name? ABCDEF
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffd9d0 --> 0xa464544434241 ('ABCDEF\n')
RBX: 0x400400 (<_init>: sub    rsp,0x8)
RCX: 0xa464544 ('DEF\n')
RDX: 0x6bce00 --> 0x0
RSI: 0x7fffffffd9d0 --> 0xa464544434241 ('ABCDEF\n')
RDI: 0x4930da ("Congrats %s\n\n")
RBP: 0x7fffffffda40 --> 0x7fffffffda70 --> 0x4019e0 (<__libc_csu_init>: push   r15)
RSP: 0x7fffffffd9d0 --> 0xa464544434241 ('ABCDEF\n')
RIP: 0x400c7f (<win+63>:        mov    eax,0x0)
R8 : 0x6bfb57 --> 0x0
R9 : 0x6be880 (0x00000000006be880)
R10: 0x6be880 (0x00000000006be880)
R11: 0x246
R12: 0x401a80 (<__libc_csu_fini>:       push   rbp)
R13: 0x0
R14: 0x6ba018 --> 0x444bf0 (<__strcpy_sse2_unaligned>:  mov    rcx,rsi)
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400c71 <win+49>:   lea    rax,[rbp-0x70]
   0x400c75 <win+53>:   mov    rsi,rax
   0x400c78 <win+56>:   lea    rdi,[rip+0x9245b]        # 0x4930da
=> 0x400c7f <win+63>:   mov    eax,0x0
   0x400c84 <win+68>:   call   0x410010 <printf>
   0x400c89 <win+73>:   nop
   0x400c8a <win+74>:   leave
   0x400c8b <win+75>:   ret
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd9d0 --> 0xa464544434241 ('ABCDEF\n')
0008| 0x7fffffffd9d8 --> 0x4930e8 ("Welcome to my guessing game!\n")
0016| 0x7fffffffd9e0 --> 0x6bc0a0 --> 0x0
0024| 0x7fffffffd9e8 --> 0x6ba018 --> 0x444bf0 (<__strcpy_sse2_unaligned>:      mov    rcx,rsi)
0032| 0x7fffffffd9f0 --> 0x0
0040| 0x7fffffffd9f8 --> 0x4163b3 (<_IO_new_file_overflow+259>: cmp    eax,0xffffffff)
0048| 0x7fffffffda00 --> 0x1d
0056| 0x7fffffffda08 --> 0x6ba360 --> 0xfbad2887
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400c7f in win ()
```
