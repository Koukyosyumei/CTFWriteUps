# zero_to_hero

## Bins

The heap manager needs to keep track of freed chunks so that `malloc` can reuse them during allocation requessts.

There are 5 types of bins. The small, large and unsorted bins all live togher in the same arrau; index 0 is unused, 1 is the unsorted bin, 2-64 are small bins, and 65-127 are large bins.

- small bins (62)

Each small bin stores chunks with the same fixed size. (MAXSIZE is 1024 on 64-bit and 512 on 32-bit)

- large bins (63)

Each bin stores a chunk within a size range.

- unsorted bin (1)

Instead of immediately putting newly freed chunks onto the correct bin, the heap manager coalesces it with neighbors, and dumps it onto a general unsorted linked list. During malloc, each item on the unsorted bin is checked to see if it “fits” the request. If it does, malloc can use it immediately. If it does not, malloc then puts the chunk into its corresponding small or large bin.

- fast bins (10)

- tcache bins (64)

-- First, there are no checks when tcache returns a pointer to malloc. If we can corrupt the tcache, then when malloc asks for a chunk of some size, malloc will simply let us write with whatever corrupted pointers are stored in tcache.

-- Second, the only protection that tcache has against double-free is that it makes sure the current chunk being freed is different from all chunks freed earlier of the same size.

## Strategy

1. We want to call `win`. For example, we overwrite `__free_hool` with win, we can redirect the actions of `free` to `win`.

2. 

```
malloc a chunk A with the size of 0x30
malloc a chunk B with the size of 0x110
free a chunk B
free a chunk A
malloc a chunk A with the size of 0x30
    -> overwrite the size of a chunk B with null byte
free a chunk B (double free!)
malloc` chunk of size 0x100 and overwrite the forward address to `__free_hook`
`malloc` the same (as above) chunk but from the list for size 0x110, thus removing it from the list and leaving the next chunk pointer pointing at `__free_hook`
Use `malloc` to write the address of `win()` to `__free_hook`
```

```
tcache
    0x30  chunkA
    0x110 chunkB
    
overwrite a chunk A with the size of 0x30
tcache
    0x30 chunkA
    0x110 chunkB(size is writeen as 0x100)
    
free B (double free!)
tcache 
    0x30 chukA
    0x100 chunkB
    0x110 chunkB

malloc chunk of size 0x100
 -> malloc returns chunkB
 -> overwrite the foraward address to __free_hook to chunkB

tcache
    0x30 chunkA
    0x110 chunkB (forward addr is __free_hook)

malloc (0x110)

tcache
    0x30 chunkA
    0x110 __free_hook

malloc (0x110)

get the location of __free_hook
    -> store the addr of win
```
