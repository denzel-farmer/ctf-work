# Vague Strategy
- gets overflow to set up ROP chain with payload 1
- run until return, executing ROP chain
- Chain gets a pointer to a known LIBC symbol address
    - gadget 0x4011b7:  mov eax, dword ptr [rbp - 4] ; leave ; ret
- Chain passes known symbol address to puts() to leak it 
- Chain restarts to give another shot for payload 2
- Based on libc address from payload 1, construct payload 2
- Either find libc one-gadget or construct new payload

# Payload 1 

1. Padding 
2. Rbp (need to think about how it is affected by leave)
    - use bss - 0x404e00

## Get known libc symbol address
- some libc addresses live in GOT, need a pointer to one
- actual pointer value is known (since no PIE?)
    - just use exe.got.puts
- can use 'read_int' to read pointer to libc address in and store it in EAX

### Structure Built on Stack

3. call read_int : exe.sym.read_int (0x401176)

## Leak libc address
- With libc address in eax, can use puts call pairs from main 
    - these mov rdi, rax and call puts

### Structure Built on Stack

4. call puts: 0x0401367

## Restart to give another shot 
- Make puts call pair the one before the end, then just input 'repeat' to get another gets() call
    - or could just use puts right before gets, leak, then put in second payload


## Compiled Payload 1
1. Padding (64 bytes)
2. Rbp (need to think about how it is affected by leave, so bss (0x404e00))
3. call read_int : exe.sym.read_int (0x401176)
4. call puts: 0x0401367

# Payload 2 
??


# Notes

- rdi after gets(): 00007FCB1DF0D7E0 where libc base is  00007FCB1DD23000