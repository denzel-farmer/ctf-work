# minecraft
## Summary

This challenge provides a Linux CLI program with a stack buffer overflow
vulnerability that is exploited by building and executing a two-stage ROP chain
which launches a remote shell. 

**Challenge Artifacts:**
* `chall/chall`: vulnerable 64-bit ELF executable provided by challenge authors
* `chall/chall.c`: vulnerable source code provided by challenge authors
* `chall/libc.so.6`: libc binary dinamically linked with `chall`
* `chall/ld-linux-x86-64.so.2`: ld-linux binary used to run and link `chall` 

**Solution Artifacts:**
* `solve.py`: `pwntools` exploit script that executes `/bin/sh` via a ROP chain
* `chall-gadgets.txt`: ROP gadgets in `chall/vuln` found with `ROPgadget`
* `libc-gagdets.txt`: ROP gadgets in `chall/libc.so.6` found with `ROPgadget`
* `Dockerfile`: container image build file configured with vulnerable program and
debugging environment

## Context

The `minecraft` challenge authors provide a domain and port to connect to the 
challenge, a copy of the compiled `chall` binary that is running, the `libc.so.6`
binary it is dynamically linked against, and the binary source code `chall.c`.

The program is a simple CLI-based 'minecraft' game, where the user inputs options
into a CLI menu. With a certain set of inputs, the game includes a path which
allows the user to input a 'world name' string:
```
$ ./chall/chall

M I N C E R A F T

1. Singleplayer
2. Multiplayer
1
Creating new world
Enter world name:
AAAAAAAAAA
```

The binary is a 64-bit x86 ELF executable, which is dynamically linked by
`ld-linux` with the provided `libc`. It is executed in an environment with 
ASLR enabled, so the base address where `libc` is placed at runtime is
randomized. However, position independence (PIE) is disabled, so addresses
from the `chall` binary itself are known. The stack is not executable, so 
shellcode cannot directly be executed from the stack.

```
$ file chall/chall
chall/chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=85733c251d84d09de2cc21c10b82f13adf2b9878, for GNU/Linux 3.2.0, not stripped

$ checksec chall/chall
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
  

## Vulnerability 

The source `chall/chall.c` includes a vulnerable stack buffer overflow on line
33, where it makes a call to `gets` which reads user input into a local stack
variable `char world_name[64]`.

The libc `gets` function is inherently insecure, as it reads bytes from `stdin`
to its output buffer in memory unconditionally until it finds a newline.

As a result, with the right sequence of input an attacker controlling `stdin`
can reach the `gets` call and provide a payload line longer than the expected
64 bytes, which will overwrite the stack frame of the `main` function. Without
stack canaries enabled, this allows the attacker to gain control of execution
via a ROP chain. 

## Exploitation

**Exploit overview:** the exploit uses a local stack buffer overflow to launch
a two-stage rop chain: the first stage leaks the randomized base address of
`libc.so.6` and launches the second stage, which uses ROP gadgets from `libc` to
execute a remote shell.

**Primitives used:**
1. Local stack buffer overflow to overwrite return address and deliver payloads
2. Global Offset Table (GOT) entry leak to discover libc base address

**Input constraints:**
The `gets` function reads payloads until a newline character or EOF, so the
constructed payloads cannot include a newline character (`0x0a`). Since the
second payload is partially random, occassionally it will include `0x0a` and
the exploit must be run again. 

### Detail Exploit Description
The `solve.py` script interacts with the target using pwntools, and performs the
exploit int two stages: The first stage leaks the libc base address, while the
second stage uses the leaked address to construct a payload that launches
`/bin/sh`.

The two-stage design is required because the `chall` binary is small, and does
not have enough ROP gagdets to easily construct a shell execution or file read
payload (see `chall-gadgets.txt`). To construct the final payload, we need
gadgets from the dynamically loaded `libc.so.6` code, which requires first
leaking the runtime-randomized libc base address.  

#### Stage 1: Libc Leak 

To leak libc, `solve.py` first navigates to the vulnerable `gets` call (just
after the "Enter world name:" prompt) in the `main` function, and sends the
initial payload. The stack just before the overflow, when `RIP` points to the vulnerable
`call gets` instruction, looks like this (assuming `RSP=0x7ff000`):
```
<high addresses>

[0xxxxxxx] [-------- previous stack frames -------]
[0x7ff048] [------ saved ret addr (8 bytes) ------]
[0x7ff040] [-------- saved rbp (8 bytes) ---------] <-- rbp
[0x7ff038] [------- char world_name[56:63] -------|
[0x7ff030] |------ char world_name[48:55] --------|
[0x7ffxxx] |-------- char world_name[...] --------| 
[0x7ff000] |------- char world_name[0:7] ---------] <-- rsp, rdi (gets() write location)

<low addresses>
```
At this point, `rdi` points at the same location as `rsp`, since the call to `gets`
is writing into the local variable `world_name` on the top of the stack. However,
`gets` will happily overwrite beyond `world_name` and into the stack frame if an
appropriately sized payload is provded. 

The first payload includes padding 'A' bytes to overrun `world_name`, followed
by a malicious 'saved rbp' value, and then a chain of ROP gadget addresses, the
first of which overwrites the saved return address that `main` will pop and call
when it hits its `ret` instruction. After the first payload overwrite, the 
stack then looks like this:
```
<high addresses>

[0xxxxxxx] [-------- previous stack frames -------]  
[0x7ff050] [--------- main+0x87 inst addr --------] (...  
[0x7ff048] [--------- read_int func addr ---------]  ROP chain
[0x7ff048] [---------- nop gadget addr -----------]  ...)
[0x7ff040] [----- second stack (0x404e00) --------] <-- rbp
[0x7ff038] [--------- padding 'A' bytes  ---------|
[0x7ff030] |--------- padding 'A' bytes  ---------|
[0x7ffxxx] |---------         ...        ---------| 
[0x7ff000] |--------- padding 'A' bytes  ---------] <-- rsp (gets() write location)

<low addresses>
```

Now, the stack frame has been replaced with a malicious payload. 

As `solve.py` sends input to navigate to the `ret` instruction at the end of
`main`, the function cleans up its stack frame by setting `rsp=rbp` (so `rsp`
points to the the fake "saved rbp") and popping the value at the top of the 
stack (the fake "saved rbp") into `rbp`. This value is the address of some unused
but writable 'second stack', where the second payload will later be constructed.

The `rsp` is the left pointing at the address of the first ROP gadget (a 'nop'
gadget), so when the main `ret` instruction finally executes the program will
return to the gadget. The nop gadget does nothing except call `ret` again, which
ensures that `rsp` is 16-byte aligned before the executing next gadget. 

The next gadget is just a pointer to the `read_int` function, which is in the
`chall` binary and reads a number from `stdin`, converts it to an integer, and
returns it by placing it in `eax`. When this function is called during the exploit,
`solve.py` sends the known address of the `puts@libc` entry in the GOT, which is
an address that contains the address of `puts` in `libc.so.6` (which the payload
ultimately leaks). When `read_int` returns, it pops and jumps to the final gadget,
`main+0x87`. 

The gadget `main+0x87` is one instruction before the call to `puts` that
normally displays the "Enter world name" prompt in main, specifically
`mov rdi, eax`. This fills `rdi` (where the subsequent `puts` expects a pointer
to a buffer to display) with `eax`, which the previous gadget filled with the
libc GOT entry. When the `call puts` instruction executes, it sends the address
of `puts` (which is in libc) to the attacker. `solve.py` uses this address
to construct the second payload, described in the next section. 

After leaking a libc address, the program continues executing the `main`
function a second time, starting after `main+0x87`, which hits the vulnerable
`gets` call a second time. This recieves the second payload, beginning stage two.

#### Stage 2: Remote Shell

The second stage starts with `solve.py` building the second payload which launches
`/bin/sh`. This payload again uses ROP gadgets, but now can incorperate those
from `libc` (which are much more numerous and complex). To use a `libc` gadget,
`solve.py` uses its constant offset relative to the leaked base address, and then
adds that address to calculate an absolute address. 

After building the payload, `solve.py` sends it to the second `gets` call. This
call writes the payload bytes to `rbp-0x40`, which normally points to the
beginning of the `world_name` local variable. However, since the stage 1 gadget
returned directly to `main+0x87`, the `main` function never set up a stack frame,
and `rbp` still points to our 'second stack' writeable location. So, just after
the second `gets` call, the stack 'pivots' from its original location to a new
stack constructed at `0x404e00`: 
```
Original Stack (fully 'rolled up'):
<high addresses>

[0xxxxxxx] [-------- previous stack frames -------]  <-- rsp
[0x7ff050] [--------- main+0x87 inst addr --------] 
[0x7ff048] [--------- read_int func addr ---------] 
[0x7ff048] [---------- nop gadget addr -----------]  
[0x7ff040] [----- second stack (0x404e00) --------] 
[0x7ff038] [--------- padding 'A' bytes  ---------|
[0x7ff030] |--------- padding 'A' bytes  ---------|
[0x7ffxxx] |---------         ...        ---------| 
[0x7ff000] |--------- padding 'A' bytes  ---------]

...

Second stack: 

[0x404e18] [-------- execv "/bin/sh" addr --------]
[0x404e1A] [-------- pop rdi value (NULL) --------]
[0x404e18] [-------- pop_rdi gadget addr ---------]
[0x404e10] [-------- pop r13 value (NULL) --------]
[0x404e0A] [------- pop rbp value (0x404f00) -----]
[0x404e08] [------- pop_rbp_r13 gadget addr ------]  
[0x404e00] [--- unused saved rbp (0xdeadbeef) ----] <-- rbp
[0x404df8] [--------- padding 'A' bytes  ---------|
[0x404dc0] |--------- padding 'A' bytes  ---------|
[0x404dxx] |---------         ...        ---------| 
[0x404dc8] |--------- padding 'A' bytes  ---------] <-- new gets() write location


<low addresses>
```
Once again, after the `gets` call the exploit navigates to the `ret` at the
end of `main`, which "cleans up" the newly constructed stack by reseting
`rsp=rbp` and popping that value (this time, an unused value) into `rbp`. This
leaves `rsp` pointing to the first gadget address (in libc) when `ret` executes.

The first gadget is a `pop rbp; pop r13; ret` gadget that allows us to set the 
values of registers to values required by the final 'one gadget'. Specifically,
we must set `rbp` to a writeable region, and `r13` to `NULL`. These values are
popped off the stack, so can just be hardcoded next into the payload.

This gadget returns to the final setup gadget, that pops `NULL` into `rdi`, meeting
the final requirement of the target "one gadget". When the pop_rdi gadget returns,
it jumps to the "one gadget", which calls `execve("/bin/sh", rbp-0x40, r13)`.

Just before this call, the second stack is fully rolled up and `rsp` is 16-byte
aligned. When the call is made, it launches a `/bin/sh` shell and `solve.py`
enters interactive mode, allowing the attacker to display the contents of `flag.txt`. 

### Payload Structures
**Payload 1**
```
---------------------------------------------------------
| Component                     | Value     | Size      |
---------------------------------------------------------
| Padding 'A' bytes             | 'A'*64    | 64 bytes  |
| 'Second stack' address        | 0x404e00  | 8 bytes   |
| NOP gadget address            | 0x4010ef  | 8 bytes   |
| read_int function address     | 0x401176  | 8 bytes   |
| main+087 inst. address        | 0x401234  | 8 bytes   |
---------------------------------------------------------
```
**Payload 2**
```
-------------------------------------------------------------
| Component                     | Value             | Size  |
-------------------------------------------------------------
| Padding 'A' bytes             | 'A'*64        | 64 bytes  |
| Unused saved rbp              | 0xdeadbeef    | 8 bytes   |
| pop rbp pop r13 gadget addr   | libc+0xfea7c  | 8 bytes   |
| rbp address (writeable)       | 0x404f00      | 8 bytes   |
| r13 value                     | NULL (0x0)    | 8 bytes   |       
| pop rdi gadget address        | libc+0x277e5  | 8 bytes   |
| rdi value                     | NULL (0x0)    | 8 bytes   | 
| execv "one gadget" address    | libc+0xd511f  | 8 bytes   |
-------------------------------------------------------------
```

## Remediation
- replace gets with fgets
- mitigations:
    - stack canary 
    - PIE disabled 

## Configuration Notes
- Use container 
















-----------------------------------------------------
| Component                             | Size      |
-----------------------------------------------------
| Padding 'A' bytes                     | 64 bytes  |
| unused rbp = 0xdeadbeef               | 8 bytes   |
| pop_rbp       | 8 bytes   |
| read_int function address = 0x401176  | 8 bytes   |
| main+087 inst. address = 0x401234     | 8 bytes   |
-----------------------------------------------------
```

```
[0xxxxxxx] [-------- previous stack frames -------]  
[0x7ff050] [--------- main+0x87 inst addr --------] (...  
[0x7ff048] [--------- read_int func addr ---------]  ROP chain
[0x7ff048] [---------- nop gadget addr -----------]  ...)
[0x7ff040] [----- second stack (0x404e00) --------] <-- rbp

Structure:
```
 | padding | rbp | nop | read_int | puts | main | 
 ```

#### Payload 2
Structure: 
```
| padding | rbp | pop_rbp_r13 | writable addr (rbp) | NULL (r13) | pop_rdi | NULL (rdi) | one_gadget |
```

#### Step-by-Step Exploit
- Vulnerable gets comes from "Enter world name" prompt, first neavigate to this prompt
- Send binary payload, which gets clobbers the stack with
Original Stack (RIP = call gets() in main)
```
high
[------- previous stack frames ------]
[----- saved ret addr (8 bytes) -----]
[------- saved rbp (8 bytes) --------] <-- rbp
[---- local variables (64 bytes) ----|
|------- char world_name[63] --------|
|------- char world_name[...] -------|  
|------- char world_name[0] ---------] <-- rsp, gets() write location
low 
```
Stack just after gets() (RIP = instr after call gets() in main)
```
high
[--- chain[2]: main puts call addr --]
[------ chain[1]: read_int addr -----]
[----- chain[0]: nop gadget addr ----]
[----- malicious rbp (8 bytes) ------] <-- rbp
[------- padding 'A' bytes  ---------|
|------- padding 'A' bytes  ---------|
|-------         ...        ---------|  
|------- padding 'A' bytes  ---------] <-- rsp, gets() write location
low
``` 
- Navigates through the rest of main, intentionally hit 'ret' which kicks off rop chain
    - Note that during this processes, main 'cleans up' stack with the following:
        - sets rsp=rbp (so rsp=&malicious rbp), effectively trashing local varaiables/padding
        - pops to rbp, so rbp=malicious rbp and rsp=&chain[0]
    - Ret pops nop gadget address, which includes a nop and then calls another ret which 
    moves forward to chain[1]
        - Point of this is to move RSP up by 8 without affecting state, because RSP must
        be 16-byte aligned
- Executes chain[1], read_int to read GOT address from exploit input 
    - Exploit sends address of puts entry in GOT (known at compile-time), which
    read_int loads into eax 
    - read_int is a full function, so it pushes/cleans up its own stack and calls
    ret, which executes chain[2]
- Executes chain[2], which is the address of an instruction halfway through main to
leak address of puts and start payload 2
    - Instruction moves eax (containing puts GOT entry addr) -> rdi 
    - Next instruction calls puts(), which sends contents of puts GOT entry (so,
    the real libc address of puts) to exploit script
    - Exploit script subtracts known puts offset, and gets libc base 
    - Exploit script builds payload 2, using libc gadgets now available
- main continues executing, exploit script navigates again to gets() to write payload 2
    - Payload delivered to rbp-40, so written to 'pivoted' stack
Stack just after second gets() payload delivery:
```
Original Stack:
high
[--- chain[2]: main puts call addr --] <-- rsp
[------ chain[1]: read_int addr -----] 
[----- chain[0]: nop gadget addr ----]
[----- malicious rbp (0x404e00) -----] 
[------- padding 'A' bytes  ---------|
|------- padding 'A' bytes  ---------|
|-------         ...        ---------| 
|------- padding 'A' bytes  ---------]
low
```

'Pivoted' Stack (Starting at 0x404e00):

``` 
high
[0x404e18] [------- chain2[2]: execv addr ------]
[0x404e1A] [-------- pop rdi value (0x0)  ------]
[0x404e18] [------ chain2[1]: pop_rdi addr -----]
[0x404e10] [-------- pop r13 value (0x0)  ------]
[0x404e0A] [----- pop rbp value (0x404f00)  ----]
[0x404e08] [---- chain2[0]: pop_rbp_r13 addr ---]
[0x404e00] [----- unused rbp (0xdeadbeef) ------] <-- rbp
[0x404df8] [------- padding 'A' bytes  ---------|
[0x404dc0] |------- padding 'A' bytes  ---------|
[0x404dxx] |-------         ...        ---------| 
[0x404dc8] |------- padding 'A' bytes  ---------] <-- new gets() write location
low 
```  
- Exploit keeps navigating after gets(), and again hits end of main
    - main again cleans up
        - sets rsp=rbp 
        - pop rbp, so rsp-=8 and rbp gets 'unused rbp', or 0xdeadbeef
- return pops each gadget from stack, they consume their values
    - set rbp = 0x404f00 (something writeable for libc to use)
    - set r13 and rdi to NULL (for envp and argvp)
- Calls execv("bin/sh") 'one_gadget', now with requirements met

Stack just before execv:
rip=ret in last gadget (chain2[1], pop_rdi)
``` 
high
[0x404f00] [------ blank writeable "stack" -----] <- rbp
...
[0x404e18] [------- chain2[2]: execv addr ------] <-- rsp
[0x404e1A] [-------- pop rdi value (0x0)  ------]
[0x404e18] [------ chain2[1]: pop_rdi addr -----]
[0x404e10] [-------- pop r13 value (0x0)  ------]
[0x404e0A] [----- pop rbp value (0x404f00)  ----]
[0x404e08] [---- chain2[0]: pop_rbp_r13 addr ---]
[0x404e00] [----- unused rbp (0xdeadbeef) ------] 
[0x404df8] [------- padding 'A' bytes  ---------|
[0x404dc0] |------- padding 'A' bytes  ---------|
[0x404dxx] |-------         ...        ---------| 
[0x404dc8] |------- padding 'A' bytes  ---------] <-- second gets() write location
low 
``` 


#### Payload 1
Structure:
```
 | padding | rbp | nop | read_int | puts | main | 
 ```

#### Payload 2
Structure: 
```
| padding | rbp | pop_rbp_r13 | writable addr (rbp) | NULL (r13) | pop_rdi | NULL (rdi) | one_gadget |
```

## Remediation

To patch the vulnerability, `chall.c` should use an alternative to `gets`, which
is almost always insecure. Using a drop-in replacement like `fgets` with a
correct buffer size argument (i.e. `sizeof(world_name) - 1`) would prevent the
buffer overflow entirely. 

Besides this, adding exploit mitigations would make the ROP chain more difficult
to construct (but likely not impossible):
* Stack canaries would prevent the chain from returning into the first gadget without
find another leak primitive to leak the canary value 
* PIE would prevent hardcoding instructions from the code itself into the ROP chain
without another leak primitive


## Configuration Notes

Use container for development:

```bash
docker build -t lactf-minecraft -f Dockerfile
docker run --rm -it -v $(pwd):/ctf lactf-minecraft /bin/tmux
```

Execute solution script against local target in container:

```bash
$ python3 solve.py
[+] Starting local process '/ctf/chall/ld-linux-x86-64.so.2': pid 16
Press enter to start exploit
Building payload 1...
Payload 1 bytes:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00N@\x00\x00\x00\x00\x00\xef\x10@\x00\x00\x00\x00\x00v\x11@\x00\x00\x00\x00\x00C\x12@\x00\x00\x00\x00\x00'
Payload 1 length:  96
Sending first payload...
Navigating to return...
Ret into the payload...
Sending GOT address to leak puts...
Leaked puts address (in libc):  0x7b2386677980
Building payload 2...
Libc base:  0x7b2386600000
pop_rbp_r13_addr:  0x7b23866fea7c
pop_rdi_addr:  0x7b23866277e5
one_gadget_addr:  0x7b23866d511f
Payload 2 bytes:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde\x00\x00\x00\x00|\xeao\x86#{\x00\x00\x00O@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe5wb\x86#{\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1fQm\x86#{\x00\x00'
Payload 2 length:  120
Sending second payload...
Opening shell...
[*] Switching to interactive mode

$ cat chall/flag.txt
THIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAG
$  
```

Execute solution script and start GDB for debugging target locally in
container, writing `pwntools` debugging context to stdout:

```
$ python3 solve.py GDB LOG
```

Execute solution script against remote target (assuming instance running
remotely and `solve.py` includes correct domain/port):

```
python3 solve.py REMOTE
<snip>
$ cat flag.txt
```

# ropfu

## Summary

This challenge provides a Linux CLI program with a stack buffer overflow
vulnerability that is exploited by executing shellcode on the executable
stack. The exploit uses a single ROP gadget to jump into the stack.

**Artifacts:**
* chall/vuln: vulnerable executable program provided by challenge authors
* chall/vuln.c: vulnerable program source code provided by challenge authors
* solve.py: exploit script that executes `/bin/sh` shellcode in the vulnerable
  process
* gadgets.txt: ROP gadgets in `chall/vuln` found by the `ROPgadget` utility
* Dockerfile: container image file configured with the vulnerable program and
  debugging environments to analyze the program and develop the exploit

## Context

The `ropfu` challenge authors provide a domain and port to connect to the
challenge. They also provide a copy of the compiled challenge binary
(`chall/vuln`) and the source code used to produce the binary (`chall/vuln.c`).

`vuln` is a 32-bit x86 Linux userspace program. It runs as a CLI program and
reads input from `stdin` and prints to `stdout`.

The program functions only to prompt the user to enter a line of text,
receive that text, and then exit:

```
$ ./chall/vuln
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
hello
```

The binary is statically compiled without standard exploit mitigations applied:
the stack is *executable* and position independent executable (PIE) settings
are *disabled*. Despite `checksec` reporting that stack canaries are enabled,
later inspection of the vulnerable function shows that *stack canaries are not
checked*.

```
$ file chall/vuln
chall/vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=232215a502491a549a155b1a790de97f0c433482, for GNU/Linux 3.2.0, not stripped

$ checksec chall/vuln
[*] '/home/andreas/ctf/picoctf/pwn/ropfu/chall/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

$ readelf -l chall/vuln
<snip>
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x08048000 0x08048000 0x001e8 0x001e8 R   0x1000
  LOAD           0x001000 0x08049000 0x08049000 0x6a950 0x6a950 R E 0x1000
  LOAD           0x06c000 0x080b4000 0x080b4000 0x2e42d 0x2e42d R   0x1000
  LOAD           0x09a6a0 0x080e36a0 0x080e36a0 0x02c18 0x03950 RW  0x1000
  NOTE           0x000134 0x08048134 0x08048134 0x00044 0x00044 R   0x4
  TLS            0x09a6a0 0x080e36a0 0x080e36a0 0x00010 0x00030 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
  GNU_RELRO      0x09a6a0 0x080e36a0 0x080e36a0 0x01960 0x01960 R   0x1
<snip>
```

## Vulnerability

The `vuln` program contains a stack buffer overwrite vulnerability in the `vuln`
function.

`vuln.c` line 12 contains a call to libc `gets` to read user input from `stdin`:

```
void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return gets(buf);
}
```

The [`gets` manual page](https://man7.org/linux/man-pages/man3/gets.3.html)
warns of the security problems of the `gets` libc function:

> Never use this function.
>
> gets() reads a line from stdin into the buffer pointed to by s
> until either a terminating newline or EOF, which it replaces with
> a null byte ('\0').  No check for buffer overrun is performed

Therefore, an attacker can overwrite the 16 byte stack-allocated `buf` buffer to
write to addresses beyond the buffer. Because `gets` reads until a newline or
EOF, the number of bytes written can be almost arbitrarily large, likely
limited only by the size of the stack segment in memory.

The vulnerability can be confirmed by providing any input of 29 bytes (not
containing newline characters) and observing the program crash.

```
$ ./chall/vuln
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
aaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```

## Exploitation

**Exploit overview**: the exploit uses a local stack buffer overflow to achieve
arbitrary code execution by jumping to attacker-controlled data written to the
executable stack.

**Exploit mitigation considerations**:
* the `vuln` function does not check for a correct stack canary; therefore,
  overwriting the saved return address on the stack is not protected.
* the stack is executable; therefore, any data that the attacker writes to the
  stack can be executed if the `eip` register points to it.
* PIE is disabled; therefore, the addresses of all executable instructions in
  the text segments of the compiled program are fixed and known prior to
  execution. These instruction addresses can be used for gadgets without a
  memory leak.

**Input constraints**: [`\n`]
* The `gets` function reads until a newline character or EOF. Therefore, the
  exploit input cannot contain any newline characters.

**Exploit description**: the `solve.py` exploit sends a single input that both 1)
writes the shellcode into executable process memory and 2) gains control of the
instruction pointer to execute the shellcode.

The saved return address is located on the stack 28 bytes after the start of
the `buf` buffer, where start of the user input is written. Therefore, when the
`vuln` function returns with a `ret` instruction @0x08049dc0, `eip` is set to
bytes 28-32 of the input. We confirm this by sending an input containing 28
bytes of padding followed by the value `0xdeadbeef` (little-ending encoded) to
observe the program crash due to the `eip` register containing the value
`0xdeadbeef`.

```
0                                28         32
[---------------padding---------][efbeaddde]
```

Ideally, we would return directly to the data we wrote to the stack in the
`buf` buffer. However, the address of the stack buffer is not known
_a priori_ due to stack address randomization. To overcome this, we observe
that at the point in program execution immediately before executing the `ret`
instruction in `vuln` (@0x08049dc0), the `eax` register is set to the address
of the `buf` buffer where our inputs are written. Therefore, we can use ROP
gadgets to set `eip` indirectly to the address in `eax`. Fortunately, the
binary contains a `jmp eax` gadget:

```
eax
 |
 V
 0                               28        32
 [--------------padding---------][@JMP-EAX]
```

Now, the vulnerable program will return program execution to the `jmp eax`
gadget and set `eip` to the address of `buf` where our padding values are.
Therefore, we could place our shellcode at the beginning of the input:

```
eax
 |
 V
 0                               28        32
 [shellcode][---padding---------][@JMP-EAX]
```

However, 28 bytes is not a lot of space; the pwntools x86 Linux `/bin/sh`
shellcode is 42 bytes long and will not fit in the padding space. Rather than
trying to minimize the shellcode to squeeze it in, we instead place a single
`jmp` instruction at the beginning of the input that jumps forward 32 bytes (a
trampoline), and then place the full shellcode _after_ the gadget, where we
have no limitation on the size of the shellcode. The only remaining constraint
is that the input cannot contain any newline characters.

```
eax
 |
 V
 0           2                    28        32
 [jmp $+0x20][---padding---------][@JMP-EAX][----shellcode----]
  |                                          ^
  |                                          |
  --------------------------------------------
```

Executing the vulnerable program with this input results in the execution of
a `/bin/sh` shell to read the flag. See the `solve.py` script for proof of
concept.

**Exploit primitives used**:
1. Local stack buffer overwrite to overwrite saved return address
2. Overwrite saved return address to control instruction pointer
3. Control instruction pointer to execute arbitrary code

## Remediation

To patch the vulnerability, the `gets` function call should be replaced with a
size-sensitive function call like `fgets`, and restricted to only read as many
bytes as are allocated:

```
void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return fgets(buf, sizeof buf, stdin);
}
```

Compiling the program with standard exploit mitigations would make the
vulnerability more difficult to exploit:
* a stack canary would prevent turning the local overwrite into instruction
  pointer control.
* PIE would prevent the use of program instructions as ROP gadgets.
* a non-executable stack would prevent the execution of shellcode written to
  the stack.

None of the above mitigations would guarantee that the vulnerability is not
exploitable, but they would have made exploitation more challenging.

We could search programs for more vulnerabilities of this type by conducting a
simple regex search for calls to the `gets` library function.

## Configuration Notes

Use container for development:

```
docker build -t pico-ropfu -f Dockerfile
docker run --rm -it -p $(pwd):/ctf pico-ropfu /bin/bash
```

Execute solution script against local target in container:

```
$ python3 solve.py
<snip>
[+] Starting local process '/ctf/chall/vuln': pid 88
[*] Switching to interactive mode
$ cat chall/flag.txt
THIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAG
```

Execute solution script and start GDB for debugging target locally in
container:

```
# Must start tmux session before script executes.
tmux

python3 solve.py GDB
```

Execute solution script against remote target (ensure that the instance is
running in the picoCTF dashboard and that the URL and port are updated in the
script):

```
python3 solve.py REMOTE
<snip>
$ cat flag.txt
```
