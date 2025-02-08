from pwn import *
import subprocess

# Call the decode_now script
subprocess.run(['gcc', 'decode_now.c', '-o', 'decode_now'])
subprocess.run(['gcc', 'my_eye.c', '-o', 'my-eye'])
# # Connect to the server
conn = remote('chall.lac.tf', 31313)
# conn = process("./the-eye")

# Read the output
output = conn.recvall().decode()

# Write the output to encoded.txt
with open('encoded.txt', 'w') as f:
    f.write(output)

# Close the connection
conn.close()


# Call the decode_now script
subprocess.run(['./decode_now'])