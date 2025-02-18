from pwn import *

import dns.resolver


# def parse_data_bytes(data_bytes):
#     bytes_string = str(data_bytes)
#     stripped_str = bytes_string[1:-1]
#     str_len = len(stripped_str)

#     if (str_len >= 8):
#        shifted_len = str_len >> 3
#        print("shifted_len: ", shifted_len)

    
#     print(stripped_str)
#     print(str_len)

# def dns_record_extract(base_number):
#     domain = f"{base_number}.rev.lac.tf"
#     result = dns.resolver.resolve(domain, 'TXT')
#     # Print object type
#     print(type(result))
#     # Print type
#     print(result.rdtype)
#     for rdata_text in result:
#         # print((type(rdata)))
#         # data_bytes = bytes(rdata)
#         return rdata_text
    

# if __name__ == "__main__":
#     data_bytes = dns_record_extract(0)
#     parse_data_bytes(data_bytes)

#!/usr/bin/env python3
"""
This program emulates the decompiled C code:
  1. It builds a DNS query name from a “decoded” format string and a pointer value.
  2. It queries the TXT record for that domain.
  3. It expects the TXT record to be in the format: "<n>;<d1>,<d2>"
     - The first token (<n>) is converted to an integer and stored for the next query.
     - The second token is two comma‐separated integers.
  4. It uses d1 to index a secret string (some_flag) and check one bit of that byte.
     If that bit is 1 then d2 must be 1; if 0 then d2 must be 0.
  5. If the check fails, it prints "Incorrect." and exits.
  6. Otherwise, it loops (sleeping 1 second and printing a dot each time).
     When the pointer becomes -1, it prints "Correct!" and exits successfully.
"""

import sys, time
import dns.resolver




# In the real program the “format string” is stored obfuscated.
# Here we simply use a fixed format string.
SLEEP_DELAY = 2
def check_flag(some_flag):
    corr_check = 2124
    while True:
        # Build the domain name (like decode_formatstring + snprintf in C)
        domain = f"{corr_check}.rev.lac.tf"

        try:
            # Query for a TXT record
            answers = dns.resolver.resolve(domain, "TXT")
        except Exception:
            # If the DNS query fails, exit the loop.
            print("QUERY FAILED")
            break

        # Take the first TXT record and join its strings.
        # (dnspython returns a list of byte strings in each TXT record.)
        txt = "".join([s.decode() for s in answers[0].strings])
        print("Record:", txt)

        # Expect the TXT record to be of the form: "<n>;<d1>,<d2>"
        parts = txt.split(";")
        if len(parts) < 2:
            # If the TXT record doesn’t have both parts, just sleep and show progress.
            print("Not all parts found")
            time.sleep(SLEEP_DELAY)
            sys.stdout.write(".")
            sys.stdout.flush()
            continue
        
        # The first token becomes the new pointer.
        try:
            new_corr = int(parts[0])
        except ValueError:
            time.sleep(SLEEP_DELAY)
            sys.stdout.write(".")
            sys.stdout.flush()
            continue
        corr_check = new_corr

        # The second token should contain two numbers separated by a comma.
        try:
            d1_str, d2_str = parts[1].split(",")
            d1 = int(d1_str)
            d2 = int(d2_str)
        except Exception:
            time.sleep(SLEEP_DELAY)
            sys.stdout.write(".")
            sys.stdout.flush()
            continue

        # Now perform the “bit test” on the secret flag.
        if d1 < 8 * len(some_flag):
            # Get the byte from the secret flag at index (d1 >> 3)
            index = d1 >> 3
            flag_char = some_flag[index]
            flag_val = ord(flag_char)
            # The bit to test is bit position (7 - (d1 mod 8)).
            bit_index = 7 - (d1 & 7)
            bit_set = (flag_val >> bit_index) & 1
            # The decompiled code requires:
            #   if the bit is set then d2 must be nonzero,
            #   else (if the bit is clear) then d2 must be zero.
            if bit_set:
                if d2 == 0:
                    print("\nIncorrect.")
                    sys.exit(-1)
            else:
                if d2 == 1:
                    print("\nIncorrect.")
                    sys.exit(-1)
        # End of TXT record processing.
        time.sleep(SLEEP_DELAY)
        sys.stdout.write(".")
        sys.stdout.flush()

        # When the TXT record’s first token is -1 we are done.
        if corr_check == -1:
            print("\nCorrect!")
            sys.exit(0)

    # If we reach here, something went wrong.
    print("\nAn unexpected error occurred.\n", file=sys.stderr)
    sys.exit(-1)


# The secret flag (called some_flag_shuffled_QQ in the decompiled code).
# (In an actual challenge this would be obfuscated or hidden.)
possible_flag = "A"*37

check_flag(possible_flag)