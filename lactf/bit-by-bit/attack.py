from pwn import *

import dns.resolver

def get_dns_rr_hex(domain):
    try:
        # Perform DNS query
        answers = dns.resolver.resolve(domain, 'A')
        print(answers)
        for rdata in answers:
            # Convert the response to hex
            rr_hex = rdata.to_text().encode('utf-8').hex()
            print(f"Hex of RR struct for {domain}: {rr_hex}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    domain = "0.rev.lac.tf"
    get_dns_rr_hex(domain)