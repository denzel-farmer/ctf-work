import time

import dns.resolver

def scan_subdomains():
    resolver = dns.resolver.Resolver()
    for i in range(10**7):
        subdomain = f"{i}.rev.lac.tf"
        try:
            answers = resolver.resolve(subdomain, 'TXT')
            for rdata in answers:
                print(f"{subdomain}: {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            print(f"{subdomain}: No TXT record found")
        except dns.resolver.NXDOMAIN:
            print(f"{subdomain}: Domain does not exist")
        except Exception as e:
            print(f"{subdomain}: Error - {e}")
        time.sleep(1)

if __name__ == "__main__":
    scan_subdomains()