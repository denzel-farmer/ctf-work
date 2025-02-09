#!/usr/bin/env python3
import random
import sys
import os
import re
from google.cloud import storage

import subprocess
from google.cloud import storage
import os
import json 
from enum import Enum

import importlib.util
import sys

import platform



import time
import os
import pickle

import dns.resolver

from tqdm import tqdm
import threading


import socket

# First, get the IP address of ns1rev.lac.tf
ns_ip = socket.gethostbyname("ns1rev.lac.tf")

# Create a Resolver instance without loading the system's configuration
resolver = dns.resolver.Resolver(configure=False)

# Set the resolver to use only the desired nameserver
resolver.nameservers = [ns_ip]

resolver_lock = threading.Lock()

SLEEP_DELAY = 1

if len(sys.argv) > 1:
    WORKER_ID = sys.argv[1]
else:
    print("Usage: reassemble.py <worker_id>")
    sys.exit(1)


def run_cmd(cmd: str, silent: bool = False, shell: bool = True, **kwargs) -> int:
    """Runs cmd and returns the status code."""
    return subprocess.run(cmd, shell=shell, capture_output=silent, **kwargs).returncode

# TODO break this out into its own module, and handle credentials correctly
# Upload a file to the google cloud bucket 
def upload_to_bucket(bucket_name, source_path, destination_blob_name):
    
    # This file's directory plus glcoud-account.json
    credentials_path = os.path.join(os.path.dirname(__file__), 'gcloud-account.json')
 
    storage_client = storage.Client.from_service_account_json(credentials_path)
 
    bucket = storage_client.bucket(bucket_name)

    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(source_path)
    
    print(f'File {source_path} uploaded to gs://{bucket_name}/{destination_blob_name}')


def download_from_bucket(bucket_name, source_blob_name, destination_file_name):
    # This file's directory plus glcoud-account.json
    credentials_path = os.path.join(os.path.dirname(__file__), 'gcloud-account.json')
 
    storage_client = storage.Client.from_service_account_json(credentials_path)
 
    bucket = storage_client.bucket(bucket_name)

    blob = bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_name)
    
    print(f'File {source_blob_name} downloaded to {destination_file_name}')
    
    return destination_file_name


def download_all_matching_from_bucket(bucket_name, regex_pattern, destination_folder):
    """
    Downloads all files in the given GCP bucket whose names match the regex_pattern.
    
    Parameters:
      bucket_name (str): The name of the GCP bucket.
      regex_pattern (str): The regex pattern to match file names.
      destination_folder (str): Local folder where matching files will be saved.
    """
    # Build the path to your credentials file (assumed to be in the same directory)
    credentials_path = os.path.join(os.path.dirname(__file__), 'gcloud-account.json')
    
    # Create a storage client using the service account credentials
    storage_client = storage.Client.from_service_account_json(credentials_path)
    bucket = storage_client.bucket(bucket_name)
    
    # Ensure the destination folder exists; if not, create it
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
    
    # Compile the regex pattern
    pattern = re.compile(regex_pattern)
    
    # List all blobs in the bucket
    blobs = bucket.list_blobs()
    
    found_match = False
    for blob in blobs:
        # Use fullmatch to ensure the entire blob name matches the pattern.
        # You could also use pattern.search(blob.name) if you only need a substring match.
        if pattern.fullmatch(blob.name):
            # Construct the local file path (using the basename to avoid creating extra directories)
            destination_file_path = os.path.join(destination_folder, os.path.basename(blob.name))
            blob.download_to_filename(destination_file_path)
            print(f'File {blob.name} downloaded to {destination_file_path}')
            found_match = True

    if not found_match:
        print("No files matching the regex were found in the bucket.")

# Example usag

class QueryCache:
    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.Lock()
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                self.cache = pickle.load(f)
        else:
            self.cache = {}
            self._save()

    def _save(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self.cache, f)

    def query(self, node_id):
        with self.lock:
            return self.cache.get(node_id)

    def save(self, filename=None):
        if filename is None:
            filename = self.filename
        with self.lock:
            self._save(filename)

    def insert(self, node_id, value):
        with self.lock:
            self.cache[node_id] = value
            self._save(self.filename)  
    def merge(self, other_filename):
        with self.lock:
            if os.path.exists(other_filename):
                with open(other_filename, 'rb') as f:
                    other_cache = pickle.load(f)
                    self.cache.update(other_cache)
                    self._save(self.filename)
            else:
                print(f"File {other_filename} does not exist.")

qc_file = f"query_cache_{WORKER_ID}.pkl"
flag_file = f"flag_{WORKER_ID}.txt"
query_cache = QueryCache(qc_file)


BUCKET_NAME = "microwave-manifests"

def upload_state():
    # check if flag file exists
    if os.path.exists(flag_file):
        upload_to_bucket(BUCKET_NAME, flag_file, flag_file)

    query_cache.save("temp_qc_up.pkl")
    upload_to_bucket(BUCKET_NAME, "temp_qc_up.pkl", qc_file)
    os.remove("temp_qc_up.pkl")

def download_state():
    base = "query_cache_"
    ext = ".pkl"
    qc_regex = rf'^{base}.*{ext}$'
    download_all_matching_from_bucket(BUCKET_NAME, qc_regex, ".")

    # Merge all query caches into one
    merge_all()

def merge_all():
    # Merge all query caches into one
    query_cache.merge("query_cache.pkl")
    for filename in os.listdir('.'):
        if filename.startswith("query_cache_") and filename.endswith(".pkl") and filename != qc_file:
            query_cache.merge(filename)

# Every 20 seconds, do git pull, merge, then add/commit/push the query cache
def qc_merge_thread():
    while True:
        time.sleep(20)
        print("Merging query caches...")
        merge_all()
        os.system("git pull")
        os.system(f"git add {qc_file} {flag_file}")
        os.system(f"git commit -m 'update query cache'")
        os.system("git push")

# Launch qc merge thread
t = threading.Thread(target=qc_merge_thread)
t.start()
#print(query_cache.cache)

def print_thread(*args, **kwargs):
    thread_id = threading.get_ident()
    with threading.Lock():
        print(f"[{thread_id}] ", end="")
        print(*args, **kwargs)

def query(node_id):
        # Check the cache first
        cached = query_cache.query(node_id)
        if cached is not None:
            return cached

        # Build the domain name (like decode_formatstring + snprintf in C)
        domain = f"{node_id}.rev.lac.tf"
    
        try:
            # Query for a TXT record
            with resolver_lock:
                answers = resolver.resolve(domain, "TXT")
        except dns.resolver.NXDOMAIN:
            # If the domain does not exist, cache None and return
            print_thread(f"DOMAIN DOES NOT EXIST: {domain}")
            query_cache.insert(node_id, (None, None))
            return None, None
        except dns.resolver.NoNameservers:
            # If the DNS query fails due to SERVFAIL, retry up to 10 times
            retries = 10
            while retries > 0:
                print_thread(f"QUERY FAILED (SERVFAIL), retrying... ({10 - retries + 1}/10)")
                time.sleep(SLEEP_DELAY)
                try:
                    with resolver_lock:
                        answers = resolver.resolve(domain, "TXT")
                    break
                except dns.resolver.NoNameservers:
                    retries -= 1
            if retries == 0:
                print_thread(f"QUERY FAILED AFTER 10 RETRIES")
                return None, None
        except Exception as e:
            # If the DNS query fails for other reasons, print the exception and return
            print_thread(f"QUERY FAILED: {e}")
            return None, None
    
        # Take the first TXT record and join its strings.
        # (dnspython returns a list of byte strings in each TXT record.)
        txt = "".join([s.decode() for s in answers[0].strings])
     #   print_thread("Record:", txt)

        # Expect the TXT record to be of the form: "<n>;<d1>,<d2>"
        next_node_id = None
        bit_data = None
        parts = txt.split(";")
        # Strip parts of empty strings
        parts = [p for p in parts if p]
     #   print_thread("Parts:", parts)
        if len(parts) > 0:
            # record only has first part
            next_node_id = int(parts[0])

        if len(parts) > 1:
            # record has both parts
            d1_str, d2_str = parts[1].split(",")
            bit_data = (int(d1_str), int(d2_str))
            print_thread("FOUND BIT DATA")
            # Append bit data line to "flag.txt" or create it if it doesn't exist
            with open(flag_file, "a") as f:
                f.write(f"{node_id}:{next_node_id};{bit_data}\n")
        
        # Cache the result
        query_cache.insert(node_id, (next_node_id, bit_data))

        # Sleep to avoid rate-limiting
        time.sleep(SLEEP_DELAY) 

        return next_node_id, bit_data


# # --- Global cache for query results -----------------------
# # So we never re-query a node.
# cache = {}
# def cached_query(node_id):
#     if node_id in cache:
#         return cache[node_id]
#     res = query(node_id)
#     cache[node_id] = res
#     return res

# --- Exception for hitting the end of the list -------------
class EndOfList(Exception):
    pass

jump = {}
def jump_ahead(node, steps, pbar=None):
    """
    Starting from 'node', follow 'steps' next pointers.
    Uses caching to speed up repeated calls.
    
    An optional tqdm progress bar (pbar) is used to track progress.
    If no pbar is passed, a new one is created for this call.
    
    Raises EndOfList if the end is reached before taking all steps.
    """
    # If no progress bar was provided, create one for this call.
    if pbar is None:
        with tqdm(total=steps, desc=f"Jumping ahead {steps} steps", leave=False) as new_pbar:
            return jump_ahead(node, steps, pbar=new_pbar)

    # Base case: zero steps.
    if steps == 0:
        return node

    # Check for cached result.
    key = (node, steps)
    if key in jump:
        # If returning a cached result, we simulate that the progress was made.
        # (Note: cached calls do not update the progress bar from the actual queries.)
        pbar.update(steps)
        return jump[key]

    # Base case: one step.
    if steps == 1:
        nxt, _ = query(node)
        pbar.update(1)
        if nxt is None:
            raise EndOfList
        jump[key] = nxt
        return nxt

    # Recursive case: split the jump into two parts.
    half = steps // 2
    rem  = steps - half
    mid = jump_ahead(node, half, pbar)
    nxt = jump_ahead(mid, rem, pbar)
    jump[key] = nxt
    return nxt

# --- Finding the length of the linked list ---------------
def find_length():
    """
    Use exponential search to get an upper bound on the number of nodes,
    then binary search to pinpoint the exact length. During the binary
    search, print a progress bar (percentage complete) based on how much the
    search interval has been reduced.
    """
    # Exponential search: double pos until we hit the end.
    pos = 1
    while True:
        try:
            jump_ahead(0, pos)
            pos *= 2
        except EndOfList:
            break

    # Binary search between pos//2 and pos.
    lo = pos // 2
    hi = pos
    initial_range = hi - lo
    # We'll update progress based on the reduction in range size.
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            jump_ahead(0, mid)
            lo = mid + 1
        except EndOfList:
            hi = mid
        # Calculate progress: when the search range goes from initial_range to 0,
        # we consider that 100% complete.
        progress = 100 * (1 - (hi - lo) / initial_range)
        print_thread(f"Finding length: {progress:6.2f}% complete (range size: {hi - lo})", end="\r", file=sys.stderr)
    # When finished, print a newline so subsequent output isn’t overwritten.
    print_thread(file=sys.stderr)
    return lo

# --- Main flag–recovery function ---------------------------
def get_flag():
    """
    Repeatedly sample random positions in the list and then sweep a few nodes
    in order to catch the rare nodes that contain flag–data.
    Once all 296 bits (flag bits 0 to 295) are found, reassemble them into
    a 37-byte ASCII string.
    """
    # Dictionary mapping bit_index -> bit_value
    flag_bits = {}
    total_flag_bits = 296  # 37 bytes
    L = total_flag_bits * 8450 # find_length()
    print_thread("Estimated list length =", L, file=sys.stderr)
    trials = 0

    # Continue until we have every bit.
    while len(flag_bits) < total_flag_bits:
        # Pick a random starting position in the list.
        pos = random.randint(0, max(L - 100, 0))
        try:
            node = jump_ahead(0, pos)
        except EndOfList:
            continue

        # From this starting point, sweep forward 100 nodes.
        for i in range(100):
            try:
                nxt, bit_data = query(node)
            except Exception:
                break
            if bit_data is not None:
                bit_index, bit_value = bit_data
                if bit_index not in flag_bits:
                    flag_bits[bit_index] = bit_value
                    print_thread(f"Found bit {bit_index} = {bit_value} (after {trials} trials)", file=sys.stderr)
                    # If we have all bits, stop.
                    if len(flag_bits) == total_flag_bits:
                        break
            if nxt is None:
                break
            node = nxt
            trials += 1

    # Reassemble the 296 bits into a binary string.
    flag_bin = ''.join(str(flag_bits[i]) for i in range(total_flag_bits))
    # Convert every 8 bits into a character.
    flag_chars = []
    for i in range(0, total_flag_bits, 8):
        byte = flag_bin[i:i+8]
        flag_chars.append(chr(int(byte, 2)))
    return ''.join(flag_chars)

# Run a thread that starts running at a random index up to 9000 steps 
def random_thread():
    # Start at a random index from 0 to 10^7
    start_index = random.randint(0, 10**7)
    print_thread("Starting at index", start_index)
    # Query until sequence value found
    while True:
        next_node, _ = query(start_index)
        if next_node is not None:
            start_index = next_node
            break

        start_index += 1

    print_thread("Found next node", start_index)
    num_steps = 0
    curr_node = start_index
    with tqdm(total=9000, desc="Random thread progress", leave=False) as pbar:
        while num_steps < 9000:
            next_node, bit_info = query(curr_node)
            if bit_info is not None:
                print_thread("Found bit info at ", curr_node, ":", bit_info)
                return
            num_steps += 1
            curr_node = next_node
            pbar.update(1)

def launch_threads(count=2):
    def thread_wrapper():
        while True:
            print_thread("Starting thread...")
            random_thread()
            print_thread("Thread finished.")

    for _ in range(count):
        t = threading.Thread(target=thread_wrapper)
      #  t.daemon = True
        t.start()

# --- Main --------------------------------------------------
if __name__ == '__main__':

    random.seed(43 + WORKER_ID)
    launch_threads(3)

    # flag = get_flag()
    # print("FLAG:", flag)
