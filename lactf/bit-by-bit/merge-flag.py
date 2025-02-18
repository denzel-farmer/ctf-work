import os
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
import copy
from itertools import product
import random

def download_all_matching_from_bucket(bucket_name, regex_pattern, destination_folder):
    """
    Downloads all files in the given GCP bucket whose names match the regex_pattern.
    
    Parameters:
      bucket_name (str): The name of the GCP bucket.
      regex_pattern (str): The regex pattern to match file names.
      destination_folder (str): Local folder where matching files will be saved.
    """
    # Build the path to your credentials file (assumed to be in the same directory)
    credentials_path = 'gcloud-account.json'
    
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
    matching_blobs = [blob for blob in blobs if pattern.fullmatch(blob.name)]
    with tqdm(total=len(matching_blobs), desc="Downloading files", unit="file") as progress:
        for blob in matching_blobs:
            destination_file_path = os.path.join(destination_folder, os.path.basename(blob.name))
            try:
                time.sleep(0.1)
                blob.download_to_filename(destination_file_path)
                progress.set_postfix_str(f"Downloaded {blob.name}")
            except Exception as e:
                progress.set_postfix_str(f"Failed to download {blob.name}")
                tqdm.write(f"Failed to download {blob.name}: {e}")
                tqdm.write("Continuing")
            found_match = True
            progress.update(1)

    if not found_match:
        print("No files matching the regex were found in the bucket.")

BUCKET_NAME = "microwave-manifests"
STATE_FOLDER = "state-bucket"

def recalculate_flag():
    # exit()
    # Download from bucket 
    flag_lines = []
    state_folder = STATE_FOLDER
    for filename in os.listdir(state_folder):
        if filename.endswith('.txt'):
            with open(os.path.join(state_folder, filename), 'r') as file:
                flag_lines.extend(file.readlines())

    #Also add lines from STATE_FOLDER2 and traverse subdirectories recursively
    state_folder2 = "state"
    for root, dirs, files in os.walk(state_folder2):
        for filename in files:
            if filename.endswith('.txt'):
                with open(os.path.join(root, filename), 'r') as file:
                    flag_lines.extend(file.readlines())


    # strip each line
    flag_lines = [line.strip() for line in flag_lines]

    # Flag line format is num_1:num_2;(bit_index, bit_value)
    bit_dict = {}
    for flag_line in flag_lines:
        # print(flag_line)
        # Split on semicolon; expecting format "num_1:num_2;(bit_index, bit_value)"
        parts = flag_line.split(';')
        if len(parts) < 2:
            continue
        bit_pair = parts[1].strip()  # e.g. "(23, 1)"
        # Remove the surrounding parentheses
        bit_pair = bit_pair.strip("()")
        try:
            index_str, value_str = bit_pair.split(',')
            bit_index = int(index_str.strip())
            bit_value = int(value_str.strip())
            bit_dict[bit_index] = bit_value
        except Exception as e:
            print(f"Error parsing line: {flag_line} -> {e}")

    if not bit_dict:
        print("No bit data found.")
    else:
        print("Bit data:", bit_dict)
        # Print bit_dict sorted by index in ascending order
        # bit_list = []
        # for key in sorted(bit_dict.keys()):
        #     print(f"Index {key}: {bit_dict[key]}")
        #     bit_list.append(bit_dict[key])

        # Length is known to be 296
        # Pad with zeros if necessary
        bit_list = ['X'] * 296
        for i in range(0, 296):
            if i in bit_dict:
                bit_list[i] = bit_dict[i]
            else:
                bit_list[i] = 'X'
        
        # print("Bit list:", bit_list)

        # Convert the list of bits to a bit string
        bit_string = "".join(str(bit) for bit in bit_list)
        # print("Bit string:", bit_string)
        # # Determine the length of our bit vector
        # max_index = max(bit_dict.keys())
        # bit_vector = [0] * (max_index + 1)
        # for idx, val in bit_dict.items():
        #     bit_vector[idx] = val

        # # Build the bit string; the first element is the most significant bit.
        # bit_string = "".join(str(bit) for bit in bit_vector)

        # # Ensure the bit string's length is a multiple of 8 by left-padding with zeros if needed.
        # remainder = len(bit_string) % 8
        # if remainder:
        #     bit_string = "0" * (8 - remainder) + bit_string

        # # Convert every 8 bits to a byte
        # byte_list = []
        # for i in range(0, len(bit_string), 8):
        #     byte_value = int(bit_string[i : i + 8], 2)
        #     byte_list.append(byte_value)
        # byte_data = bytes(byte_list)
        # print("Hex byte list:", [f"0x{b:02x}" for b in byte_data])

        known_ascii_chars = "lactf{"
        # print bits of known ascii char bytes
        for i, c in enumerate(known_ascii_chars):
            known_bits = f"{ord(c):08b}"
            for j, bit in enumerate(known_bits):
                bit_idx = i * 8 + j
                print(f"Bit {bit_idx}: Known bit: {bit} | Discovered: {bit_list[bit_idx]}")

        # Print percent of bit_list that is 'X'
        bit_x_count = bit_list.count('X')
        bit_total_count = len(bit_list)
        bit_x_percent = bit_x_count / bit_total_count * 100

        # Construct bytes
        byte_list = []
        possible_byte_list = []
        print("Length of bit list:", len(bit_list))
        for i in range(0, len(bit_list), 8):
            byte_index = i // 8
            # if byte_index < len(known_ascii_chars):
            #     # If we have a known ASCII character, use it
            #     byte_list.append(ord(known_ascii_chars[byte_index]))
            #     possible_byte_list.append(ord(known_ascii_chars[byte_index]))
            #     continue

            # Otherwise, construct the byte from the bit list
            byte_bits = bit_list[i : i + 8]
            print(f"Byte {byte_index}: {byte_bits}")
            # If any of the bits are 'X', replace with X byte
            if 'X' in byte_bits:

                # Try to recover the byte by testing all replacements of unknown bits.
                possibilities = []
                unknown_positions = [i for i, bit in enumerate(byte_bits) if bit == 'X']

                # Iterate over all possible replacements of 'X' bits
                # 2 ** len(unknown_positions) is the number of possible replacements




                for replacement in range(2 ** len(unknown_positions)):
                    candidate = list(byte_bits)
            
                    bin_str = f"{replacement:0{len(unknown_positions)}b}"
                    for pos, bit_val in zip(unknown_positions, bin_str):
                        candidate[pos] = bit_val
            
                    candidate_val = int("".join(map(str, candidate)), 2)
                #    print(f"Candidate: {candidate} -> {candidate_val}")
                    if 32 <= candidate_val <= 126:  # Check for a printable ASCII character.
                        possibilities.append(candidate_val)
                if len(possibilities) == 1:
                    byte_list.append(possibilities[0])
                    possible_byte_list.append(possibilities[0])
                else:
                    byte_list.append(88)
                    possible_byte_list.append(possibilities)
                continue
            else:
            #input("Press enter to continue")
            # Otherwise, construct byte from bits
                byte_val = int("".join(str(bit) for bit in byte_bits), 2)
                byte_list.append(byte_val)
                possible_byte_list.append(byte_val)

            #byte_str = "".join(str(bit) for bit in bit_list[i : i + 8])
            # byte_list.append(int(byte_str, 2))
        
        # Print the byte list in ascii
        byte_list[21] = ord('u')
        possible_byte_list[21] = ord('u')
        byte_list[22] = ord('s')
        possible_byte_list[22] = ord('s')
        assumption_list = copy.deepcopy(byte_list)
        # print("Recovered ASCII string:", ascii_string)
        #prediction_chars[6] = ord('b')
 
        prediction_chars = copy.deepcopy(possible_byte_list)

        prediction_chars[6] = ord('b')
        assumption_list[6] = ord('b')
        prediction_chars[7] = ord('1')
        assumption_list[7] = ord('1')
        prediction_chars[8] = ord('t')
        assumption_list[8] = ord('t')

        assumption_list[11] = ord('y')
        prediction_chars[11] = ord('y')

        prediction_chars[15] = ord('t')
        assumption_list[15] = ord('t')


        prediction_chars[24] = ord('_')
        assumption_list[24] = ord('_')

        prediction_chars[26] = ord('1')
        assumption_list[26] = ord('1')


        prediction_chars[32] = ord('0')
        assumption_list[32] = ord('0')
        prediction_chars[35] = ord('3')
        assumption_list[35] = ord('3')

        # Print the possible byte list along with known byte if available as ASCII characters
        for i, b in enumerate(possible_byte_list):
            known_char = known_ascii_chars[i] if i < len(known_ascii_chars) else None
            if i == len(byte_list) - 1:
                known_char = '}'
            
            if '_' in possible_byte_list:
                known_char = '_'

            if known_char is not None:
                assumption_list[i] = ord(known_char)
                prediction_chars[i] = ord(known_char)

            # If assumption list type is char, 

            if isinstance(b, list):
                possible_chars = [chr(x) for x in b]
                if len(possible_chars) < 10:
                    print(f"Byte {i}: Known char '{known_char}' | Possible chars: {possible_chars}")
                else:
                    print(f"Byte {i}: Known char '{known_char}' | Possible chars: {possible_chars[:10]} ...")
                
                
            else:
                byte_char = chr(b)
                if known_char is not None:
                    print(f"Byte {i}: Known char '{known_char}' | Char: '{byte_char}'")
                else:
                    print(f"Byte {i}: Char: '{byte_char}'")



        # Print percent of byte_list that is 'X'
        byte_x_count = byte_list.count(88)
        byte_total_count = len(byte_list)
        byte_x_percent = byte_x_count / byte_total_count * 100
        print(f"Percent of byte list that is 'X': {byte_x_percent:.2f}% ({byte_x_count}/{byte_total_count})")
        # Print percent of bit_list that is 'X'
        print(f"Percent of bit list that is 'X': {bit_x_percent:.2f}% ({bit_x_count}/{bit_total_count})")
      
       # print(assumption_list)
        ascii_string = ''.join(chr(b) for b in byte_list)
        print("Recovered ASCII string:", ascii_string)
        assumption_string = ''.join(chr(b) for b in assumption_list)
        print("Recovered ASCII string (assumed):", assumption_string)

        # Print the number of possible strings based on prediction chars
        # Create a dictionary mapping each index to its list of possible characters.
        # If an entry in prediction_chars is an integer, convert it to a character; if it's a list, convert each integer.
        pred_dict = {}
        for idx, entry in enumerate(prediction_chars):
            if isinstance(entry, list):
                pred_dict[idx] = [chr(x) if isinstance(x, int) else x for x in entry]
            else:
                pred_dict[idx] = [chr(entry) if isinstance(entry, int) else entry]

        # Check that we have predictions for a 37-character string.
        if len(pred_dict) != 37:
            print("Warning: Expected prediction mapping for a 37-character string, got", len(pred_dict))

        # Calculate total number of possible strings.
        total = 1
        for chars in pred_dict.values():
            total *= len(chars)

        print("Total possible strings:", total)

        # # Generate and print each possible string.
        # gen_count = 10
        possible_strings = []
        for candidate in product(*[pred_dict[i] for i in range(37)]):
            # if gen_count <= 0:
            #     break
            str_cantidate = "".join(candidate)
            print(str_cantidate)
            possible_strings.append(str_cantidate)
            # gen_count -= 1

        # gen_count = 100
        # sampled = random.sample(possible_strings, min(gen_count, len(possible_strings)))
        # print("\nRandomly sampled strings:")
        # for s in sampled:
        #     print(s)
        # # print("Length of possible strings:", len(possible_strings))


        # Build a mapping from bit index to (num1, num2) by re-parsing the flag lines.
        bit_info = {}
        for line in flag_lines:
            parts = line.split(';')
            if len(parts) < 2:
                continue
            # Parse num1 and num2 from the first part ("num1:num2")
            try:
                num1_str, num2_str = parts[0].split(':')
                num1 = num1_str.strip()
                num2 = num2_str.strip()
            except Exception as e:
                # Skip if num1 and num2 cannot be parsed.
                continue
            bit_pair = parts[1].strip().strip("()")
            try:
                index_str, _ = bit_pair.split(',')
                bit_index = int(index_str.strip())
                bit_info[bit_index] = (num1, num2)
            except Exception as e:
                continue

        # Determine the list of missing bit indices in a 296-bit vector.
        missing_indices = [i for i in range(296) if i not in bit_dict]

        print("\nMissing bit indices:")
        print(missing_indices)

        # For each missing bit index, if the immediately preceding index exists,
        # output that index along with its associated num1 and num2 values.
        found_before_missing = []
        for miss in missing_indices:
            prev = miss - 1
            if prev in bit_info:
                found_before_missing.append((prev, bit_info[prev]))

        print("\nFound bit indices just before a missing index (with num1 and num2):")
        for idx, (num1, num2) in found_before_missing:
            # Skip if idx is lower than 8*len(known_ascii_chars)
            if idx < 8*len(known_ascii_chars):
                continue
            print(f"Bit {idx}: num1={num1}, num2={num2}")
            
            # Appand all num2's to 'key_startpoints.txt'
            with open("key_startpoints.txt", "a") as f:
                f.write(f"{num2}\n")


if len(sys.argv) > 1 and sys.argv[1] == 'redownload':
    print("Downloading directly...")
    subprocess.run(["./download_flags.sh"])
        
print("Recalculating flag...")
recalculate_flag()

if len(sys.argv) > 1 and sys.argv[1] == 'redownload':
    print("Downloading files from bucket...")
    download_all_matching_from_bucket(BUCKET_NAME, r"^.*\.txt$", STATE_FOLDER)

print("Recalculating flag...")
recalculate_flag()

