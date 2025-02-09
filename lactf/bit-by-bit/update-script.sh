#!/bin/bash

# Print out each command 
set -x

# Redirect stdout and stderr to out.txt
exec > >(tee -a ~/out2.txt) 2>&1

cd /ctf-work/lactf/bit-by-bit

source /venv/bin/activate

# kill program that starts with 'python3 start-gcp.py'
kill $(ps aux | grep '[p]ython3 start-gcp.py' | awk '{print $2}')


# Get the hostname, use as first arg of reassemble.py
HOSTNAME=$(hostname)
# Get the first 10 characters of the hostname
python3 start-gcp.py $HOSTNAME