#!/bin/bash
# execute_on_vms.sh
#
# This script uses the gcloud CLI to list all Compute Engine VMs that have an external IP,
# then SSHes into each as user 'df2817', escalates privileges to root, and executes a set of commands.
#
# Prerequisites:
# - Google Cloud SDK must be installed and configured for your project.
# - SSH keys must be set up for user 'df2817' to access the VMs.
# - The user 'df2817' should be allowed to run "sudo su root" without interactive prompts.

# Retrieve external IP addresses for all VMs that have one.
ips=$(gcloud compute instances list --filter="EXTERNAL_IP:*" --format="value(EXTERNAL_IP)")

if [ -z "$ips" ]; then
  echo "No external IP addresses found. Exiting."
  exit 1
fi

# Loop through each IP address.
max_jobs=500
for ip in $ips; do
    # Wait for available job slot.
    while [ "$(jobs -r | wc -l)" -ge "$max_jobs" ]; do
        sleep 0.1
    done

    (
       # echo "Connecting to VM with IP: $ip"

        mkdir -p state/"$ip"
        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null denzelgfarmer@"$ip":/ctf-work/lactf/bit-by-bit/flag*.txt state/"$ip"/

        if [ $? -ne 0 ]; then
            echo "Error executing commands on $ip"
        fi

       # echo "-------------------------------------"
    ) &
done
wait

#
# python3 start-gcp.py $HOSTNAME