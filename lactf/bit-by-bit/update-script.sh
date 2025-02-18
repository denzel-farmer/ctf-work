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

echo "Starting"

# Loop through each IP address concurrently.
max_jobs=25

for ip in $ips; do
  (
    echo "Connecting to VM with IP: $ip"
  
    # SSH into the VM as 'df2817', then use sudo to run a bash session as root.
    # The heredoc (from ENDSSH to ENDSSH) contains the commands to be executed on the remote host.
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -t denzelgfarmer@"$ip" "sudo su root -c 'bash -s'" <<'ENDSSH'
echo $(hostname)
# Print out each command 
# set -x

# Redirect stdout and stderr to out.txt
exec > >(tee -a ~/out2.txt) 2>&1

cd /ctf-work/lactf/bit-by-bit

source /venv/bin/activate

git pull

# kill program that starts with 'python3 start-gcp.py'
kill $(ps aux | grep '[p]ython3 start-gcp.py' | awk '{print $2}')

# Get the hostname, use as first arg of reassemble.py
HOSTNAME=$(hostname)
# Get the first 10 characters of the hostname
nohup python3 start-gcp.py $HOSTNAME > ~/start-gcp.log 2>&1 &
disown
ENDSSH

    if [ $? -ne 0 ]; then
      echo "Error executing commands on $ip"
    fi

    echo "-------------------------------------"
  ) &
  
  # Limit concurrent threads to $max_jobs
  while [ "$(jobs -p | wc -l)" -ge "$max_jobs" ]; do
      sleep 1
  done
done

wait

# Wait for all background processes to complete.
wait

# #!/bin/bash
# # execute_on_vms.sh
# #
# # This script uses the gcloud CLI to list all Compute Engine VMs (with an external IP),
# # then SSHes into each as user 'df2817', escalates privileges to root, and executes 'echo hi'.

# # Retrieve external IP addresses for all VMs that have one.
# # The filter ensures that we only list instances with an external IP.
# ips=$(gcloud compute instances list --filter="EXTERNAL_IP:*" --format="value(EXTERNAL_IP)")

# if [ -z "$ips" ]; then
#   echo "No external IP addresses found. Exiting."
#   exit 1
# fi

# # Loop through each IP address.
# for ip in $ips; do
#   echo "Connecting to VM with IP: $ip"
  
#   # The -t flag forces pseudo-terminal allocation which is often necessary for sudo commands.
#     ssh -t denzelgfarmer@"$ip" "sudo su root -c 'echo hi'" 
  
#   # Check if the ssh command was successful.
#   if [ $? -ne 0 ]; then
#     echo "Error executing command on $ip"
#   fi

#   echo "-------------------------------------"
# # done

# exit
# # Print out each command 
# set -x

# # Redirect stdout and stderr to out.txt
# exec > >(tee -a ~/out2.txt) 2>&1

# cd /ctf-work/lactf/bit-by-bit

# source /venv/bin/activate

# # kill program that starts with 'python3 start-gcp.py'
# kill $(ps aux | grep '[p]ython3 start-gcp.py' | awk '{print $2}')


# # Get the hostname, use as first arg of reassemble.py
# HOSTNAME=$(hostname)
# # Get the first 10 characters of the hostname
# python3 start-gcp.py $HOSTNAME