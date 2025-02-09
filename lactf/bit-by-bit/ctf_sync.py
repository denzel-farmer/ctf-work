
import subprocess
from google.cloud import storage
import os
import json 
from enum import Enum

import importlib.util
import sys

import platform






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
