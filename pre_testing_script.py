#### IMPORTANT !!!
# 
# PLEASE REMEMBER ABOUT CHANGING SECRET_ID AND ROLE_ID in testingutils.go when you run tests locally###### 
#
#
####
import subprocess
import json
import requests
import os

# Setup environment for local vault with root token
local_env = os.environ.copy()
local_env['VAULT_ADDR'] = 'http://localhost:8200'
local_env['VAULT_TOKEN'] = 'root'

subprocess.run(["vault", "secrets", "enable", "-path=aead-secrets/aead", "vault-plugin-aead"], env=local_env)

subprocess.run(["vault", "auth", "enable", "approle"], env=local_env)

subprocess.run(["vault", "secrets", "enable", "transit"], env=local_env)


# Create a policy from policy.json
subprocess.run(["vault", "policy", "write", "my-policy", "./policy.json"], env=local_env)
subprocess.run(["vault", "write", "auth/approle/role/my-approle", "token_policies=my-policy"], env=local_env)

# Retrieve and save the role_id
result = subprocess.run(["vault", "read", "-field=role_id", "auth/approle/role/my-approle/role-id"], capture_output=True, text=True, env=local_env)
role_id = result.stdout.strip()

# Generate and save the secret_id
result = subprocess.run(["vault", "write", "-f", "-field=secret_id", "auth/approle/role/my-approle/secret-id"], capture_output=True, text=True, env=local_env)
secret_id = result.stdout.strip()

# Write the transit key
subprocess.run(["vault", "write", "-f", "transit/keys/my-key"], env=local_env)
# Make a cURL request with the saved role_id and secret_id
url = "http://localhost:8200/v1/aead-secrets/aead/config"
headers = {
    "Accept": "*/*",
    "User-Agent": "Thunder Client (https://www.thunderclient.com)",
    "X-Vault-Token": "root",
    "Content-Type": "application/json"
}
data = {
    "VAULT_KV_SECRET_ID": secret_id,
    "VAULT_KV_APPROLE_ID": role_id,
    "VAULT_KV_URL": "http://localhost:8200",
    "VAULT_KV_ENGINE": "secret",
    "VAULT_KV_WRITER_ROLE": "my-approle",
    "VAULT_KV_VERSION": "v2",
    "VAULT_TRANSIT_KEK": "aead-secrets",
    "VAULT_TRANSIT_APPROLE_ID": role_id,
    "VAULT_TRANSIT_APPROLE_NAME": "my-approle",
    "VAULT_TRANSIT_KV_ENGINE" : "transit",
    "VAULT_TRANSIT_SG_IAM_ROLE_NAME" : "aead-secrets-transit-reader-secretgenerator-iam",
    "VAULT_TRANSIT_URL": "http://localhost:8200",
    "VAULT_KV_ACTIVE": "true",
    "VAULT_KV_LOCAL": "true"
}

response = requests.post(url, headers=headers, json=data)

print("Response:")
print(response.text)

