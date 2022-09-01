#!/bin/bash

./performance -f 6 -r 1000 -c 100 -i 100 -t <a-vault-token> -u <vault-url> -b -s -col


# /performance -f 6 -r 1 -c 1 -i 1 --sa "/path/to/sa-key.json"  --u "https://vault.example.com" --vr "encryptor-decryptor-example-iam"  --path example-aead -b -col -p http://proxy.example.com:8000
