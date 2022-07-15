#!/bin/bash

./performance -f 6 -r 1000 -c 100 -i 100 -t <a-vault-token> -u <vault-url> -b -s -col


# /performance -f 6 -r 1 -c 1 -i 1 --sa "/path/to/sa-key.json"  --u "https://beta-eaas.rubik.vodafone.com" --vr "encryptor-decryptor-common-nonlive-iam"  --path common-nonlive/aead -b -col -p http://vfukukproxy.internal.vodafone.com:8080