FROM europe-west1-docker.pkg.dev/vf-grp-neuronenabler-nonlive/core/hashicorp/vault:1.12.0

RUN mkdir /vault/plugins

COPY vault-plugin-aead /vault/plugins/vault-plugin-aead

RUN chmod +x /vault/plugins/vault-plugin-aead
