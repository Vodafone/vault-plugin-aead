ARG REPO_PROJECT 
FROM europe-west1-docker.pkg.dev/${REPO_PROJECT}/core/hashicorp/vault-enterprise:1.12-ent
RUN mkdir /vault/plugins

COPY vault-plugin-aead /vault/plugins/vault-plugin-aead

RUN chmod +x /vault/plugins/vault-plugin-aead
