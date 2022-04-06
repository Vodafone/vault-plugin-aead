FROM eu.gcr.io/vf-grp-neuronenabler-nonlive/vault:1.9.0-ent

RUN mkdir /vault/plugins

COPY vault-plugin-aead /vault/plugins/vault-plugin-aead

RUN chmod +x /vault/plugins/vault-plugin-aead
