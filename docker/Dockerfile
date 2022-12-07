ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
RUN mkdir /vault/plugins

COPY vault-plugin-aead /vault/plugins/vault-plugin-aead

RUN chmod +x /vault/plugins/vault-plugin-aead
