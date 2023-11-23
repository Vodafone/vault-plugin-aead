ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
RUN mkdir /vault/plugins

COPY vault-plugin-aead /vault/plugins/vault-plugin-aead
ARG VERSION=${VERSION}
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${VERSION}

RUN chmod +x /vault/plugins/vault-plugin-aead
