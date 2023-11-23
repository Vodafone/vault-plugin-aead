ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
RUN mkdir /vault/plugins
COPY vault-plugin-aead /vault/plugins/vault-plugin-aead
ARG VERSION=${VERSION}
ENV VERSION=${VERSION}
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${VERSION}
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_tttttt
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${FQ_BASE_IMAGE}

RUN chmod +x /vault/plugins/vault-plugin-aead
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_mvbmvmv
