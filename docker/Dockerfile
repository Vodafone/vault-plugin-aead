ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
ARG P_VERSION="default"
ENV VERSION_PLUGIN=${P_VERSION}
RUN mkdir /vault/plugins
COPY vault-plugin-aead /vault/plugins/vault-plugin-aead
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${VERSION_PLUGIN}
RUN chmod +x /vault/plugins/vault-plugin-aead
