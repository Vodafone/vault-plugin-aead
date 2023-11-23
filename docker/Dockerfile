ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
RUN mkdir /vault/plugins
COPY vault-plugin-aead /vault/plugins/vault-plugin-aead
ARG VERSION
ENV VERSION_PLUGIN=${VERSION}
ENV SOME_ENV_VAR_NAME=${FQ_BASE_IMAGE}
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${VERSION_PLUGIN}
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_tttttt
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${SOME_ENV_VAR_NAME}
RUN "echo ${VERSION_PLUGIN}" 
RUN "echo ${VERSION}" 

RUN chmod +x /vault/plugins/vault-plugin-aead
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_mvbmvmv
