ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
ARG FQ_BASE_IMAGE
ARG VERSION
ENV FQ_BASE_IMAGE=${FQ_BASE_IMAGE}
ENV SOME_ENV_VAR_NAME=${FQ_BASE_IMAGE}
ENV VERSION_PLUGIN=${VERSION}
RUN echo "o-${VERSION_PLUGIN}" 
RUN echo "h-${VERSION}" 
RUN echo "y-${SOME_ENV_VAR_NAME}" 

RUN mkdir /vault/plugins
COPY vault-plugin-aead /vault/plugins/vault-plugin-aead
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${VERSION_PLUGIN}
RUN chmod +x /vault/plugins/vault-plugin-aead
