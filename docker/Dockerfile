ARG VERSION
ARG FQ_BASE_IMAGE 
FROM ${FQ_BASE_IMAGE}
ARG FQ_BASE_IMAGE
ENV FQ_BASE_IMAGE=${FQ_BASE_IMAGE}
ENV SOME_ENV_VAR_NAME=${FQ_BASE_IMAGE}

RUN echo "g-${FQ_BASE_IMAGE}" 
RUN echo "ju-${FQ_BASE_IMAGE}" 

ENV VERSION_PLUGIN=${VERSION}
RUN echo "o-${VERSION_PLUGIN}" 

RUN mkdir /vault/plugins
COPY vault-plugin-aead /vault/plugins/vault-plugin-aead
ARG VERSION
ENV VERSION_PLUGIN=${VERSION}
ENV SOME_ENV_VAR_NAME=${FQ_BASE_IMAGE}
RUN echo "x-${VERSION_PLUGIN}" 
RUN echo "y-${VERSION}" 
RUN echo "g-${FQ_BASE_IMAGE}" 
RUN echo "j-${SOME_ENV_VAR_NAME}" 
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${VERSION_PLUGIN}
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_tttttt
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_${SOME_ENV_VAR_NAME}


RUN chmod +x /vault/plugins/vault-plugin-aead
RUN ln -s /vault/plugins/vault-plugin-aead /vault/plugins/vault-plugin-aead_mvbmvmv
