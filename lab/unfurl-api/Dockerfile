ARG NODE_IMAGE=node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5
FROM ${NODE_IMAGE}

LABEL org.opencontainers.image.title="Node2Shell unfurl API lab"
LABEL org.opencontainers.image.description="Affected Node.js v24.22.0 link unfurl API"
LABEL org.opencontainers.image.version="24.22.0"
LABEL org.opencontainers.image.source="https://github.com/Delvin-45/node2shell-lab-poc"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY --chown=node:node src/package*.json ./
RUN npm ci --omit=dev
COPY --chown=node:node src/ ./
COPY --chown=node:node scripts/supervise.sh /usr/local/bin/node2shell-supervise
RUN chmod 0755 /usr/local/bin/node2shell-supervise

ENV N2S_PORT=3000
ENV N2S_SUPERVISE=0
EXPOSE 3000
USER node
CMD ["/usr/local/bin/node2shell-supervise"]
