FROM node:20.17.0 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y --no-install-recommends curl
RUN curl -sL -o /usr/local/bin/circom https://github.com/iden3/circom/releases/download/v2.1.9/circom-linux-amd64 && chmod +x /usr/local/bin/circom
WORKDIR /app
RUN yarn set version 4.0.2
COPY . .
RUN yarn
RUN yarn setup && yarn build
WORKDIR /app/examples/demo-app/core
RUN yarn

FROM node:20.17.0-bookworm-slim

ENV PATH="$PATH:/app/node_modules/.bin:/app/examples/demo-app/core/node_modules/.bin"
USER node
WORKDIR /app
COPY --chown=node:node --from=build /app/examples/demo-app /app/examples/demo-app
COPY --chown=node:node --from=build /app/node_modules /app/node_modules
COPY --chown=node:node --from=build /app/upa/dist /app/upa/dist
COPY --chown=node:node --from=build /app/upa/package.json /app/upa/package.json
ENTRYPOINT ["demo-app"]
