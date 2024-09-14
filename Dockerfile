FROM node:22-alpine AS ui-build

ENV BUILD_PATH=/app/build

WORKDIR /app

COPY ./frontend /app

RUN --mount=type=cache,target=/app/node_modules npm install


ENV PUBLIC_URL=/admin
ENV REACT_APP_API_HOST=https://127.0.0.1
ENV REACT_APP_API_PORT=5000

RUN --mount=type=cache,target=/app/node_modules npm run build

# build the go app
FROM golang:1.22 AS go-build

ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64
ENV GOCACHE=/go/cache
ENV GOPATH=/go

WORKDIR /app

WORKDIR /app/disconcierge

COPY . .

COPY --from=ui-build /app/build /app/disconcierge/disconcierge/static

RUN --mount=type=cache,target=/go/cache go build -o /go/bin/disconcierge

# smaller stage with config
FROM golang:1.22

RUN groupadd --force --gid 65532 disconcierge && \
    useradd --system --uid 65532 --gid 65532 disconcierge
RUN mkdir -p /data
RUN chown -R disconcierge:disconcierge /data

COPY --from=go-build /go/bin/disconcierge /go/bin/disconcierge
COPY ./docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV GIN_MODE=release

ENV PUBLIC_URL=/admin
ENV REACT_APP_API_HOST=https://127.0.0.1
ENV REACT_APP_API_PORT=5000

ENV DC_DATABASE_TYPE=sqlite
ENV DC_DATABASE=/data/disconcierge.sqlite3
ENV DC_DATABASE_SLOW_THRESHOLD="200ms"

ENV DC_DISCORD_TOKEN=""
ENV DC_DISCORD_APPLICATION_ID=""
ENV DC_OPENAI_TOKEN=""
ENV DC_OPENAI_ASSISTANT_ID=""

ENV DC_API_LISTEN=":5000"
ENV DC_API_SECRET=""
ENV DC_API_DEVELOPMENT="true"
ENV DC_API_CORS_ALLOW_ORIGINS=""
ENV DC_API_CORS_ALLOW_METHODS="GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD"
ENV DC_API_CORS_ALLOW_HEADERS="Origin,Content-Length-Content-Type,Accept,Authorization,X-Requested-With,Cache-Control,X-CSRF-Tokens,X-Request-Id"
ENV DC_API_CORS_EXPOSE_HEADERS="Content-Type,Content-Length,Accept-Encoding,X-CSRF-Token,Authorization,X-User-Agent,X-Grpc-Web,X-Request-Id,ETag,Last-Modified"
ENV DC_API_CORS_ALLOW_CREDENTIALS="true"
ENV DC_API_CORS_MAX_AGE="24h"
ENV DC_API_SSL_KEY="/data/cert.key"
ENV DC_API_SSL_CERT="/data/cert.pem"

ENV DC_DISCORD_GUILD_ID=""
ENV DC_DISCORD_NOTIFICATION_CHANNEL_ID=""
ENV DC_STARTUP_TIMEOUT="60s"
ENV DC_SHUTDOWN_TIMEOUT="60s"
ENV DC_RECOVER_PANIC="true"

ENV DC_QUEUE_SIZE="100"
ENV DC_QUEUE_MAX_AGE="3m"
ENV DC_QUEUE_SLEEP_EMPTY="1s"
ENV DC_QUEUE_SLEEP_PAUSED="5s"


ENV DC_LOG_LEVEL="INFO"
ENV DC_OPENAI_LOG_LEVEL="INFO"
ENV DC_DISCORD_LOG_LEVEL="INFO"
ENV DC_API_LOG_LEVEL="INFO"
ENV DC_DATABASE_LOG_LEVEL="INFO"


EXPOSE 5000
VOLUME ["/data"]
USER disconcierge
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/go/bin/disconcierge", "run"]