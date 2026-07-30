# ========================================================
# Stage: Frontend (Vite)
# ========================================================
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
COPY internal/web/translation /src/internal/web/translation
RUN npm run build

# ========================================================
# Stage: Builder
# ========================================================
FROM golang:1.26-alpine AS builder
WORKDIR /app
ARG TARGETARCH

RUN apk --no-cache --update add \
  build-base \
  gcc \
  curl \
  unzip

COPY . .
COPY --from=frontend /src/internal/web/dist ./internal/web/dist

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"
RUN go build -ldflags "-w -s" -o build/primevpn main.go
RUN ./packaging/docker/init.sh "$TARGETARCH"

# ========================================================
# Stage: Final Image of PRIMEVPN
# ========================================================
FROM alpine
ENV TZ=Asia/Tehran
WORKDIR /app

RUN apk add --no-cache --update \
  ca-certificates \
  tzdata \
  bash \
  curl \
  openssl

COPY --from=builder /app/build/ /app/
COPY --from=builder /app/packaging/docker/entrypoint.sh /app/entrypoint.sh
COPY --from=builder /app/primevpn.sh /usr/bin/primevpn
COPY --from=builder /app/internal/web/translation /app/internal/web/translation


RUN chmod +x \
  /app/entrypoint.sh \
  /app/primevpn \
  /usr/bin/primevpn

ENV XUI_IN_DOCKER="true"
ENV XUI_MAIN_FOLDER="/app"
ENV XUI_DB_TYPE=""
ENV XUI_DB_DSN=""
EXPOSE 2053
VOLUME [ "/etc/primevpn" ]
CMD [ "./primevpn" ]
ENTRYPOINT [ "/app/entrypoint.sh" ]
