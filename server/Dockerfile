# syntax=docker/dockerfile:1
FROM golang:1.23 AS build
WORKDIR /src

# Copy crypto package first
COPY pkg/crypto/ ./pkg/crypto/

# Copy server files
COPY server/ ./server/

# Build the server from server directory
WORKDIR /src/server
RUN go mod download && CGO_ENABLED=0 GOOS=linux go build -o server .

FROM gcr.io/distroless/base-debian12
ENV PORT=8080
ENV GEOIP_DB_PATH=/geolite/GeoLite2-City.mmdb
COPY --from=build /src/server/server /server
COPY --from=build /src/server/geolite/ /geolite/
USER nonroot:nonroot
ENTRYPOINT ["/server"]