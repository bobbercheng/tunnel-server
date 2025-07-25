# syntax=docker/dockerfile:1
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./main.go

FROM gcr.io/distroless/base-debian12
ENV PORT=8080
COPY --from=build /src/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]