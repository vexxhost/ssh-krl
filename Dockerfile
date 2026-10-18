# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ssh-krl ./cmd/ssh-krl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ssh-krl /ssh-krl
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ssh-krl"]
