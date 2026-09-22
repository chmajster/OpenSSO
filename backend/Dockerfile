FROM golang:1.25.13-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/opensso ./cmd/opensso
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/opensso-healthcheck ./cmd/healthcheck

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opensso /opensso
COPY --from=build /out/opensso-healthcheck /opensso-healthcheck
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/opensso"]
