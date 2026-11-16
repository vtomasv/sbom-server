FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/sbom-server ./cmd/sbom-server \
    && mkdir -p /state && touch /state/.keep

FROM scratch
COPY --from=build /out/sbom-server /sbom-server
COPY --from=build --chown=65532:65532 /state/ /var/lib/sbom-server/
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/sbom-server"]
CMD ["-config", "/etc/sbom/config.json"]
