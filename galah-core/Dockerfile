FROM golang:latest
WORKDIR /galah
COPY . .
RUN <<EOF
go mod download
go build -o galah-app ./cmd/galah
EOF
ENTRYPOINT ["./galah-app"]