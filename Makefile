.PHONY: all build server client tidy clean

BINARY_DIR := bin

all: tidy build

tidy:
	go mod tidy

build: server client

server:
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/peekport-server ./cmd/server

client:
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/peekport-client ./cmd/client

# Cross-compile for Linux amd64 (VDS target)
server-linux:
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/peekport-server-linux-amd64 ./cmd/server

client-linux:
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/peekport-client-linux-amd64 ./cmd/client

clean:
	rm -rf $(BINARY_DIR)

# Run dev server (HTTP on :8080, no TLS, no API key)
dev-server:
	go run ./cmd/server --dev

# Example scan against localhost dev server
dev-scan:
	go run ./cmd/client scan \
		--server ws://localhost:8080 \
		--target $(TARGET) \
		--mode fast \
		--proto tcp,udp \
		--insecure
