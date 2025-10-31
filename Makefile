SHELL=/bin/bash

test: tests
tests:
	go test -v -race ./...

build:
	@go build -o bin/cryptus ./cmd/cryptus/main.go
