SHELL=/bin/bash

test: tests
tests:
	go test -v -race ./...
