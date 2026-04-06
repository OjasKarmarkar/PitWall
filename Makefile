.PHONY: run build test bench clean

# Load .env automatically if it exists (make run, make build, etc.)
ifneq (,$(wildcard .env))
  include .env
  export
endif

## run: start the server (reads .env automatically)
run:
	go run .

## build: compile a single binary called `pitwall`
build:
	go build -o pitwall .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o pitwall .

## test: run all unit tests
test:
	go test ./...

## bench: run the benchmarks with memory stats
bench:
	go test -bench=. -benchmem -benchtime=3s ./...

## clean: remove compiled binary
clean:
	rm -f pitwall
