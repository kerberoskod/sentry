.PHONY: build test clean

build:
	go build -o bin/sentry .

test:
	go test ./... -v -count=1

clean:
	rm -rf bin/
