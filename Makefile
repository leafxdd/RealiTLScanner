.PHONY: build test docker clean

build:
	go build -o RealiTLScanner ./cmd/realitlscanner

test:
	go test -race ./... -count=1

vet:
	go vet ./...

docker:
	docker build -t realitlscanner .

clean:
	rm -f RealiTLScanner RealiTLScanner.exe
