BINARY := bin/check-secrets
GOFLAGS := -trimpath -ldflags="-s -w"

.PHONY: build test cover clean install

build:
	cd scripts && go build $(GOFLAGS) -o ../$(BINARY) .

test:
	cd scripts && go test -v -race ./...

cover:
	cd scripts && go test -cover ./...

clean:
	rm -f $(BINARY)
	rm -f scripts/check-secrets

install: build test
