.PHONY: build test clean install

# Build the check-secrets binary for the current platform
build:
	cd scripts && go build -o check-secrets .

# Run all tests with race detection and coverage
test:
	cd scripts && go test -v -race -cover ./...

# Remove build artifacts
clean:
	rm -f scripts/check-secrets

# Build and verify (build + test)
install: build test
