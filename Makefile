.PHONY: lint test-unit test-integration

lint:
	golangci-lint run ./...

test-unit:
	go test -skip '^Test(Integration|Hardware)' ./...

test-integration:
	go test -run '^TestIntegration' ./...
