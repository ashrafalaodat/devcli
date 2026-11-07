.PHONY: build test test-db demo-up demo-test demo-down fmt
build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/devctl ./cmd/devctl
	go build -buildvcs=false -trimpath -o bin/devctld ./cmd/devctld
test:
	go test -race ./...
test-db:
	DEVCTL_TEST_DATABASE_URL="$${DEVCTL_TEST_DATABASE_URL:-postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable}" go test -race ./internal/store ./internal/api -count=1
demo-up: build
	./scripts/demo-up.sh
demo-test: build
	./scripts/demo-test.sh
demo-down:
	./scripts/demo-down.sh
fmt:
	gofmt -w cmd internal tests
