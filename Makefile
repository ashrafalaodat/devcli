.PHONY: build test test-db demo-up demo-test browser-test demo-down client-package plugin-package fmt
build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/devctl ./cmd/devctl
	go build -buildvcs=false -trimpath -o bin/devctld ./cmd/devctld
	go build -buildvcs=false -trimpath -o bin/kubectl-devctl ./cmd/kubectl-devctl
test:
	./scripts/demo-env-test.sh
	go test -race ./...
test-db:
	DEVCTL_TEST_DATABASE_URL="$${DEVCTL_TEST_DATABASE_URL:-postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable}" go test -race ./internal/store ./internal/api ./internal/browser -count=1
demo-up: build
	./scripts/demo-up.sh
demo-test: build
	./scripts/demo-test.sh
browser-test: build
	./scripts/browser-test.sh
demo-down:
	./scripts/demo-down.sh
client-package: build
	./scripts/package-client.sh
plugin-package: build
	./scripts/package-plugin.sh
fmt:
	gofmt -w cmd internal tests
