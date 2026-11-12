.DEFAULT_GOAL := build

.PHONY: build backend-build test test-db frontend-install frontend-build frontend-check frontend-test frontend-dev demo-up demo-test browser-test demo-down client-package fmt
frontend/node_modules/.devctl-dependencies: frontend/package.json frontend/package-lock.json
	npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
	touch $@
frontend-install: frontend/node_modules/.devctl-dependencies
frontend-build: frontend-install
	npm --prefix frontend run build
frontend-check: frontend-install
	npm --prefix frontend run typecheck
	npm --prefix frontend test
frontend-test: frontend-build frontend-check
	npm --prefix frontend run test:ui
frontend-dev: frontend-install
	npm --prefix frontend run dev
build: frontend-build
	$(MAKE) backend-build
backend-build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/devctl ./cmd/devctl
	go build -buildvcs=false -trimpath -o bin/devctld ./cmd/devctld
test: frontend-check
	./scripts/demo-env-test.sh
	./scripts/demo-passwords-test.sh
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
fmt:
	gofmt -w cmd internal tests
