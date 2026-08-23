.PHONY: help build test test-integration test-isolation race lint vet fmt tidy crosscheck vuln secrets db-setup db-drop migrate-up migrate-status migrate-down web demo ci

TEST_DB      ?= statushub_test
TEST_DB_URL  ?= postgres://localhost:5432/$(TEST_DB)?sslmode=disable
MIGRATIONS   := migrations

# Keep in step with .github/workflows/ci.yml so local and CI agree.
GOLANGCI_LINT_VERSION ?= v2.12.2

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

build: ## Compile everything
	go build ./...

web: ## Rebuild the dashboard and stage it for embedding
	cd web && npm install --silent && npm run build
	rm -rf web/embed/dist && cp -r web/dist web/embed/dist

demo: ## End to end in one command: a signed Paystack webhook in, a canonical event out
	@bash scripts/demo.sh

test: ## Unit tests with the race detector (no database needed)
	go test -race ./tests/...

test-integration: db-setup ## Full suite including Postgres integration tests
	STATUSHUB_TEST_DATABASE_URL="$(TEST_DB_URL)" go test -race -coverpkg=./internal/...,./pkg/... ./tests/...

test-isolation: db-setup ## Tenant isolation gate on its own (§8.1)
	STATUSHUB_TEST_DATABASE_URL="$(TEST_DB_URL)" go test -race ./tests/... -run 'Store/TenantIsolation' -v

test-adapters: ## Every adapter against its captured payloads and signature vectors (§11.9)
	go test -race ./tests/... -run 'Adapter' -v

race: ## Race detector only
	go test -race ./tests/...

vet: ## go vet
	go vet ./...

crosscheck: ## Build for the platform CI uses (dev is often arm64, CI is amd64)
	@echo "building linux/amd64"
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=linux GOARCH=amd64 go vet ./...

fmt: ## Format
	gofmt -w .

tidy: ## Tidy modules
	go mod tidy

lint: ## Lint with the same golangci-lint version CI pins
	@command -v golangci-lint >/dev/null 2>&1 || \
		{ echo "installing golangci-lint $(GOLANGCI_LINT_VERSION)"; \
		  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); }
	golangci-lint run ./...

vuln: ## Scan for known vulnerabilities (§8.5)
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

secrets: ## Scan the whole history for committed secrets
	@command -v gitleaks >/dev/null 2>&1 || go install github.com/zricethezav/gitleaks/v8@latest
	gitleaks detect --redact --no-banner -v

db-setup: ## Create the local test database
	@createdb $(TEST_DB) 2>/dev/null || true

db-drop: ## Drop the local test database
	@dropdb --if-exists $(TEST_DB)

sync-migrations: ## Copy migrations/ into the embedded copy the binary ships with
	rm -f internal/migrate/sql/*.sql
	cp $(MIGRATIONS)/*.sql internal/migrate/sql/

migrate-up: ## Apply pending migrations to TEST_DB
	STATUSHUB_DATABASE_URL="$(TEST_DB_URL)" go run ./cmd/statushubctl migrate up

migrate-status: ## What has run against TEST_DB, and what has not
	STATUSHUB_DATABASE_URL="$(TEST_DB_URL)" go run ./cmd/statushubctl migrate status

migrate-down: ## Roll every migration back on TEST_DB, newest first
	@for f in $$(ls $(MIGRATIONS)/*.down.sql | sort -r); do \
		echo "reverting $$f"; \
		psql -q -v ON_ERROR_STOP=1 -d $(TEST_DB) -f $$f || exit 1; \
	done
	@# Clear the ledger too, or the next migrate-up reports "up to date"
	@# against a database with no tables in it.
	@psql -q -d $(TEST_DB) -c "TRUNCATE schema_migrations" 2>/dev/null || true

test-sdks: ## The Node and Python client libraries, against the Go-signed fixtures
	cd sdk/node && npm install --silent && npm run build && node --test test/*.test.js
	cd sdk/python && python3 -m pytest tests/ -q

openapi: ## Regenerate docs/openapi.yaml from the routes
	go run ./cmd/statushubctl openapi --version $$(grep -m1 "version:" docs/openapi.yaml | tr -d " version:\"") --out docs/openapi.yaml

sdk-fixtures: ## Regenerate the signature vectors the client libraries verify against
	go test ./tests -run GenerateSDKFixtures

ci: fmt vet crosscheck lint sync-migrations test-integration test-sdks ## What CI runs
