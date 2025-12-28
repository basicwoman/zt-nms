.PHONY: all build test clean docker docker-push lint fmt deps run-api help

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-w -s -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"
GOBIN := $(shell go env GOPATH)/bin

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Directories
BIN_DIR := bin
CMD_DIR := cmd

# Binaries
API_GATEWAY := $(BIN_DIR)/api-gateway
CLI := $(BIN_DIR)/zt-nms-cli
AGENT := $(BIN_DIR)/zt-nms-agent

# Docker
DOCKER_REGISTRY ?= ghcr.io/zt-nms
DOCKER_TAG ?= $(VERSION)

all: deps build test

help:
	@echo "Zero Trust NMS - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make deps        - Download dependencies"
	@echo "  make build       - Build all binaries"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run linter"
	@echo "  make fmt         - Format code"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make docker      - Build Docker images"
	@echo "  make docker-push - Push Docker images"
	@echo "  make run-api     - Run API gateway locally"
	@echo "  make dev         - Start development environment"
	@echo "  make db-migrate  - Run database migrations"
	@echo "  make generate    - Generate code (protobuf, mocks)"
	@echo ""

deps:
	$(GOMOD) download
	$(GOMOD) tidy

build: $(API_GATEWAY) $(CLI) $(AGENT)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(API_GATEWAY): $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $@ ./$(CMD_DIR)/api-gateway

$(CLI): $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $@ ./$(CMD_DIR)/zt-nms-cli

$(AGENT): $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $@ ./$(CMD_DIR)/zt-nms-agent

test:
	$(GOTEST) -v -race -cover ./...

test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

bench:
	$(GOTEST) -bench=. -benchmem ./...

lint:
	$(GOLINT) run ./...

fmt:
	$(GOFMT) -s -w .

clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

# Docker targets
docker: docker-api docker-cli docker-agent

docker-api:
	docker build -t $(DOCKER_REGISTRY)/api-gateway:$(DOCKER_TAG) \
		--build-arg SERVICE=api-gateway \
		-f deployments/docker/Dockerfile .

docker-cli:
	docker build -t $(DOCKER_REGISTRY)/zt-nms-cli:$(DOCKER_TAG) \
		--build-arg SERVICE=zt-nms-cli \
		-f deployments/docker/Dockerfile .

docker-agent:
	docker build -t $(DOCKER_REGISTRY)/zt-nms-agent:$(DOCKER_TAG) \
		--build-arg SERVICE=zt-nms-agent \
		-f deployments/docker/Dockerfile .

docker-push:
	docker push $(DOCKER_REGISTRY)/api-gateway:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/zt-nms-cli:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/zt-nms-agent:$(DOCKER_TAG)

# Development
run-api:
	$(GOBUILD) -o $(API_GATEWAY) ./$(CMD_DIR)/api-gateway
	./$(API_GATEWAY)

dev:
	cd deployments/docker && docker-compose up -d postgres redis nats etcd
	@echo "Waiting for services to start..."
	sleep 5
	@echo "Development environment ready!"
	@echo "Database: localhost:5432"
	@echo "Redis: localhost:6379"
	@echo "NATS: localhost:4222"

dev-down:
	cd deployments/docker && docker-compose down

dev-full:
	cd deployments/docker && docker-compose up -d
	@echo "Full environment started!"
	@echo "API Gateway: https://localhost:8080"
	@echo "Grafana: http://localhost:3000"
	@echo "Jaeger: http://localhost:16686"

# Database
db-migrate:
	@echo "Running database migrations..."
	PGPASSWORD=$${POSTGRES_PASSWORD:-ztnms_secret} psql -h localhost -U ztnms -d ztnms -f deployments/database/schema.sql

db-reset:
	@echo "Resetting database..."
	PGPASSWORD=$${POSTGRES_PASSWORD:-ztnms_secret} psql -h localhost -U ztnms -d postgres -c "DROP DATABASE IF EXISTS ztnms"
	PGPASSWORD=$${POSTGRES_PASSWORD:-ztnms_secret} psql -h localhost -U ztnms -d postgres -c "CREATE DATABASE ztnms"
	$(MAKE) db-migrate

# Code generation
generate:
	$(GOCMD) generate ./...

# Key generation
keygen:
	@mkdir -p keys
	./$(CLI) keygen keys/operator
	./$(CLI) keygen keys/device
	./$(CLI) keygen keys/service
	@echo "Keys generated in keys/ directory"

# Install tools
tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/golang/mock/mockgen@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Release
release: clean deps lint test build docker
	@echo "Release $(VERSION) ready!"
