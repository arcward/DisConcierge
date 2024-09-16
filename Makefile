APP_NAME := disconcierge
BUILD_DIR := ./bin
TEST_DIR := ./...
FRONTEND_DIR = ./frontend

export BUILD_PATH = ./build

# New variables for versioning
VERSION := $(shell git describe --tags --always --dirty)
COMMIT_SHA := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u +"%Y-%m-%d_%H:%M:%S")

# Ldflags for version info
LDFLAGS := -X main.Version=$(VERSION) -X main.CommitSHA=$(COMMIT_SHA) -X main.BuildTime=$(BUILD_TIME)


.PHONY: all

.PHONY: install-frontend
install-frontend:
	@echo "Installing frontend/UI dependencies..."
	@cd $(FRONTEND_DIR) && npm install


.PHONY: build-frontend
build-frontend: install-frontend
	@echo "Building frontend..."
	@cd $(FRONTEND_DIR) && npm run build
	@cp -r $(FRONTEND_DIR)/$(BUILD_PATH)/* ./disconcierge/static


.PHONY: test-frontend
test-ui:
	@cd $(FRONTEND_DIR) && npm run test -- --watchAll=false



.PHONY: build
build:
	@echo "Building backend..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)  .


.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(FRONTEND_DIR)/$(BUILD_PATH)
	@rm -rf $(BUILD_DIR)



.PHONY: test
test:
	go test -timeout 240s -v ./...

# New target for displaying version info
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT_SHA)"
	@echo "Build Time: $(BUILD_TIME)"

.PHONY: test-all
test-all: test-frontend test

.PHONY: all
all: build-frontend build