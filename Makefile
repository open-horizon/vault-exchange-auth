SHELL := /bin/bash

# Get Arch for tag and hardware (Golang style) to run test
arch_tag ?= $(shell ./tools/arch-tag)
arch ?= $(arch_tag)
ifeq ($(arch),ppc64el)
	arch := ppc64le
endif

EXECUTABLE := hznvaultauth
DOCKER_INAME := openhorizon/$(arch)_vault
DOCKER_TAG := testing
DOCKER_DEV_OPTS :=  --rm --no-cache --build-arg ARCH=$(arch)

# license file name
export LICENSE_FILE = LICENSE.txt

COMPILE_ARGS ?= CGO_ENABLED=0 GOARCH=amd64 GOOS=linux

ifndef verbose
.SILENT:
endif

all: $(EXECUTABLE)
check: test


clean:
	rm -f ./docker/bin/$(EXECUTABLE)
	-@docker rmi $(DOCKER_INAME):$(DOCKER_TAG)

format:
	@echo "Formatting all Golang source code with gofmt"
	find . -name '*.go' -exec gofmt -l -w {} \;

$(EXECUTABLE): $(shell find . -name '*.go')
	@echo "Producing $(EXECUTABLE) for arch: amd64"
	$(COMPILE_ARGS) go build -o ./docker/bin/$(EXECUTABLE)

vault-image:
	@echo "Handling $(DOCKER_INAME)"
	if [ -n "$(shell docker images | grep '$(DOCKER_INAME)')" ]; then \
		echo "Skipping since $(DOCKER_INAME) image exists, run 'make clean && make' if a rebuild is desired"; \
	else \
		echo "Building container image $(DOCKER_INAME)"; \
		docker build $(DOCKER_DEV_OPTS) -t $(DOCKER_INAME) -f docker/Dockerfile.ubi.$(arch) ./docker && docker tag $(DOCKER_INAME) $(DOCKER_INAME):$(DOCKER_TAG); \
	fi

test:
	@echo "Executing unit tests"
	-@$(COMPILE_ARGS) go test -cover -tags=unit


.PHONY: format