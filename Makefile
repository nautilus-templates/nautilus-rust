REGISTRY := local
-include .env
ENCLAVE_APP ?= twitter-example
SRC_FILES := $(shell git ls-files src)

.DEFAULT_GOAL := default
.PHONY: default
default: out/nitro.eif

out:
	mkdir -p out

out/nitro.eif: $(SRC_FILES) | out
	@DOCKER_CMD="docker build \
		--tag $(REGISTRY)/enclaveos \
		--platform linux/amd64 \
		--output type=local,rewrite-timestamp=true,dest=out\
		-f Containerfile \
		$(if $(strip $(ENCLAVE_APP)),--build-arg ENCLAVE_APP=$(ENCLAVE_APP)) \
		."; \
		$$DOCKER_CMD;

.PHONY: run
run: out/nitro.eif
	test -f out/nitro.eif || (echo "EIF file not found, please run make first" && exit 1)
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path $(PWD)/out/nitro.eif

.PHONY: run-debug
run-debug: out/nitro.eif
	test -f out/nitro.eif || (echo "EIF file not found, please run make first" && exit 1)
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path $(PWD)/out/nitro.eif \
		--debug-mode \
		--attach-console

.PHONY: update
update:
	./update.sh

.PHONY: stop
stop:
	chmod +x ./reset_enclave.sh
	./reset_enclave.sh