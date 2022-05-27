ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# PHONY means that it doesn't correspond to a file; it always runs the build commands.

.PHONY: build
build: build-use-dkg build-verify

.PHONY: build-use-dkg
build-use-dkg:
	go build -o use-dkg examples/use-dkg.go

.PHONY: build-verify
build-verify:
	go build -o verify examples/verify.go

.PHONY: clean
clean:
	rm -rf verify use-dkg
