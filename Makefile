SOURCE_FILES?=$$(go list ./...)
TEST_PATTERN?=.
TEST_OPTIONS?=-race -v

setup:
	go get -u github.com/go-critic/go-critic/...
	go get -u github.com/alecthomas/gometalinter
	go get -u golang.org/x/tools/cmd/cover
	gometalinter --install

clean:
	rm -rf ./dist

# This requires credentials are set for all providers!!!
test:
	echo 'mode: atomic' > coverage.txt && go list ./... | xargs -n1 -I{} sh -c 'go test -v -timeout=600s -covermode=atomic -coverprofile=coverage.tmp {} && tail -n +2 coverage.tmp >> coverage.txt' && rm coverage.tmp

cover: test
	go tool cover -html=coverage.txt

fmt:
	goimports -w . && gofumpt -l -w .

lint:
	golangci-lint run --disable lll --disable interfacer --disable gochecknoglobals --disable gochecknoinits --enable wsl --enable revive --enable gosec --enable unused --enable gocritic --enable gofmt --enable goimports --enable misspell --enable unparam --enable goconst --enable wrapcheck
ci: lint test

BUILD_TAG := $(shell git describe --tags 2>/dev/null)
BUILD_SHA := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u '+%Y/%m/%d:%H:%M:%S')
LATEST_TAG := $(shell git describe --abbrev=0 2>/dev/null)

build:
	CGO_ENABLED=0 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout"

build-all: fmt
	GOOS=darwin  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_darwin_amd64"
	GOOS=darwin  CGO_ENABLED=0 GOARCH=arm64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_darwin_arm64"
	GOOS=linux   CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_linux_amd64"
	GOOS=linux   CGO_ENABLED=0 GOARCH=386 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_linux_386"
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_linux_arm"
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_linux_arm64"
	GOOS=netbsd  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_netbsd_amd64"
	GOOS=openbsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_openbsd_amd64"
	GOOS=freebsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_freebsd_amd64"
	GOOS=windows CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "github.com/jonhadfield/ipscout/cmd.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC" -X "github.com/jonhadfield/ipscout/cmd.semver=$(BUILD_TAG)"' -o ".local_dist/ipscout_windows_amd64.exe"

critic:
	gocritic check  ./...

mac-install: build
	install .local_dist/ipscout /usr/local/bin/ipscout

linux-install: build
	sudo install .local_dist/ipscout /usr/local/bin/ipscout

install: build
	go install ./...

find-updates:
	go list -u -m -json all | go-mod-outdated -update -direct

NAME   := ghcr.io/jonhadfield/ipscout
TAG    := $(shell git rev-parse --short HEAD)
IMG    := ${NAME}:${TAG}
LATEST := ${NAME}:latest

build-docker:
	docker build --platform=linux/amd64 --build-arg BUILD_TAG="$(BUILD_TAG)" --build-arg BUILD_SHA="$(BUILD_SHA)" --build-arg BUILD_DATE="$(BUILD_DATE) UTC" -t ${IMG} .
	docker tag ${IMG} ${LATEST}
	docker tag ${LATEST} ipscout:latest
	docker tag ${LATEST} docker.io/jonhadfield/ipscout:latest

pull-image:
	docker pull jonhadfield/ipscout:latest

scan-image: pull-image
	trivy image jonhadfield/ipscout:latest

build-latest-docker-tag:
	docker build --build-arg="TAG=$(LATEST_TAG)" -f ./docker/Dockerfile -t ipscout ./docker

release:
	goreleaser && git push --follow-tags

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
