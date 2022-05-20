PACKAGES=./...

# build paramters
BUILD_FOLDER = build
HTTPS_GIT := https://github.com/elesto-dao/elesto.git

export GO111MODULE = on

# process build tags
all: build lint test

###############################################################################
###                                  Build                                  ###
###############################################################################

BUILD_TARGETS := build install

build: 
	go build $(PACKAGES)

clean:
	@echo clean build folder $(BUILD_FOLDER)
	rm -rf $(BUILD_FOLDER)
	@echo done

.PHONY: build build-linux clean

###############################################################################
###                          Tools & Dependencies                           ###
###############################################################################

go.sum: go.mod
	@echo "Ensure dependencies have not been modified ..." >&2
	go mod verify
	go mod tidy


###############################################################################
###                           Tests & Simulation                            ###
###############################################################################

test:
	go test -mod=readonly  -cover -race $(PACKAGES)

test-cover:
	go test -mod=readonly  -cover -race -coverprofile=./_private/coverage.out $(PACKAGES) && go tool cover -html=_private/coverage.out -o=_private/coverage.html

docs:
	@echo "launch local documentation portal"
	mkdocs serve

.PHONY: docs openapi

###############################################################################
###                                Linting                                  ###
###############################################################################

lint: go.sum
	@echo "--> Running linter"
	golangci-lint run

.PHONY: lint

###############################################################################
###                                CI / CD                                  ###
###############################################################################

test-ci:
	go test -coverprofile=coverage.txt -covermode=atomic -mod=readonly $(PACKAGES)

###############################################################################
###                                RELEASE                                  ###
###############################################################################

changelog:
	git-chglog --output CHANGELOG.md

_get-release-version:
ifneq ($(shell git branch --show-current | head -c 9), release/v)
	$(error this is not a release branch. a release branch should be something like 'release/v1.2.3')
endif
	$(eval APP_VERSION = $(subst release/,,$(shell git branch --show-current)))
#	@echo -n "releasing version $(APP_VERSION), confirm? [y/N] " && read ans && [ $${ans:-N} == y ]

release-prepare: _get-release-version
	@echo making release $(APP_VERSION)
ifndef APP_VERSION
	$(error APP_VERSION is not set, please specifiy the version you want to tag)
endif
	git tag $(APP_VERSION)
	git-chglog --output CHANGELOG.md
	git tag $(APP_VERSION) --delete
	git add CHANGELOG.md && git commit -m "chore: update changelog for $(APP_VERSION)"
	@echo release complete

git-tag:
ifndef APP_VERSION
	$(error APP_VERSION is not set, please specifiy the version you want to tag)
endif
ifneq ($(shell git rev-parse --abbrev-ref HEAD),main)
	$(error you are not on the main branch. aborting)
endif
	git tag -s -a "$(APP_VERSION)" -m "Changelog: https://github.com/elesto-dao/elesto/blob/main/CHANGELOG.md"
