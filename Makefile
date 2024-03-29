GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

# force OS and ENV if building on darwin, biuut will deploy on linux
# OS = linux
# env GOOS=linux GOARCH=amd64 go build

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOPROXY=direct GOOS=$(OS) GOARCH="$(GOARCH)" go build -ldflags "-X github.com/Vodafone/vault-plugin-aead/version.Version=$(VERSION)" -o vault/plugins/vault-plugin-aead cmd/vault-plugin-aead/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=aead-secrets vault-plugin-aead

clean:
	rm -f ./vault/plugins/vault-plugin-aead

fmt:
	go fmt $$(go list ./...)

test:
	go test 
	go test ./aeadutils

.PHONY: build clean fmt start enable
