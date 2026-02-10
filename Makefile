.PHONY: test fmt tidy verify

test:
	GOPATH=/tmp/gopath GOMODCACHE=/tmp/gopath/pkg/mod GOCACHE=/tmp/go-build go test ./...

fmt:
	gofmt -w *.go internal/oidc/*.go tests/*.go

tidy:
	go mod tidy

verify: fmt test
