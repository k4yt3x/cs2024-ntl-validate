build:
	GOOS=linux GOARCH=amd64 CC=musl-gcc go build \
		-tags musl \
		--ldflags '-linkmode "external" -extldflags="-static"' \
		-o ../../bin/verifier ./cmd/verifier
	strip -s ../../bin/verifier

build-gcc:
	rm -rf bin
	go build -o ../../bin/verifier ./cmd/verifier
	strip -s ../../bin/verifier

debug:
	rm -rf bin
	go build -gcflags "-N -l" -o ../../bin/verifier ./cmd/verifier

