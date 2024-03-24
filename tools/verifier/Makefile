build:
	rm -rf bin
	go build -o ../../bin/verifier ./cmd/verifier
	strip -s ../../bin/verifier

debug:
	rm -rf bin
	go build -gcflags "-N -l" -o ../../bin/verifier ./cmd/verifier

build-musl:
	CGO_ENABLED=1 CC=musl-gcc go build \
		--ldflags 'linkmode external -extldflags="-static"' \
		-o ../../bin/verifier ./cmd/verifier
	strip -s ../../bin/verifier

