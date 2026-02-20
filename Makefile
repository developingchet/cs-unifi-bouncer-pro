.PHONY: build test race lint clean docker-build docker-test run

build:
	go build -ldflags="-s -w -X main.Version=dev" -o cs-unifi-bouncer-pro ./cmd/bouncer

test:
	go test ./...

race:
	go test -race ./... -count=1 -timeout=120s

lint:
	golangci-lint run ./...

clean:
	rm -f cs-unifi-bouncer-pro bouncer bouncer.exe
	rm -rf dist/

docker-build:
	docker compose build

docker-test: docker-build
	@echo "==> Seccomp sanity check (Alpine)..."
	@docker run --rm \
	  --security-opt "seccomp:./security/seccomp-unifi.json" \
	  --security-opt no-new-privileges:true \
	  --cap-drop ALL \
	  alpine:latest \
	  ls /proc/self/fd
	@echo "==> Running container under seccomp profile..."
	@set +e; \
	output=$$(timeout 20 docker run --rm \
	  --security-opt "seccomp:./security/seccomp-unifi.json" \
	  --security-opt no-new-privileges:true \
	  --cap-drop ALL \
	  --read-only \
	  --tmpfs /tmp:size=10M \
	  --tmpfs /data:size=50M \
	  -e UNIFI_URL=https://192.0.2.1 \
	  -e UNIFI_API_KEY=test-api-key \
	  -e CROWDSEC_LAPI_URL=http://no-such-host:8080 \
	  -e CROWDSEC_LAPI_KEY=test-lapi-key \
	  developingchet/cs-unifi-bouncer-pro:latest 2>&1) || true; \
	set -e; \
	echo "$$output"; \
	if echo "$$output" | grep -qE "reopen exec fifo|error closing exec fds"; then \
	  echo "FAIL: seccomp blocked container startup"; exit 1; \
	fi; \
	[ -n "$$output" ] || { echo "FAIL: no output from container"; exit 1; }; \
	echo "PASS: container started under seccomp profile"

run:
	docker compose up -d
