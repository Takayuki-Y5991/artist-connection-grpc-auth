.PHONY: fix
fix:
	cargo fmt
	cargo clippy -- -D warnings

.PHONY: docker-v-rm
docker-v-rm:
	docker compose -f docker-compose.test.yaml down -v

.PHONY: docker-up
docker-up:
	docker compose -f docker-compose.test.yaml up -d


.PHONY: test-unit test-integration test-all

test-unit:
	cargo test --test unit -- --nocapture

test-integration:
	docker compose -f docker-compose.test.yaml up -d
	sleep 3
	cargo test --test integration -- --nocapture
	docker compose -f docker-compose.test.yaml down

test-all: test-unit test-integration