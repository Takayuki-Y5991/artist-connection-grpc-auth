.PHONY: fix

fix:
	cargo fmt
	cargo clippy -- -D warnings