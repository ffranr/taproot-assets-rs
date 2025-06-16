.PHONY: all build-all build build-rpc build-zk vendor-proto build-tests fmt

all: build-all

# Build all workspace crates, including host-side zk crates.
# This depends on `build-zk` to ensure the guest binaries are built first.
build-all: build build-zk

# Build workspace excluding zk guests.
build: build-rpc build-tests
	@echo "Building workspace (excluding zk)"
	@cargo build -p taproot-assets
	@cargo build -p taproot-assets-types
	@cargo build -p taproot-assets-zk-core
	@cargo build -p taproot-assets-zk-verifier

# Build the zk guest code (the prover circuits).
# This will build all guest packages in the workspace.
build-zk:
	@echo "Building zk guest: mint-prover"
	@cargo +nightly-2024-05-15 risczero build -p mint-prover

# Copy the authoritative proto into the taproot-assets-rpc crate `./proto` dir.
PROTO_SRC  := external/taproot-assets-upstream/taprpc/taprootassets.proto
PROTO_DEST := taproot-assets-rpc/proto/taprootassets.proto

vendor-proto:
	@# Copy only if DEST doesn't exist OR content differs
	@if [ ! -e $(PROTO_DEST) ] || ! cmp -s $(PROTO_SRC) $(PROTO_DEST); then \
	    echo "Updating $(PROTO_DEST)"; \
	    cp $(PROTO_SRC) $(PROTO_DEST); \
	else \
	    echo "Proto up-to-date"; \
	fi

# Re-generate Rust stubs (requires build-protos feature).
build-rpc: vendor-proto
	@cargo build -p taproot-assets-rpc --features build-protos

build-tests:
	@cargo test --no-run --workspace --exclude mint-prover --exclude taproot-assets-zk-core

publish-dry-run:
	@echo "Publishing dry run"
	@cargo publish --dry-run -p taproot-assets-types
	@cargo publish --dry-run -p taproot-assets-rpc
	@cargo publish --dry-run -p taproot-assets
	@cargo publish --dry-run -p taproot-assets-zk-core
	@cargo publish --dry-run -p taproot-assets-zk-verifier

fmt:
	@echo "Formatting worksapce"
	@cargo fmt
	@dprint fmt