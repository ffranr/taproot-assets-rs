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
	@cargo build -p taproot-assets-core
	@cargo build -p taproot-assets-zk-core
	@cargo build -p taproot-assets-zk-verifier

# Build the zk guest code (the prover circuits).
# This will build all guest packages in the workspace.
GUEST_PROFILE_ENV := CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=true \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_STRIP=symbols

build-zk:
	@echo "Building zk guest: anchor-claim-prover"
	@$(GUEST_PROFILE_ENV) cargo +nightly-2024-12-15 risczero build -p anchor-claim-prover
	@echo "Building zk guest: taproot-commitment-prover"
	@$(GUEST_PROFILE_ENV) cargo +nightly-2024-12-15 risczero build -p taproot-commitment-prover
	@echo "Building zk guest: stxo-claim-prover"
	@$(GUEST_PROFILE_ENV) cargo +nightly-2024-12-15 risczero build -p stxo-claim-prover
	@echo "Building zk guest: asset-claim-prover"
	@$(GUEST_PROFILE_ENV) cargo +nightly-2024-12-15 risczero build -p asset-claim-prover
	@echo "Building zk guest: proof-chain-claim-prover"
	@$(GUEST_PROFILE_ENV) cargo +nightly-2024-12-15 risczero build -p proof-chain-claim-prover
	@echo "Building zk guest: join-prover"
	@$(GUEST_PROFILE_ENV) cargo +nightly-2024-12-15 risczero build -p join-prover

# Copy the authoritative protos into the taproot-assets-rpc crate `./proto` dir.
PROTO_SRC_DIR := external/taproot-assets-upstream/taprpc
PROTO_DEST_DIR := taproot-assets-rpc/proto
PROTO_FILES := taprootassets.proto tapcommon.proto

vendor-proto:
	@mkdir -p $(PROTO_DEST_DIR)
	@for file in $(PROTO_FILES); do \
	    src="$(PROTO_SRC_DIR)/$$file"; \
	    dest="$(PROTO_DEST_DIR)/$$file"; \
	    if [ ! -e $$dest ] || ! cmp -s $$src $$dest; then \
	        echo "Updating $$dest"; \
	        cp $$src $$dest; \
	    else \
	        echo "$$dest up-to-date"; \
	    fi; \
	done

check-protoc:
	@command -v protoc >/dev/null 2>&1 || { \
		echo "error: protoc not found. Install it with: sudo dnf install -y protobuf-compiler"; \
		exit 1; \
	}

# Re-generate Rust stubs (requires build-protos feature).
build-rpc: vendor-proto check-protoc
	@cargo build -p taproot-assets-rpc --features build-protos

build-tests:
	@cargo test --no-run --workspace --exclude anchor-claim-prover --exclude taproot-commitment-prover --exclude join-prover --exclude stxo-claim-prover --exclude asset-claim-prover --exclude proof-chain-claim-prover --exclude taproot-assets-zk-core

publish-dry-run:
	@echo "Publishing dry run"
	@cargo publish --dry-run -p taproot-assets-types
	@cargo publish --dry-run -p taproot-assets-core
	@cargo publish --dry-run -p taproot-assets-rpc
	@cargo publish --dry-run -p taproot-assets
	@cargo publish --dry-run -p taproot-assets-zk-core
	@cargo publish --dry-run -p taproot-assets-zk-verifier

fmt:
	@echo "Formatting worksapce"
	@cargo fmt
