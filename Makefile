# Local targets. `make pre-deploy-checks` is the gate a release must pass: the
# same checks as the pre-push hook (scripts/ci.sh: fmt, clippy, tests).

.PHONY: help build run ci pre-deploy-checks

help:
	@echo "Available targets:"
	@echo "  make build              cargo build --release -p certcrypt-node"
	@echo "  make run                Run the node locally (scripts/run_node.sh)"
	@echo "  make ci                 What the pre-push hook runs"
	@echo "  make pre-deploy-checks  What a release must pass (same as ci)"

build:
	cargo build --release -p certcrypt-node

run:
	bash scripts/run_node.sh

ci:
	bash scripts/ci.sh

pre-deploy-checks: ci
