# CyberForge Pipeline — convenience targets.
#
# These are thin wrappers around the existing, authoritative scripts so that the
# documented one-command reproducer (T-94) works literally:
#
#     cd Pipeline && make demo-pack
#
# Nothing here re-implements logic — each target delegates to the real script,
# which remains the single source of truth.

SHELL := /bin/bash

.DEFAULT_GOAL := help

# Resolve the Makefile's own directory so targets work regardless of CWD.
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: help demo-pack verify-pack verify-pack-strict

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

demo-pack: ## Regenerate the founder-independent sample Evidence Pack (offline degrade mode) — runs verify-evidence-pack.sh
	bash "$(ROOT_DIR)sample-evidence-pack/make-sample-pack.sh"

verify-pack: ## Verify the committed (offline, degrade-mode) sample Evidence Pack — exit 0 on success
	EVIDENCE_ALLOW_DEGRADE=1 bash "$(ROOT_DIR)scripts/verify-evidence-pack.sh" "$(ROOT_DIR)sample-evidence-pack/evidence"

verify-pack-strict: ## STRICT release-pack verification (no degrade): requires cosign bundle + PDF/A. Use on a CI-produced release pack, NOT the offline sample.
	bash "$(ROOT_DIR)scripts/verify-evidence-pack.sh" "$(ROOT_DIR)sample-evidence-pack/evidence"
