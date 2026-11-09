# Rust Workspace Scaffold Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this small scaffold inline.

**Goal:** Establish the six-crate workspace approved by the user.
**Architecture:** One executable depends on the orchestrator, which depends on the service libraries; shared types belong in core.
**Tech Stack:** Rust 2024, Cargo, rustfmt, Clippy, GitHub Actions; no external Rust dependencies.
**Spec:** `docs/superpowers/specs/2026-11-09-workspace-design.md`

## Global Constraints

- Implement structure only; no network listeners or filtering behavior.
- Preserve existing documentation of intended product behavior.
- Keep framework choices open and do not add placeholder public APIs.

## Review Focus

Check dependency direction, honest startup output, workspace-wide checks,
lockfile/toolchain consistency, and accurate development instructions.

## Task 1: Create and validate the workspace

- [x] Add workspace manifest, six crate manifests and sources, toolchain pin, and build ignores.
- [x] Generate the lockfile and build all targets.
- [x] Run the application and confirm it explicitly reports scaffold-only status.
- [x] Add CI and update README and architecture documentation with actual commands and structure.
- [x] Run format, Clippy, tests, documentation, and whitespace checks; inspect changes.

No synthetic unit tests are needed for documentation-only libraries and static startup output.

Validation: all six crates built; formatting, Clippy with warnings denied, Rust documentation with warnings denied, and the CLI smoke check passed. Cargo test completed with zero tests, as expected for this scaffold.
