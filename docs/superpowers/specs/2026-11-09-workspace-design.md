# Rust workspace scaffold

Approved approach: one deployable application and five library crates in a Cargo workspace.

## Intent and scope

Establish buildable component boundaries for NullGate without implementing filtering,
network listeners, authentication, persistence, or certificate generation.

## Approaches

- Single crate with modules: fewer manifests, less component separation.
- Cargo workspace: explicit component boundaries and one application; selected by the user.

## Structure

- `nullgate`: application entry point; depends on the orchestrator.
- `nullgate-core`: shared rules, configuration, and types in future work.
- `nullgate-dns` and `nullgate-http`: depend on core.
- `nullgate-web`: depends on core; framework undecided.
- `nullgate-orchestrator`: depends on core and the three service crates.

Libraries initially contain documentation only. The executable explicitly reports
that services are unimplemented and exits; it must not imply filtering is running.
No external Rust dependencies are needed. Use Rust 2024, a pinned toolchain,
workspace formatting/lint policy, a committed lockfile, and CI checks.

## Validation

Build all crates, run the scaffold executable, check formatting, Clippy, tests,
and Rust documentation. Zero behavioral tests are expected at this stage;
compilation and the CLI smoke check validate the scaffold only.
