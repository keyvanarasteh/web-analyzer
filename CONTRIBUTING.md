# Contributing to Web Analyzer

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

1. Fork and clone the repository
2. Run `cargo build --all-features` to verify everything compiles
3. Run `cargo test --all-features` to run the test suite

## External Dependencies

Some modules require system tools to be installed:

- `dig` — DNS resolution (`sudo apt install dnsutils`)
- `nmap` — Port scanning (`sudo apt install nmap`)
- `subfinder` — Subdomain discovery (`go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
- `openssl` — SSL analysis (`sudo apt install openssl`)
- `whois` — WHOIS queries (`sudo apt install whois`)

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy --all-features -- -D warnings` and fix all warnings
- Add doc comments (`///`) to all public items
- Follow existing patterns in other modules

## Adding a New Module

1. Create `src/your_module.rs`
2. Add a feature flag in `Cargo.toml`
3. Register the module in `src/lib.rs` with `#[cfg(feature = "your-module")]`
4. Add documentation in `docs/your_module.md`
5. Add integration tests in `tests/your_module_tests.rs`

## Testing

```bash
# Run all tests
cargo test --all-features

# Run tests for a specific module
cargo test --features "domain-info" -- domain_info

# Run a specific example
cargo run --example domain_info --all-features
```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commit messages
3. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass
4. Open a PR with a description of your changes

## License

By contributing, you agree that your contributions will be licensed under the same dual MIT/Apache-2.0 license as the project.
