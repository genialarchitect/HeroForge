# Contributing to HeroForge

Thank you for your interest in contributing to HeroForge! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@heroforge.io.

## Getting Started

### Prerequisites

- **Rust**: 1.70+ (edition 2021)
- **Node.js**: 18+ (for frontend)
- **Docker**: 24.0+ (for containerized development)
- **SQLite**: 3.x (or let the app create it)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/HeroForge.git
   cd HeroForge
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/genialarchitect/HeroForge.git
   ```

## Development Setup

### Backend (Rust)

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test

# Run with development settings
JWT_SECRET=$(openssl rand -hex 32) cargo run -- serve
```

### Frontend (React/TypeScript)

```bash
cd frontend

# Install dependencies
npm install

# Start development server (proxies to backend on :8080)
npm run dev

# Build for production
npm run build
```

### Full Stack Development

```bash
# Terminal 1: Backend
JWT_SECRET=dev-secret-key cargo run -- serve --bind 127.0.0.1:8080

# Terminal 2: Frontend
cd frontend && npm run dev
```

Access the app at `http://localhost:5173` (Vite dev server).

### Docker Development

```bash
# Build and run with Docker Compose
docker compose up --build

# Or use the development compose file
docker compose -f docker-compose.dev.yml up
```

## Making Changes

### Branch Naming

Use descriptive branch names:

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/description` | `feat/add-nmap-import` |
| Bug fix | `fix/description` | `fix/websocket-timeout` |
| Documentation | `docs/description` | `docs/api-examples` |
| Refactor | `refactor/description` | `refactor/scanner-module` |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(scanner): add UDP protocol support

fix(auth): resolve JWT expiration edge case

docs(api): add examples for scan endpoints
```

### Keep Commits Focused

- One logical change per commit
- Atomic commits that can be reverted independently
- Include relevant tests with feature commits

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run the full test suite:**
   ```bash
   cargo test
   cd frontend && npm run lint && npm run build
   ```

3. **Check formatting and lints:**
   ```bash
   cargo fmt -- --check
   cargo clippy --all-targets -- -D warnings
   ```

4. **Update documentation** if needed

### Submitting a PR

1. Push your branch to your fork
2. Open a Pull Request against `main`
3. Fill out the PR template completely
4. Link any related issues

### PR Requirements

- [ ] All CI checks pass
- [ ] Code follows project style guidelines
- [ ] Tests added/updated for changes
- [ ] Documentation updated if needed
- [ ] No merge conflicts
- [ ] Reviewed by at least one maintainer

### Review Process

1. Maintainers will review within 3-5 business days
2. Address feedback and push updates
3. Once approved, a maintainer will merge

## Coding Standards

### Rust

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting (default config)
- Zero `clippy` warnings with `-D warnings`
- Prefer `anyhow::Error` for error handling in async code
- Document public APIs with `///` doc comments

```rust
/// Performs a TCP connect scan on the specified targets.
///
/// # Arguments
///
/// * `targets` - List of IP addresses or CIDR ranges to scan
/// * `ports` - Port range specification (e.g., "1-1000" or "80,443,8080")
///
/// # Returns
///
/// Returns a `ScanResult` containing discovered hosts and services.
///
/// # Errors
///
/// Returns an error if the network is unreachable or permissions are insufficient.
pub async fn tcp_connect_scan(
    targets: &[IpAddr],
    ports: &str,
) -> Result<ScanResult> {
    // Implementation
}
```

### TypeScript/React

- Follow the existing ESLint configuration
- Use TypeScript strict mode
- Prefer functional components with hooks
- Use Zustand for global state, React Query for server state

### SQL

- Use parameterized queries (never string concatenation)
- Migrations are auto-applied; add new ones in `db/migrations.rs`

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test scanner::

# With output
cargo test -- --nocapture

# Sequential (for DB tests)
cargo test -- --test-threads=1
```

### Writing Tests

- Unit tests go in `#[cfg(test)]` modules within source files
- Integration tests go in `tests/` directory
- Use `#[serial_test::serial]` for tests that need database isolation

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_parser() {
        let ports = parse_ports("80,443,8080").unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[tokio::test]
    async fn test_scan_localhost() {
        let result = tcp_connect_scan(&["127.0.0.1".parse().unwrap()], "80")
            .await
            .unwrap();
        // Assertions
    }
}
```

### Test Coverage

We aim for >50% code coverage. Check coverage locally:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

## Documentation

### Code Documentation

- All public functions, structs, and modules need doc comments
- Include examples where helpful
- Document error conditions

### User Documentation

- Update `README.md` for user-facing changes
- API changes should update `docs/` files
- New features need usage examples

### Changelog

- Add entries to `CHANGELOG.md` under `[Unreleased]`
- Follow Keep a Changelog format

## Questions?

- **Discord**: [Coming soon]
- **Discussions**: Use GitHub Discussions for questions
- **Issues**: For bugs and feature requests

Thank you for contributing to HeroForge!
