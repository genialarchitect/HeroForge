# Contributing to HeroForge

Thank you for your interest in contributing to HeroForge! This document provides guidelines for contributing to this authorized security testing tool.

## Ethical Guidelines

**Before contributing, please understand:**

HeroForge is designed exclusively for **authorized security assessments**, including:
- Licensed penetration testing engagements
- Authorized bug bounty programs
- Security research in controlled environments
- Network administration on systems you own or have permission to test

All contributions must align with these ethical standards. We do not accept contributions that:
- Facilitate unauthorized access to systems
- Bypass security controls for malicious purposes
- Target specific organizations or individuals without authorization
- Violate responsible disclosure practices

## Getting Started

### Prerequisites

- Rust 1.70 or higher
- Git
- A development environment (VS Code, IntelliJ IDEA, or similar)
- Familiarity with network security concepts

### Setting Up Your Development Environment

1. **Fork the repository**
   ```bash
   # Clone your fork
   git clone https://github.com/YOUR_USERNAME/HeroForge.git
   cd HeroForge
   ```

2. **Install dependencies**
   ```bash
   cargo build
   ```

3. **Run tests**
   ```bash
   cargo test
   ```

4. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check existing issues to avoid duplicates
2. Collect relevant information (OS, Rust version, error messages)

When submitting:
- Use a clear, descriptive title
- Describe steps to reproduce the issue
- Include expected vs. actual behavior
- Add relevant logs or screenshots

### Suggesting Features

We welcome feature suggestions that enhance HeroForge's capabilities for **authorized security testing**. Please include:
- Clear description of the feature
- Use case and benefits for legitimate security assessments
- Potential implementation approach (if known)

### Submitting Code

#### Pull Request Process

1. **Ensure your code follows our standards**
   - Run `cargo fmt` for formatting
   - Run `cargo clippy` for linting
   - All tests must pass (`cargo test`)

2. **Write meaningful commit messages**
   ```
   feat: add TCP SYN scan capability for authorized assessments

   - Implements raw socket SYN scanning
   - Adds rate limiting to prevent network disruption
   - Includes documentation for proper usage
   ```

3. **Update documentation** if your changes affect:
   - Command-line interface
   - Configuration options
   - API endpoints
   - Security considerations

4. **Submit your pull request**
   - Reference any related issues
   - Describe what your changes do
   - Explain testing performed
   - Confirm ethical compliance

#### Code Review

All submissions require review. Reviewers will check for:
- Code quality and style consistency
- Test coverage
- Security implications
- Documentation completeness
- Alignment with ethical use guidelines

## Coding Standards

### Rust Style Guide

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` with default settings
- Address all `cargo clippy` warnings
- Write documentation comments for public APIs

### Security Considerations

When contributing security-related code:

1. **Include safeguards** - Add rate limiting, timeouts, and scope restrictions
2. **Document responsibly** - Explain legitimate use cases without providing attack tutorials
3. **Consider impact** - Ensure features cannot easily be weaponized
4. **Add warnings** - Include appropriate disclaimers in user-facing output

### Testing Requirements

- Unit tests for new functionality
- Integration tests for scanning features
- **Test only against authorized targets** (localhost, test networks, or dedicated lab environments)
- Never include real IP addresses or hostnames in test code

## Documentation

Good documentation helps users understand how to use HeroForge responsibly:

- Document all command-line options
- Provide usage examples for legitimate scenarios
- Include authorization reminders where appropriate
- Keep the README and docs/ folder up to date

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community chat
- **Pull Requests**: Code contributions and reviews

### Code of Conduct

All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md), which emphasizes:
- Ethical use of security tools
- Respectful community interaction
- Legal compliance in all activities

## Recognition

Contributors are recognized in:
- Release notes for significant contributions
- The CONTRIBUTORS file for ongoing participation
- Security advisories for responsible vulnerability disclosure

## Legal Notice

By contributing to HeroForge, you agree that:

1. Your contributions are your original work or properly attributed
2. You grant the project a license to use your contributions under the MIT License
3. Your contributions are intended for authorized security testing purposes
4. You will not contribute code designed for malicious use

## Questions?

If you have questions about contributing, please:
- Open a GitHub Discussion
- Email [contribute@heroforge.dev](mailto:contribute@heroforge.dev)

Thank you for helping make HeroForge a valuable tool for the security community!
