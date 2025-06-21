# Contributing to K8Sec Toolkit

Thank you for your interest in contributing to K8Sec Toolkit! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Development Setup](#development-setup)
- [Pre-commit Hooks](#pre-commit-hooks)
- [Code Quality Standards](#code-quality-standards)
- [Security Guidelines](#security-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git
- Python 3.7+ (for pre-commit hooks)
- Docker (optional, for container testing)

### Initial Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/kholcomb/k8sec-toolkit.git
   cd k8sec-toolkit
   ```

2. **Install dependencies:**

   ```bash
   make deps
   ```

3. **Install pre-commit hooks:**

   ```bash
   # Install pre-commit if not already installed
   pip install pre-commit

   # Install the hooks
   make pre-commit-install
   ```

4. **Install security tools (for development and testing):**

   ```bash
   # Install security scanning tools (macOS with Homebrew)
   brew install trivy kubescape kube-bench kubectl-who-can polaris

   # Or install manually following tool-specific documentation
   ```

## Pre-commit Hooks

We use pre-commit hooks to ensure code quality and consistency. These hooks run automatically before each commit.

### Installed Hooks

#### Essential Go Hooks

- **go-fmt**: Automatically formats Go code (built-in, fast, reliable)
- **go-mod-tidy**: Cleans up go.mod and go.sum files

#### Security Hooks (Critical for Security Project)

- **detect-secrets**: Prevents committing secrets and credentials
- **gitleaks**: Additional secret detection with GitLeaks

#### File Quality Hooks

- **trailing-whitespace**: Removes trailing whitespace
- **end-of-file-fixer**: Ensures files end with newline
- **check-merge-conflict**: Detects merge conflict markers
- **check-yaml**: Validates YAML syntax
- **check-json**: Validates JSON syntax

#### Project-Specific Hooks

- **check-k8sec-toolkit-references**: Ensures no old "kubesec" references remain
- **check-go-module-path**: Validates go.mod uses correct module path

### Moved to CI Pipeline

The following checks are now handled in the CI pipeline to improve developer experience:

- **go-imports**: Requires goimports installation
- **go-vet**: Environment/PATH issues in different setups
- **go-unit-tests**: Comprehensive testing in CI
- **golangci-lint**: Requires golangci-lint installation
- **markdownlint**: Documentation style checks
- **shellcheck**: Shell script linting

## Benefits of Optimized Configuration

- **No external tool installation requirements**: Faster setup for new contributors
- **Fast, reliable commits**: Reduced friction in development workflow
- **Security checks remain active**: Critical security validation preserved
- **Essential quality maintained**: Core code quality standards enforced
- **Development velocity improved**: Fewer blocking pre-commit failures


### Running Pre-commit Hooks

```bash
# Run hooks on all files
make pre-commit-run

# Run hooks manually
pre-commit run --all-files

# Run specific hook
pre-commit run go-fmt --all-files

# Skip hooks (not recommended)
git commit -m "message" --no-verify
```

### Updating Pre-commit Hooks

```bash
pre-commit autoupdate
```

## Code Quality Standards

### Go Code Standards

1. **Formatting**: Use `gofmt` and `goimports`
2. **Linting**: Pass all `golangci-lint` checks
3. **Testing**: Minimum 80% test coverage
4. **Documentation**: All exported functions must have docstrings
5. **Error Handling**: Proper error handling and logging

### Code Review Checklist

- [ ] Code follows Go best practices
- [ ] All tests pass
- [ ] Code coverage meets requirements
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Performance impact considered
- [ ] Breaking changes documented

## Security Guidelines

### Security Requirements

1. **No Secrets**: Never commit secrets, keys, or credentials
2. **Input Validation**: Validate all external inputs
3. **Error Handling**: Don't expose sensitive information in errors
4. **Dependencies**: Keep dependencies updated and secure
5. **Logging**: Be careful about what gets logged

### Security Tools

```bash
# Run security checks
make security-check

# Run Gosec security scanner
gosec ./...

# Check for secrets
detect-secrets scan --all-files
```

### Reporting Security Issues

Please report security vulnerabilities privately by emailing the maintainers rather than opening public issues.

## Testing Guidelines

### Test Structure

```
internal/
├── scanner/
│   ├── scanner.go
│   └── scanner_test.go
└── tools/
    ├── trivy.go
    └── trivy_test.go
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...

# View coverage report
go tool cover -html=coverage.out
```

### Test Requirements

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test component interactions
3. **Table-Driven Tests**: Use for multiple test cases
4. **Error Cases**: Test error conditions
5. **Mocking**: Mock external dependencies

## Submitting Changes

### GitFlow Workflow

We follow the GitFlow branching model:

1. **main**: Production-ready code
2. **develop**: Integration branch for features
3. **feature/***: Feature development branches
4. **hotfix/***: Critical fixes for production
5. **release/***: Release preparation branches

### Contributing Process

1. **Create Feature Branch:**

   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes:**
   - Write code following our standards
   - Add/update tests
   - Update documentation
   - Ensure all pre-commit hooks pass

3. **Test Locally:**

   ```bash
   make ci-check  # Runs all CI checks locally
   ```

4. **Commit Changes:**

   ```bash
   git add .
   git commit -m "feat: add new security scanner integration"
   ```

5. **Push and Create PR:**

   ```bash
   git push origin feature/your-feature-name
   # Create pull request through GitHub
   ```

### Commit Message Format

We follow conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/modifications
- `chore`: Maintenance tasks

### Pull Request Guidelines

1. **Title**: Clear, descriptive title
2. **Description**: Explain what and why
3. **Testing**: Describe how you tested changes
4. **Breaking Changes**: Document any breaking changes
5. **Issues**: Reference related issues

### Code Review Process

1. All PRs require at least one review
2. All CI checks must pass
3. Pre-commit hooks must pass
4. Security scan must pass
5. Test coverage must not decrease

## Useful Commands

```bash
# Development workflow
make deps          # Install dependencies
make build         # Build binary
make test          # Run tests
make lint          # Run linters
make security-check # Run security checks
make ci-check      # Run all CI checks

# Pre-commit workflow
make pre-commit-install  # Install pre-commit hooks
make pre-commit-run      # Run hooks on all files

# Validation
make validate      # Run Go validation checks
```

## Getting Help

- **Documentation**: Check the project README and docs
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Email maintainers for security issues

## License

By contributing to K8Sec Toolkit, you agree that your contributions will be licensed under the same license as the project.
