# Contributing to 🔴🟡🟢 AMPEL

Thanks for your interest in contributing to **AMPEL** — the Amazing Multipurpose
Policy Engine (and L)!

AMPEL is a supply chain policy engine designed to verify software artifacts using
attestations, policies, and reusable verification logic across the SDLC. We welcome
contributions from the community to improve functionality, usability, and
ecosystem integration.

---

## 🧭 How to Contribute

There are many ways to contribute to AMPEL:

- 🐛 Report bugs or unexpected behavior
- ✨ Propose or implement new features
- 📦 Add or improve policy examples
- 🔌 Build plugins or transformers
- 📖 Improve documentation
- 🔐 Contribute security use cases or integrations

If you're unsure where to start, open an issue or check the existing ones.

## 🚀 Getting Started

### 0. Issues Please!

Except minor changes, we expect all pull requests to be backed by
an issue. Before you begin make sure you open a new issue or work
on an existing issue.

### 1. Fork and Clone

Start by [forking the main project repo](https://github.com/policylabs/ampel/fork)
and work from your fork!

```bash
git clone https://github.com/YOURNAME/ampel.git
cd ampel
git remote add upstream https://github.com/policylabs/ampel.git
```

Depending on where you are interested in working, you may need to clone other
repos (the
[attestation collector](https://github.com/policylabs/collector), the
[attestation framework](https://github.com/policylabs/attestation), the
[policy compiler](https://github.com/policylabs/policy), etc).

### 2. Set Up Your Environment

AMPEL is written in Go, as AMPEL is an end-user binary, we build and release it
using the latest stable version.

**Requirements:**

- Go compiler
- golangci-lint

Install dependencies:

```bash
go mod tidy
```

Run tests and linter:

```bash
go test ./...
golangci-lint run
```

## 🧪 Development Workflow

1. Create a new branch:

```bash
git checkout -b my-feature
```

2. Make your changes
3. Add or update tests
4. Ensure all tests pass
5. Submit a Pull Request (PR)

## 🧱 Project Structure (High-Level)

The full ampel functionality is broken into several repositories
to make it easier to maintain and reuse. This repository contains:

- `cmd/ampel/` — CLI entrypoint
- `pkg/context/` — contextual data assembler
- `pkg/verifier/` — core verifier engine
- `pkg/evaluator` — policy code evaluator and implementations (CEL for now)

The AMPEL repository contains only the policy engine, it relies on
other modules in in the Policy Labs project which are developed and
released independently:

- The [attestation collector](https://github.com/policylabs/collector)
- The Policy Labs [attestation framework](https://github.com/policylabs/attestation)
- The [policy compiler](https://github.com/policylabs/policy)
- Signer Library

AMPEL evaluates **policies** written in JSON with executable logic (typically CEL)
and applies them to **attestations** such as in-toto statements.

## 🧩 Types of Contributions

### 1. Core Engine Changes

Changes to:

- Policy evaluation logic
- Attestation verification
- Evidence chains
- Identity verification (e.g., Sigstore, Keys)

These require:

- Tests
- Backward compatibility consideration
- Clear documentation

### 2. Policies & Examples

We strongly encourage contributions of:

- Reusable policies (e.g., SBOM checks, SLSA requirements)
- PolicySets for real-world scenarios
- Security framework mappings (e.g., SLSA, OSPS, CRA)

Example policy snippet:

```json
{
  "id": "sbom-check",
  "tenets": [
    {
      "runtime": "cel@v0",
      "code": "has(sbom.packages) && sbom.packages.size() > 0"
    }
  ]
}
```

Policy, PolicySet and PolicyGroup contributions should be submitted to the 
[policies community repository](https://github.com/carabiner-dev/policies).

### 3. Plugins & Extensions

AMPEL supports extensibility via:

- **CEL plugins** (custom functions, data sources)
- **Transformers** (predicate manipulation)
- **Collector Drivers** (sources of attested data)

CEL plugins and Transformers are currently kept in-tree. Collector drivers
are kept in the [collector repo](https://github.com/policylabs/collector).

Examples:

- SBOM graph queries
- Vulnerability data ingestion

## 🧪 Testing Guidelines

- Add unit tests for new features
- Avoid breaking existing behavior
- Prefer table-driven tests in Go

Run:

```bash
go test ./...
```

## 🔐 Security Contributions

Security is core to AMPEL.

If your contribution involves:

- Attestation formats
- Signature verification
- Identity validation
- Supply chain threat models

Please include:

- Threat model considerations
- Real-world applicability
- References to standards (SLSA, in-toto, OpenVEX, etc.)

For **security vulnerabilities**, please DO NOT open a public issue.
Instead,
[initiate a privet vulnerarbility report](https://github.com/policylabs/ampel/security/advisories/new).

## 🧹 Code Style

- Follow standard Go conventions
- Keep functions small and composable
- Prefer clarity over cleverness
- Document exported functions
- Always run golangci-lint before submitting a PR

Use:

```bash
go fmt ./...
go vet ./...
golangci-lint run
```

## 📦 Commit Guidelines

- Keep commmits small, scoped to a single change.
- Use clear, descriptive commit messages
- Reference issues when applicable
- Using copilot's auto-summary is fine but we also want to hear from you!

## 🔄 Pull Request Process

Before submitting a PR:

- [ ] Code builds successfully
- [ ] Tests pass
- [ ] New functionality is tested
- [ ] Documentation updated if needed

PRs should include:

- Description of the change
- Motivation / use case
- Any breaking changes

Maintainers may request changes before merging.

## 🧠 Design Philosophy

AMPEL aims to be:

* **Composable** — reusable policy building blocks
* **Extensible** — plugins and multiple runtimes
* **Non-prescriptive** — works with existing pipelines
* **Verifiable** — grounded in attestations and cryptographic evidence

Contributions should align with these principles.

## 📄 License

By contributing, you agree that your contributions will be licensed under the
Apache 2.0 License.

## 🙌 Thank You

AMPEL exists to make **cryptographically verifiable supply chain security practical**.

Your contributions help move the ecosystem forward 🚀
