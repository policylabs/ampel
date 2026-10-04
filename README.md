# 🔴🟡🟢 AMPEL

### The Amazing Multi-Purpose Policy Engine (and L)

![Image](https://github.com/user-attachments/assets/95d714a4-2401-4c33-a978-1016d5a961f6)

Ampel is a lightweight supply chain policy engine designed to be embedded
across the software development lifecycle to make sure that source code,
tools and the build environment can be trusted by verifying unforgeable
metadata captured in signed attestations.

![Image](https://github.com/user-attachments/assets/c3794605-ff84-48dd-be3f-ccefd702f301)

## Attesting Metadata

Ampel works with attestations in the [in-toto](https://in-toto.io/) format and has native verification
support for sigstore bundles. Signing schemes are pluggable, meaning other
signature verification mechanisms can be added.

As a supply chain security tool, Ampel can work with common formats like
[SLSA](https://slsa.dev) to check software provenance and SBOMs to gate on
depedndency data, but policies can be written against any custom data in JSON.

The policy engine also supports __transformers__ that can read and verify attestations to then convert them to other formats, simplifying policy
authoring.

[Diagram]

For example, by loading the vulnerability report transformer, Ampel
can transform the output of the common vulnerability scanners to a common format, such as OSV, allowing you to write a single policy to verify the findings of any scanner.

## Installing

### Download a Binary

Pre-built binaries for Linux, macOS and Windows are available on the
[GitHub Releases](https://github.com/carabiner-dev/ampel/releases) page.
Download the binary for your architecture, and place it as
`ampel` binary somewhere in your `$PATH`.

### Homebrew

Ampel is available through the Carabiner Homebrew tap:

```shell
brew install carabiner-dev/tap/ampel
```

Or, if you prefer to tap explicitly:

```shell
brew tap carabiner-dev/tap
brew install ampel
```

### Go Install

If you have Go installed, you can install ampel directly:

```shell
go install github.com/carabiner-dev/ampel/cmd/ampel@latest
```

### GitHub Action

Ampel is also available as a GitHub Action for use in CI/CD workflows.
See [carabiner-dev/actions](https://github.com/carabiner-dev/actions) for
setup instructions and usage examples.

## The Ampel Ecosystem

### Attestations Collector

Policy evaluation relies on attestations. AMPEL relies on the
[Carabiner Collector](https://github.com/carabiner-dev/collector)
to read attestations from all sorts of backends, from repositories, registries,
filesystems and more.

### Other Tools

Ampel is part of a growing ecosystem of tools that let software developers and
security engineers harden their SDLC processes. The more mature siblings of
AMPEL are:

- [bnd](https://github.com/carabiner-dev/bnd): A tool to attest, sign and verify
data. It also has features that work with attestations and sigstore bundles.

- [snappy](https://github.com/carabiner-dev/snappy): Takes snapshots of APIs to
attest their state.

- [unpack](https://github.com/carabiner-dev/unpack): A dependency extractor with
SBOM visualization and generation capabilities.

## Policies

Ampel uses a model of policies as code. The policy frame can be written in either
**JSON** or **HJSON** format (HJSON is recommended for better readability with
support for comments and relaxed syntax). The evaluation code is written in a
supported runtime. At present Ampel ships with a CEL (Common Expression Language)
runtime and more runtimes are in the roadmap.

### Policy Structure

The structure of an Ampel policy is described at length in its own documentation
At a higher level a policy consists of:

- Metadata
- Contextual Info
- Attestation Spec
- Identity Definition
- Tenets (one or more)

### Tenet

A policy's _tenets_ (those principles we hold to be true) are the core of the
policy. Each tenet represents a check Ampel will perform on the avilable evidence.

The tenet structure contains the evaluation code that will be executed to check
if the tenet holds true.

A policy's tenets can be evaluated in two modes:

- `AND` a policy will evaluate to PASS when all tenets are true.
- `OR` a policy will `PASS` if at least one tenet evaluates to true. Useful when
there is more than one way to check.

Think of tenets as questions to ask your attested data:

- Was this artifact built by my GitHub account?
- Does my vulnerability report contain HIGH CVEs?
- Does this repository have MFA enabled?
- Is this project licensed under an approved OSI license?
- ... and more.

## Link to Compliance Controls

A policy can be linked to a security framework control. When evaluating the
compliance status of artifacts against a security framework, Ampel can
link the policies to controls and checks defined in OSCAL catalogs and profiles.

## Results and Results Attestations

Ampel can report the status of a policy or block processes when a policy evaluates
to `FAIL`. But the evaluation results are rich with metadata and human-friendly
messages which makes them suitable to display in various situations such as reports,
webpages, CI/CD systems, etc.

A powerful feature of Ampel is that evaluation results can also be attested.
This means that results can be used as input attestations for further policies,
making it simple to check for complex processes further downstream after they
have been checked once.

Result attestations can be produced as the full Ampel ResultSet, as a SLSA
[Verification Summary Attestation (VSA)](https://slsa.dev/verification_summary/v1)
or as an in-toto [Simple Verification Result (SVR)](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md),
and can optionally be signed with sigstore, SPIFFE, or a local key via the
`--sign` flag. See [Producing Result Attestations](docs/02-ampel-attestations.md#producing-result-attestations)
for details.

### Policy Sets

Multiple policies can be specified together in a `PolicySet`. This is a handy way
to maintain policies that relate to each other in a single file to make them
available to the engine at evaluation time. The results of policies tied together
in a PolicySet can also be reported together in a ResultsSet.

## Copyright

Ampel is released under the Apache 2.0 license by The Policy Labs Project Contributors.
Feel free to contribute patches or open an issue if you find a problem. Feedback
is always welcome!
