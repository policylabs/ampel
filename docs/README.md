# 🔴🟡🟢 AMPEL

### The Amazing Multipurpose Policy Engine (and L)

Version: 1.0-pre<br>
Copyright © 2025 Carbiner Systems, Inc

## An Introduction to the AMPEL Policy Engine

AMPEL is a policy engine specially crafted to protect the software development
lifecycle through trusted security metadata. It has native support for Software
Supply Chain Security technologies such as In-toto, Sigstore, SLSA, Protobom, etc
but it can also work with any kind of signed metadata.

The engine is extensible in various ways, from pluggable evaluation runtimes to
transformers and runtime plugins. It is designed to be embedable in software
powering software builds, packaging and delivery.

AMPEL is a backronym in search of a meaning. It currently stands for Amazing
Multipurpose Policy Engine (and L), so we are 80% there!

This is the AMPEL user manual. We do our best to keep these docs up to date,
but - as all software documentation - expect the manual to be always under
construction and always behind the latest version. As always, patches and
contributions are welcome!

## Installing

The fastest way to get a working `ampel` binary is through Homebrew using
the Carabiner tap:

```shell
brew install carabiner-dev/tap/ampel
```

Pre-built binaries for Linux, macOS and Windows are also available on the
[GitHub Releases](https://github.com/policylabs/ampel/releases) page,
and `go install github.com/policylabs/ampel/cmd/ampel@latest` works for
Go users. See the project [README](../README.md#installing) for the full
list of installation options.

## Runnable Examples

The [`examples/`](examples) directory has one small, commented example of each
policy document type — a policy, a PolicySet and a PolicyGroup — plus one
showing how to write policy against a predicate type AMPEL knows nothing
about. Each ships with the attestation it reads, so they all run as-is with no
network access. Start there if you learn by poking at things.

## Table of Contents

- Policy Evaluation Basics
  - Three Main Ingredients
  - Basic Evaluation Run

- The AMPEL Attestation Framework
  - How AMPEL Abstracts Attestations
    - Wrappers
      - Signed Envelopes
      - The "Bare" Envelope
    - Contents
      - Subjects
      - Predicates
  - Reading Attestations
    - Types and Versioning
    - Collectors
    - Queries and Filters
  - Signatures and Identities
  - Producing Result Attestations
    - Output Paths
    - Result Attestation Formats
    - Signing Result Attestations
    - Output Shape
  - Tools
    - bnd

- The AMPEL Policy Guide
  - Policies and PolicySets
  - A Word About Runtimes
  - General Policy Structure
    - Metadata
    - Identities
    - Predicate Spec
    - Tenets
  - Evaluation Context
    - An Intro to Contextual Data
    - The ContextVal struct
    - Common Context in PolicySets
    - Data Sources
      - Policy Code
      - JSON Struct
      - Command Line Flag
    - Definition Override Order
    - Using Context Data
      - Data types and Complex Data
    - Context Values in Evaluation Results
  - Transformers
  - Attestation Chaining
  - Identities
    - Identity Types
    - Sigstore Identities
    - Keys
  - Outputs
  - Security Frameworks
    - Tying Policies to Controls

- Working With PolicySets
  - Abstracting Common Properties
    - Identities
    - Contexts
  - PolicySets and Security Frameworks

- Remote Policies and References
  - How Referencing Works
  - Overriding Policy Definitions
  - Abstracting Common Overrides
  - Sources
    - HTTP
    - git

- Evaluation Results
  - Evaluation Status
  - Results Objects
    - Evaluation Result
    - ResultSet
  - Attesting Results
  - Displaying Results
    - Display Drivers

- Appendix A: The AMPEL CEL Runtime
  - The Runtime Environment
  - AMPEL Functions
  - [Plugins](cel-plugins.md) — the runtime globals (`hasher`,
    `url`, `github`, `protobom`, `purl`, `semver`) available in
    every CEL expression.
