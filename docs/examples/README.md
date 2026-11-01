# AMPEL Examples

Six small examples. The first five are self-contained: each directory holds
a policy and the attestation it reads, so they run as-is with no network
access and no collectors configured. The last one verifies a published
container image and reads its attestations from the registry.

The first four describe the same imaginary artifact, so they share one
subject digest:

```shell
export SUBJECT=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The attestations are unsigned, which is fine for a demo but not for real life.
AMPEL prints a warning about it and admits them because they were passed
explicitly with `-a`; in production you would set `identities` on the policy
and let AMPEL verify the signatures.

| Example | What it shows |
| --- | --- |
| [`sbom/`](sbom) | A plain policy with three tenets, reading an SBOM |
| [`custom-predicate/`](custom-predicate) | Writing policy against a predicate type AMPEL knows nothing about |
| [`policyset/`](policyset) | A PolicySet: several policies sharing context, mapped to framework controls |
| [`group/`](group) | A PolicyGroup: blocks of _alternative_ policies |
| [`model/`](model) | Verifying an AI model directory against its model signing statement |
| [`image/`](image) | Verifying a published container image with the provenance attached to it in the registry |

## 1. Checking an SBOM

[`sbom/sbom-checks.hjson`](sbom/sbom-checks.hjson) is the simplest shape a
policy takes: an id, some metadata, the predicate types it wants, and a list
of tenets. The three tenets check that every package in the SBOM declares a
license, that those licenses are on an allowed list, and that a specific
dependency is present, looked up by its package URL.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/sbom/sbom-checks.hjson \
  -a docs/examples/sbom/sbom.spdx.intoto.json
```

The policy names both the SPDX and the CycloneDX predicate types, so the same
code works against an SBOM in either format.

## 2. A made up predicate

AMPEL has native support for well known attestation types, but it does not
need to know anything about a predicate to run policy on it.
[`custom-predicate/code-review.hjson`](custom-predicate/code-review.hjson)
reads an invented `https://example.com/attestations/code-review/v1` predicate
and checks that a change was approved by two people other than its author.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/custom-predicate/code-review.hjson \
  -a docs/examples/custom-predicate/code-review.intoto.json
```

Name the type in the policy's `predicates` block and the predicate JSON shows
up in the runtime under `predicates[0].data`, untouched.

## 3. A PolicySet verifying SLSA provenance

[`policyset/slsa-build.hjson`](policyset/slsa-build.hjson) bundles three
policies that check the SLSA provenance of the artifact: that it was built by
the expected builder, through the expected build type, and from the expected
source repository.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/policyset/slsa-build.hjson \
  -a docs/examples/policyset/provenance.intoto.json
```

The set's `common` block defines the expected builder, build type and
repository once, and all three policies read them as `context.*`. That is what
makes the policies reusable — point the set at a different project by
overriding a value on the command line instead of editing the file:

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/policyset/slsa-build.hjson \
  -a docs/examples/policyset/provenance.intoto.json \
  --context="sourceRepo:https://github.com/example/other-project"
```

That run fails, which is the point.

Each policy also maps itself to a SLSA control through `meta.controls`, so the
results table gets a Controls column. The policies in the
[carabiner-dev/policies](https://github.com/carabiner-dev/policies) repository
are organized the same way, except that the sets there reference their
policies remotely by commit rather than inlining them.

## 4. A PolicyGroup, or: blocks are alternatives

[`group/breakfast.hjson`](group/breakfast.hjson) is deliberately silly, because
the structure is the only thing worth remembering:

- a group is a list of **blocks**, and every block is a requirement
- a block is a list of **alternative** policies that can satisfy it

Blocks combine with AND, policies inside a block with OR. This group asks for
something to drink AND something to eat, and accepts coffee OR tea for the
first, toast OR cereal for the second.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/group/breakfast.hjson \
  -a docs/examples/group/breakfast.intoto.json
```

The attestation records coffee and toast, so both blocks pass. Edit it to
serve orange juice instead and the drinks block fails while the food block
keeps passing — one failed requirement is enough to fail the group.

## 5. An AI model

The subjects above are all digests, because the examples describe an
imaginary artifact. [`model/`](model) is different: it holds an actual model,
the two-file `simple` model of the
[OpenSSF Model Signing](https://github.com/ossf/model-signing-spec)
conformance suite, and `ampel verify model` hashes the directory the way the
specification defines, every file hashed and the digests folded into one root
digest. That digest is what model signing records as the subject of its
signatures, and it is the subject of
[`model/model-signing.intoto.json`](model/model-signing.intoto.json), the
statement such a signature carries.

```shell
ampel verify model docs/examples/model/simple \
  -p docs/examples/model/model-signing.hjson \
  -a docs/examples/model/model-signing.intoto.json
```

[`model/model-signing.hjson`](model/model-signing.hjson) reads the statement's
predicate, which records how the model was serialized, and checks that it was
hashed file by file with sha256 and without following symlinks. Change a byte
of either file and the run fails before any tenet is evaluated: the directory
no longer hashes to the subject the attestation describes, so there is no
evidence to evaluate.

A real model signature is a sigstore bundle produced by the
[model_signing](https://github.com/sigstore/model-transparency) tool or by
[oms](https://github.com/carabiner-dev/model-signing); pass it with `-a` the
same way.

## 6. A container image, with evidence from the registry

Everything so far read attestations from files. [`image/`](image) holds only
a policy, because the evidence lives in the registry: the ampel release
workflow signs the ampel container image with sigstore and attaches its SLSA
provenance to the image as an OCI referrer. `ampel verify image` resolves the
tag to the digest of the image's manifest and collects what is attached to it
under cosign's `.att` tag and as OCI referrers, so the policy's provenance is
found without any collector configured.

```shell
ampel verify image ghcr.io/policylabs/ampel:v1.4.2 \
  -p docs/examples/image/ampel-image.hjson
```

[`image/ampel-image.hjson`](image/ampel-image.hjson) is the first example to
pin its signer. Its `identities` block accepts only provenance signed through
GitHub Actions by the ampel release workflow, matched with a regular
expression so every release qualifies; provenance signed by anyone else is
rejected before a tenet sees it. The tenets then check the builder, the build
type and the source repository the way the SLSA example does, except that
GitHub's provenance names the workflow and the commit it ran at as the
builder, so the tenet pins the workflow and lets the commit vary.

Change the identity to another repository and the run fails with
"attestation signer does not match an accepted identity", which is the
difference between evidence and signed evidence.
