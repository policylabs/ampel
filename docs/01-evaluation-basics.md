# Policy Evaluation Basics

An evaluation in AMPEL implies looking into software metadata for expected data
as defined in a policy. As that phrase implies, you need three ingredients to
run an evaluation: A piece of software, trusted metadata and a policy.

## The Three Main Ingredients

This is a brief introduction about the elements required to run a policy evaluation.
Things can get more sophisticated (hopefully not too complex).

### The Subject

First you need a _subject_, this is generally a piece of software but you can
write policies about anything that can be securely represented as a hash: a binary,
a container image manifest, a git commit, etc.

### Security Metadata

Then you need the data that AMPEL will look at. Or put another way, attestations
that describe properties of the subject. Ideally attestations will be signed by
a trusted identity and produced in a secure fashion. AMPEL uses the in-toto
attestation format natively.

### A Policy

Finally you need a policy. A policy dicatates the expected conditions that the 
metadata needs to meet for the policy to PASS. Policies are written in JSON and
can have many conditions, known as _tenets_ in AMPEL-speak. Policies can specify
trusted identities, can be tied to security framework controls and can be reused.

## A Basic Evaluation Run

To run an evaluation, simply invoke AMPEL passing the three required ingredients:

```bash
ampel verify binary.exe -p policy.json -a attestation.intoto.json
```

By default, AMPEL exits -1 if the policy does not pass. In the example above, we
are feeding ampel a single attestation. While you can specify attestations via
the `-a|--attestation` flag, in the real world you will be using collectors. 

`ampel verify` on its own is short for `ampel verify artifact`, the subcommand
that takes a file to hash or a digest. Other kinds of subjects get their own
subcommand under `ampel verify`, which computes the digest the way the
attestations about them do:

```bash
# A container image, resolved to the digest of its manifest
ampel verify image ghcr.io/example/app:v1.2.3 -p policy.json

# An AI model directory, hashed as OpenSSF Model Signing does
ampel verify model ./my-model -p policy.json -a my-model.sig
```

`ampel verify image` resolves the reference at its registry into the digest
of the manifest the tag points to, the digest that signatures and
attestations about the image are bound to. A reference that already carries
a digest is used as is. Multi-platform images resolve to the digest of their
index; to check one platform, pass that platform's manifest digest. The
attestations attached to the image in its registry, both under cosign's
`.att` tag and as OCI referrers, are collected by default, so no collector
needs to be configured for them; `--registry-attestations=false` turns that
off, and `--attestation` and `--collector` add evidence from elsewhere.

`ampel verify model` walks the model directory (or a single model file),
hashes every regular file and folds the digests into the root digest that
model signing records as the subject of its signatures. Git metadata at the
root of the model is left out, as the specification requires; other files,
such as a signature bundle stored next to the weights, are left out with
`--ignore-path`. Symlinks are rejected unless `--allow-symlinks` is set,
matching the setting the model was signed with.
