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
# An AI model directory, hashed as OpenSSF Model Signing does
ampel verify model ./my-model -p policy.json -a my-model.sig
```

`ampel verify model` walks the model directory (or a single model file),
hashes every regular file and folds the digests into the root digest that
model signing records as the subject of its signatures. Git metadata at the
root of the model is left out, as the specification requires; other files,
such as a signature bundle stored next to the weights, are left out with
`--ignore-path`. Symlinks are rejected unless `--allow-symlinks` is set,
matching the setting the model was signed with.
