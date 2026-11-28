# The AMPEL Policy Guide

This document provides a deep dive into AMPEL policies, their structure
and format. 

## Policies and PolicySets

Attested data captures claims about a piece of software. An AMPEL policy
codifies a set of expectations called _tenets_ that are expected to be
true for a policy to pass.

The policy _frame_ defines the environment and data a policy needs to run while
the policy _code_ in each tenet defines the rules to test the ingested predicate data.

Most scenarios where AMPEL runs require more than one policy as we may be
looking for different things in attestations or the required information may be
in more than one attestation. To makr things easier to manage, groups of
policies may be bound together in a `PolicySet`. A policy set provides a logical
container for related policies and AMPEL can gate processes on the combined
results, that is the passing status of the whole set.

## A Word About Runtimes

As disccussed previously, AMPEL sets up the policy environment and then, the
tenet code is executed in a runtime. AMPEL exposes some data in the runtime
execution environment that the policy code can use:

- Loaded Predicates
- Subject data
- Attestation signer identities
- Context data
- Any data and functions defined by runtime plugins

Runtimes are sepcified in the policy framework. While AMPEL supports swappable
runtimes, at the time of writing it only ships with the default CEL (Common
Expression Language) runtime. See appendix a for details and examples.

## Policy File Format

AMPEL policies can be written in either **JSON** or **HJSON** format. Both formats
are fully supported and can be used interchangeably.

### JSON Format
Standard JSON format with strict syntax requirements. The policies in the
[carabiner-dev/policies](https://github.com/carabiner-dev/policies) repository
are mostly written this way.

### HJSON Format (Recommended for Readability)
HJSON (Human JSON) is a more user-friendly configuration format that supports:
- **Comments**: Add inline and block comments to explain policy logic
- **Unquoted keys**: Write `id: value` instead of `"id": "value"`
- **Trailing commas**: No need to remove the last comma in lists
- **Multiline strings**: Easier to read and maintain

Both `.json` and `.hjson` file extensions are supported. AMPEL sniffs the
format from the content, not from the extension, so a policy referenced
remotely works either way.

The [`examples/`](examples) directory has a runnable example of each policy
document type — a policy, a PolicySet and a PolicyGroup — written in HJSON
and commented throughout. Each one ships with the attestation it reads.

## General Policy Structure

An AMPEL policy can be extremely simple but the structure is flexible enough to
support complex use cases. A simple but sufficiently secure policy should have
the following parts:

### Metadata

The metadata block contains information about the policy itself. It has fields like 
its description, expiration date, runtime, etc.

Two of them carry the human-readable labels:

- **`name`**: a short, single-line label for the policy, for example
  `"Expected SLSA Builder"`. Newlines are rejected.
- **`description`**: the longer explanation of what the policy verifies and
  why. This is the one that shows up above the results table.

Both are optional, but a policy that other people will read (or reference
remotely) should set them. PolicySets and PolicyGroups carry the same pair in
their own metadata. Blocks are the exception: they only have a `description`.

### Identities

While not required, a policy SHOULD specify the identities that can sign the
attestations selected for evaluation. While AMPEL verifies the signatures
automatically, the sigstore identities or the signer keys will be compared
against the identities list defined in the policy. If none match, the policy
will fail. See the section below for more on specifying signer identities.

### Predicate Spec

(Required) A policy must specify at least one predicate type to run. Any matching
predicates will be loaded and exposed in the runtime environment.

Predicate types are versioned but a policy can specify an unversioned URI to match
any version of the same type. More than one predicate type can be specified, it
is up to the policy code to make sense of the loaded data.

### Tenets

A tenet is the logical unit of the policy. It wraps the policy code to add data
to specify human messages, the tenet ID and errors. Tenets can also specify a
subset of predicate types from the list defined at the policy level.

More importantly, Tenets specify _outputs_. Outputs are values pre-extracted from
the predicate data and exposed during at evaluation time. While not required,
outputs are useful when a policy needs to express in its evaluation results  the
data it looked at when evaluating. See the outputs section later in the handbook
for more information.

## Referencing Policies

A PolicySet or a PolicyGroup does not need to contain the policies it is made
of. It can reference them, and AMPEL fetches each one and puts it in place
before evaluating. A reference is a `source` with the location of the policy:

```json
{
    "id": "my-set",
    "policies": [
        {
            "source": {
                "location": {
                    "uri": "git+https://github.com/policylabs/policies@<commit>#slsa/slsa-builder-id.json"
                }
            }
        }
    ]
}
```

The `uri` is a VCS locator: the repository, the revision after `@` and the
path of the file after `#`. Pin the revision to a full commit, so that the
policy that runs is the one that was reviewed. A `sha256` value under `digest`
in the location is checked against the fetched file. An HTTPS URL works as a
location too, and a digest is the only way to pin one.

The stanza holding the reference can set fields of its own, such as `id`,
`meta`, `context`, `identities`, `when` or tenets, which are laid over the
referenced policy.

### References to the same repository

Policies that live in one repository can reference each other without naming
it. A `uri` that starts with `$/` points to a file in the same repository, at
the same revision, as the document it is written in. What follows `$/` is the
path of the file from the root of the repository:

```json
{
    "id": "my-set",
    "policies": [
        { "source": { "location": { "uri": "$/slsa/slsa-builder-id.json" } } }
    ]
}
```

The notation follows the self repository syntax of GitHub Actions. A set
written this way always runs with the policies of its own revision, so a set
and its policies can change in the same commit, and pinning the set pins
everything it references.

Where the referenced file is read from depends on how the set was given to
AMPEL:

| The set was read from | `$/path` is read from |
| --- | --- |
| A VCS locator, `-p git+https://github.com/org/repo@<commit>#sets/set.json` | The same repository at the same commit |
| A local file, `-p sets/set.json` | The working tree of the git repository the file is in, committed or not, without network access |
| An HTTPS URL | Nowhere: a URL has no revision to read the reference at, and AMPEL refuses to run the set |

A few rules apply:

- The path always starts at the root of the repository, not at the directory
  of the document, and cannot leave the repository.
- A self reference takes no revision: `$/policy.json@v1` is an error.
- A self reference belongs to the document it is written in. A group fetched
  from another repository reads its own `$/` references from that repository.
- A locator naming a branch, a tag or no revision at all is resolved to a
  commit once, and everything `$/` points to is read at that commit.
- A local file that is not inside a git repository cannot use `$/`.

The [policy materials reference](https://github.com/policylabs/policy/blob/main/docs/policy-materials.md#self-references)
has the full details.

## Evaluation Context

In order to achieve the maximum level of reusability, policy behavior can be
tuned to changing environment conditions with contextual data. For example, a
policy can define a context value with the repository name, that would allow it
to define tenets that can evaluate in any repository.

Contextual data is exposed to the evaluation runtime in key-value pairs. A policy
defines the values it needs and one of the context data providers supplies the
values. During the policy evaluation, all values are accesible through the
`context.` global object.

### An Intro to Contextual Data

Contextual data is not meant to be used a general purpose variables, the idea
of contextual data is to anchor the policy better to the environment it is
running. Without contextual data, policies could break if reused in another
environment.

Contextual data should not be used to feed AMPEL properties about the subject
under evaluation or data that should be in a signed attestation. Instead,
contextual data should reflect data from the environment that changes when 
executing a tenet in another environment.

For example, lets say you have an SBOM with data about a Linux binary and a Darwin
binary. Instead of having one policy for mac and one for linux, you could define
a contextual `platform` value that reacts to the platform running the evaluation.
This way you can have a single policy that works anywhere.

### The ContextVal struct

When a policy needs contextual values, the JSON document lists them under the
top-level `context` key. The context block is a map of `ContextVal` objects
that define a value, a default and a flag marking it as required:

```json
    "context": {
        "username": {
            "value": "",
            "default": "User",
            "required": true
        }
    }
```

If required values are not defined, the evaluation will error before executing
any of its tenets. Values "burned" into the policy (defined in the policy JSON)
cannot be modified from the command line. They can be overriden when composing 
policies but in general they are immutable.

There is no type definition or a way to coerce the type of a value. When setting
or overriding a value, the new value can be of a different type. It is up to the
evaluation runtime to cast the context values into their preferred type
representation but in general if the  runtime is typed (such as CEL for example),
the runtime _should_ respect the original type.

### Context Value Naming

Context value names are strings. They can use all letters (a-z) and digits (0-9)
plus underscores (_). Uppercase characters can be used and SHOULD be honored in
by runtimes.

One important note on names: __Context names cannot clash when normalized
to lowercase__. In other words: `MyValue` and `myvalue` are both valid context
value names but you cannot have define them at the same time. The reason for this
is that AMPEL needs to support context value providers that may be case insensitive.

### Common Context in PolicySets

PolicySets can define common contextual values. These values are defined in its
commons section and are exposed to all policies contained in the PolicySet.

```json
    "common": {
        "context": {
            "email": {
                "default": "hostmaster@example.com",
                "required": false
            },
            "num_reviewers": {
                "value": 2
            }
        }
    }
```

Policies can override the common context definition. If a policy defines a 
ContextVal under and existing key, the policy's values are merged with the
ancestor. This means that values re-defined at the policy level replace those
at the PolicySet level. Fields not present at the PolicySet level are added
if defined by the policy.

For example, in the example above, if a policy defines an `email`
entry with a value of `me@example.com`, and flipping the required value, the
resulting ContextVal would be:

```json
"email": {
    "default": "hostmaster@example.com",,
    "required": true,
    "value": "me@example.com"
}
```

As mentioned above, values can be replaced with another type for now.

### Dynamic Values via Expressions

Context values can be resolved dynamically by an evaluator runtime instead of
being supplied as a static `value`/`default` or by an external provider. To do
this, set `expression` (and optionally `runtime`) on the `ContextVal`:

```json
    "context": {
        "builderId": {
            "expression": "subject.name"
        }
    }
```

When `expression` is set, AMPEL invokes the configured runtime at evaluation
time, resolves the expression and uses the result as the context value. Like
`value`, an expression is considered burned-in to the policy: it cannot be
overridden by `default` or by external providers, and is mutually exclusive
with both `value` and `default` (the policy will fail validation if either is
combined with `expression`).

The optional `runtime` field selects which evaluator runs the expression. When
omitted, the policy's default runtime is used (CEL in the default
distribution). `runtime` is only valid when `expression` is set.

#### Resolution Order

Context values are resolved in two deterministic phases:

1. **Static phase:** every entry that does not define an `expression` is
   resolved first, in alphabetical key order, by combining `value`, `default`
   and any external provider override.
2. **Dynamic phase:** every entry that defines an `expression` is then
   resolved, also in alphabetical key order, with the static-phase results
   already populated on the `context.*` object.

Because the static snapshot is captured once before the dynamic phase begins,
expressions can rely on every static sibling being visible, but they cannot
observe other expression-resolved siblings. This keeps evaluation order
irrelevant among expressions and prevents cyclic dependencies.

#### Variables available to context expressions

Expressions evaluated against context values run *before* attestations are
filtered for a tenet, so they have access to a smaller set of inputs than a
tenet body. The available variables are:

- `subject` — the subject under evaluation (`name`, `uri`, `digest`).
- `context` — the already-resolved context values from ancestor scopes
  (PolicySet → PolicyGroup → Policy) **and** every static sibling at the
  current scope. Expression-resolved siblings at the current scope are not
  visible (see "Resolution order" above).
- Any global variables and functions registered by runtime plugins (for
  example, the `hasher`, `url`, `purl`, and `semver` helpers in the CEL
  runtime).

The following are intentionally *not* available, because they are not yet
known when context values are assembled: `predicate`, `predicates`, the
chained subjects produced by selectors, and the policy object itself.

### Data Sources

Contextual values can get their data from external sources which are not
connected to the subject, evidence or policy. In AMPEL's initial release we
support four sources: Policy code, a JSON struct, command line flags or
environment variables. AMPEL will support more ways of defining context
values in the future.

Data sources may define any number of values but note that for security 
purposes, any keys that are not defined in (or computed into) the policy
context definition will not be exposed to the evaluation engine.

#### Policy Code

Policy code can set the value of contextual data. As we saw, the context
definition can set a default value or set a value in its definition. Once
defined in the policy code a value cannot be changed unless it is overriden
from another value set in policy code.

Note that at if this writing, values trying to change a burned-in value are
simply ignored but at some point AMPEL may throw an error.

#### JSON Struct

For more control on types, conext values can be set using a JSON struct. This
struct can be passed inline through the command line or read from a file. The
JSON must be a map, keyed by stringsm with any value:

```json
{
    "name": "Yoda",
    "age": 999,
    "sith": false,
    "friends": ["Luke", "R2"]
}
```

To pass the data definitions in the command line simply pass the JSON in the
command line:

```
ampel verify ... --context-json='{"name":"Yoda","age":999,"sith":false,"friends":["Luke","R2"]}'
```

... or you can also put it in a file and read it by preceding the path with an @:

```
ampel verify ... --context-json @values.json
```

Values are parsed by the CLI, if the JSON data is invalid the verifier will not
run and return an error immediately.

#### Command Line Flag

`ampel verify` has a `--context` or `-x` flag that can be used to pass values
to populate the contextual entries. To define a value, put the key, a colon and
follow it with the value:

```
ampel verify ... --context="name:John Doe" -x "email:john@doe.com"
```

Note that all values defined with the `--context` flag are sent as string to 
the evaluation engine.

#### Environment Variables

Setting the `--context-env` flag loads the environent context provider. This
provider reads context data from environment variables. To expose context data
to AMPEL through envvars, set an environment variable with the `AMPEL_` prefix
followed by the context definition name in uppercase.

For example, to define this context value:

```json
  "context": {
    "email": { "required": true }
  }
```

Export an environment variable called `AMPEL_EMAIL`:

```bash
export AMPEL_EMAIL="joe@example.com"
```

Because of security constraints, all variable names need to have the prefix.
If you need to read an existing variable you could copy its value in the shell:

```bash
export AMPEL_USERNAME="${USERNAME}"
```

### Definition Override Order

When computing the stack of value definitions, the AMPEL CLI overrides the data
in the following order:

1. PolicySet Default
2. Policy Default
3. Environment Variable
4. JSON Struct
5. Command line flag
6. PolicySet value
7. Policy value

When referencing policies, a PolicySet or Policy derived from another
source file will inherit its parent's context definition and can override it.

Also note that this order applies to the ampel CLI verifier. Other programs
using AMPEL to verify may not follow this order.

### Using Context Data

Contextual data is exposed to the runtime and SHOULD be made available by the
runtime engine as a global value. As an example, a contextual value like this:

```json
{
    "context": {
        "spaceship":  {"default": "x-wing" }
    }
}
```

... can be accesed in the CEL runtime under the `context` global struct:

```cel
context.spaceship == "tie-fighter" // evaluates to false
```

#### Data types and Complex Data

As mentioned, values are untyped. Internally, AMPEL represents the context as
a `map[string]any` which means it can take virtually any value. But keep in 
mind that if you use complex funky data types, the runtime engine may not be
able to represent them and return an error. Therefore, it is recommende to
stick to basic types which can be represented in JSON.

### Context Values in Evaluation Results

To provide an explainable record of the policy run, AMPEL can output its
evaluation results as a Results attestation. Along with all other data used
during the evaluation, the computed data is captured into the policy results.
Note that the context definition, that is the PolicySet and Policy `ContextVal`s
are not captured, only the final compiled values. For example, this context
value:

```json
"context": {
    "pet": {
        "default": "Wicket W. Warrick",
        "value": "Chewbacca"
    }
}
```

... gets reflected in the evaluation results as:

```json
"context": {
    "pet": "Chewbacca"
}
```

Since context data is expected to change with the environment, the results
attestation keeps record of the computed values for future auditing.

## Applicability Conditions

A policy or a policy block may declare a `when` condition that decides if it
applies to the subject under evaluation. When the condition is false the
element is **skipped**: its result carries the status `SKIP`, records the
condition, and does not count towards the status of its PolicySet, group or
block. A block whose policies all skipped is skipped itself, and so is a group
whose blocks all skipped. PolicySets and PolicyGroups are containers and carry
no condition of their own.

```json
{
    "id": "slsa-v1-provenance",
    "when": {
        "expression": "semver.satisfies(context.drop_version, '>=2.0.0')"
    },
    "context": {
        "drop_version": { "type": "string", "required": true }
    },
    "tenets": [ ... ]
}
```

The condition mirrors the dynamic form of a context value: `expression` is
an evaluator-language snippet that must yield a boolean, and the optional
`runtime` selects the evaluator (defaulting to the runtime of the policy, or
of the group for a block). An absent `when`, or one with an empty expression,
always evaluates. An expression that errors, or that yields anything other
than a boolean, fails the evaluation: a condition that cannot be decided
never silently exempts a subject.

### What a condition can see

A policy's condition is decided **after its evidence is collected**: once the
chain is followed, the attestations gathered and admitted by the signer
identities, and the transformers applied. It sees the subject exactly as the
tenets would. A block's condition, which has no evidence of its own, is
decided before any of the block's policies run.

| Variable | Available | Notes |
| --- | --- | --- |
| `context` | yes | The resolved context values in scope: the policy's own, plus those inherited from the `common` block of its PolicySet and PolicyGroup. Every value the expression reads must be declared there; reading an undeclared one fails the evaluation. |
| `subject` | yes | The subject the tenets evaluate: `name`, `uri`, `digest`. For a policy with a chain this is the subject the chain resolved to, not the one the verification was asked about. |
| runtime plugins | yes | `semver`, `hasher`, `url`, `purl`, `github`, ... and `ampel`, the engine's own data: `ampel.atLeast('v1.4.0')` makes a policy apply only to engines new enough for it. |
| `predicates`, `predicate` | yes | The evidence the policy collected: the attestations about the subject that the signer identities admitted, narrowed to the policy's `predicates.types` when it declares any. `predicate` is the first of them. An empty list means no evidence was found. |
| `chain` | yes | The chain followed to reach the subject, one entry per hop (see below). Empty when the policy has no chain. |
| `outputs` | **no** | Outputs belong to tenets. |

Because the condition comes last, a policy that does not apply is skipped
whatever its evidence looks like. A chain that cannot be completed or
evidence rejected by the signer identities fails the policy only when the
policy applies; a skipped policy records the chain it followed and the
failure it set aside (see below), without failing on it.

Seeing the evidence lets a policy declare that it only applies when its
evidence exists. A policy without such a condition **fails** when the
attestations it needs are missing: asking for a verification and finding
no evidence is a failure, not an exemption. The policy below instead skips
when there is nothing of its type to check, which is what an alternative
inside an OR block of a PolicyGroup needs:

```json
{
    "id": "check-runs",
    "when": { "expression": "size(predicates) > 0" },
    "predicates": { "types": ["https://example.com/check-runs/v1"] },
    "tenets": [ ... ]
}
```

Dynamic context values are resolved before any evidence is read, so their
expressions cannot see `predicates`.

### Reading the chain

A policy with a `chain` evaluates its tenets on the subject the chain
resolved to, and the evidence it collects is about that subject. The hops it
crossed are not lost: tenets, conditions and selectors see them in the
`chain` variable, a list with one entry per hop, outermost first (a policy
set's hops, then the policy's own). Each entry carries:

| Field | Content |
| --- | --- |
| `source` | The subject the hop was read about: `name`, `uri`, `digest`. |
| `destination` | The subject the hop's selector chose, same shape. |
| `type` | The predicate type of the attestation the hop read. |
| `predicate` | That attestation's predicate, as `predicate` exposes one: `predicate_type`, `data`, `verification`. |

This is what lets a tenet compare what it finds at the end of a chain with
what the chain was read from. A release tag whose trailers name the tree
the tagged commit must carry, for instance, is verified by chaining from the
tag to the commit and checking the commit against the tag:

```json
{
    "id": "tagged-commit-carries-named-tree",
    "chain": [
        { "predicate": { "type": "https://carabiner.dev/git/tag/v0", "selector": "\"sha1:\" + predicate.data.object" } }
    ],
    "predicates": { "types": ["https://carabiner.dev/git/commit/v0"] },
    "tenets": [
        { "id": "tree-matches", "code": "predicate.data.tree == chain[0].predicate.data.trailers[\"Tree\"][0]" }
    ]
}
```

The second hop of a longer chain can likewise read the first through
`chain[0]` from its selector.

### Who signs a hop

The attestation a hop reads is evidence like any other, so it goes through
the same two gates as the attestations the tenets evaluate (see
[Signer Identities](#signer-identities)):

1. **Signature.** The attestation's signature must verify. An unsigned
   attestation, or one signed with a key the verifier does not hold, stops
   the chain and fails the policy.
2. **Identity.** When signer identities are pinned, the attestation must be
   signed by one of them. A hop is checked against the `identities` of its
   own link when it declares any, and against the policy's otherwise. With
   no identities in either, those passed with `--signer` apply.

```json
{
    "chain": [
        {
            "predicate": {
                "type": "https://carabiner.dev/git/tag/v0",
                "selector": "\"sha1:\" + predicate.data.object",
                "identities": [
                    { "sigstore": { "issuer": "https://accounts.google.com", "identity": "releases@example.com" } }
                ]
            }
        }
    ]
}
```

A link's identities replace the policy's for that hop, they do not add to
them: use them when the attestation the chain is read from is signed by a
different party than the evidence at the end of it.

The exception for unverified evidence is the general one, with the same
limits. `ampel verify` admits an unsigned attestation into a chain only when
it was passed with `--attestation` / `-a` and no signer identity applies to
the hop. An unsigned attestation found by a collector never completes a hop,
and neither does any unsigned attestation once identities are pinned. Library
callers opt in with the `AdmitUnverified` verification option, which is off
by default.

When the hop's attestation is rejected the policy fails with `unable to
validate chained attestation identity`. Only the first attestation matching
a hop is read and checked.

### Conditions on referenced policies

A `when` set on the stanza that references a policy from another location is
applied to the referenced policy when the set is compiled, so a library policy
can be gated without editing it:

```json
{
    "id": "provenance-current",
    "source": { "location": { "uri": "git+https://github.com/carabiner-dev/policies@<commit>#slsa/has-attestation.json" } },
    "when": { "expression": "semver.satisfies(context.drop_version, '>=2.0.0')" }
}
```

### Skips in results

A skipped policy's result has status `SKIP` and an evaluation result,
`when`, whose assessment records the condition. When collecting the policy's
evidence had already failed it, because its chain could not be completed or
the signer identities rejected its attestations, a second evaluation result,
`evidence`, follows: skipped like the first, its assessment names the failure
and its error keeps the message and guidance. The verdict is unchanged, since
the policy does not apply, but the record shows that the evidence was not
verified rather than merely absent. A skipped block records the condition in
its error message. The `tty` output marks them with a hollow dot.

Skips are recorded, never summarized as a verification. Within a PolicySet,
skipped policies are left out of the `VerifiedLevels` of a VSA, and a set
whose policies and groups all skipped is itself `SKIP`, as is a group whose
blocks all skipped.

### Nothing verified at the root

The material the verifier is asked to evaluate, the policy, set or group
given to `ampel verify --policy`, is the **root** of the evaluation;
everything inside a set or a block is nested. A nested policy, block, set or
group may answer `SKIP`, and its container decides what that means. The root
may not: being asked to verify a subject and verifying nothing is a
**failure**. A root policy whose condition is false, a root set whose
policies and groups all skipped, and a root group whose blocks all skipped
fail with the error "everything was skipped, nothing was verified", whose
guidance names the case. The nested results keep their `SKIP`, so the record
still shows what did not apply and why. A failed root is attested like any
other failure: as `FAILED` in a VSA or SVR, with the error in the ampel
result attestation.

`ampel verify --allow-skip` restores the skipped answer: the root reports
`SKIP` and the command exits 0, like on a `PASS`, for pipelines that treat
"nothing applied" as acceptable. Adding `--fail-skip` keeps the record as a
skip but exits non-zero on it, for a script that must block on "nothing
applied" without attesting it as a failure; without `--allow-skip` the flag
has no effect, since the run never answers `SKIP`. The ampel results
attestation records the skip; a VSA or SVR cannot, since neither has anything but PASSED and FAILED
to say. Every output format reports which statuses it can render, and
`ampel verify` asks before evaluating: `--allow-skip` refuses to run with
`--format vsa` or `svr`, or with `--attest-results --attest-format vsa` or
`svr`. To attest in those formats, verify without `--allow-skip` and a root
that verified nothing is attested as a failure. Embedders of the verifier have the same choice
through the `AllowSkip` verification option, and can recognize the failure
with `verifier.AllSkipped`.

## Signer Identities

All data used as evidence such as attestations should be signed. When ingesting
attestations, AMPEL will verify that the data signature is valid. Validating the
cryptographic signature does not imply ensuring the right party/parties have
signed the data.

While AMPEL can skip the signer identity check, it is recommended that authorizarion
includes a verification of the signer identity.

### Supported Identities

Ampel supports two kinds of identities natively:

1. __Sigstore:__ Attestations signed and packed in a sigstore bundle are natively
supported. The sigstore identity bundle consists of two parts: 1) the OIDC 
identity issuer (common ones are Google, Github, Microsoft, etc) and 2) the
identity string which will typically be the user's email or a workload identifier.

2. __Keys:__ Basic support for keys is built in. The key identity is the the key ID.
Support for keys is still under development and in flux.

### Specifying Identities

There three ways of specifying the signer identity to be verified. Remember that
if no signer is set, then attestations will be admitted regardless of who signed
them.

#### 1. In-policy Definition

Policies can have their identitied hard-coded in the policy code. This is the
preferred way identities become immutable once the policy is signed. The downside
of hard-coding IDs is that it poses some challenges when reusing policies across
systems.

Identities in the code can be specified at the `Policy` or `PolicySet` level. If a 
`PolicySet` has a set of identities defined they apply to all policies in the set.
Inidividual policies can augment the list of accepted identies at the `Policy` level.
There is no way for a policy to revoke an identity specified at the PolicySet level.

The basic identity construct accounts for both keys and sigstore types:

```json
  "identities": [
    {
      "sigstore": {
        "issuer": "https://accounts.google.com",
        "identity": "joe@example.com",
        "mode": "exact"
      }
    },
    {
      "key": {
        "id": "4e24e0c9-5b77-4b5a-9504-7cec6d91e5d5",
        "type": "ed25519",
        "data": "302a300506032b6570032100a8b4c0f7f8d7e4d6f5c3b9a2e8f1d4c7b0a9e2f5c8b1d4a7e0f3c6b9",
      }
    }
]
```

The identities list is a top level field in the policy JSON and lives under the
`commons` section in the PolicySet.

#### 2. Policy Reuse and References

A policy referencing another source policy MAY override the signer identities.
If the child policy does not have an identity set defined, it will implicitly use
the identities set in the origin source code.

#### 3. Command Line Definition

When running `ampel verify` you may specify the expected signer identity by
passing the verifier an [identity slug] using the `--signer` flag. You can
specify the`--signer` flag multiple times to create a list of allowed signer.

> [!WARNING]  
> Identities in the command line are ignored when a policy specifies its signers
> in the code (either in code or in a source policy). Once the effective policy
> is compiled, if it has a list of identities they are treated as immutable and
> cannot be overriden with `--signer`. In this case, AMPEL will print a warning
> and ignore the flag.

### Sigstore RegExp

Sigstore identities have two matching modes: `exact` or `regexp`. In exact mode,
the strings for the OIDC issuer and identity must match exactly. In real world
situations, the sigstore identity changes. For example, workflow identities in
GitHub often capture versions, branches or different workflows.

To account for the mutating nature, you can use a regexp to match chaning id
strings. For example, to allow anyone in a domain to sign an attestation:

```json
  "identities": [
    {
      "sigstore": {
        "issuer": "https://accounts.google.com",
        "identity": ".*@example.com",
        "mode": "regexp"
      }
    },
  ]
```

### Identity Slugs

To pass identity data around, AMPEL uses an identity slug format which can be
fed to the `--signer` flag and other places. The format is as follows:

#### Sigstore

The format to specify a sigstore identity is:

```
sigstore:::ISSUER:::IDENTITY
```

You can specify a regex identity adding `(regex)` to the sigstore label:

```
sigstore(regexp):::ISSUER_REGEXP:::IDENTITY_REGEXP
```

#### Keys

To specify a key (unstable), use the following string format:

```
key:::TYPE:::KEY_ID:::KEY_DATA
```

### Accessing Verification Data in Policies

Once AMPEL has verified an attestation, its verification data is exposed to CEL
tenets through the `predicate.verification` object. The following fields are
available:

| Field | Description |
| --- | --- |
| `verification.verified` | Boolean, `true` when the attestation signature was cryptographically verified. |
| `verification.identities` | The subset of signer identities that **matched a pinned allowlist** (the identities defined in the policy/`PolicySet` or passed via `--signer`). It is **empty when no allowlist was supplied**. |
| `verification.signers` | The **actual verified signer identities** of the attestation. |

Both `verification.identities` and `verification.signers` are lists whose
elements share the same shape (`.id`, and one of `.sigstore`, `.key` or `.ref`,
matching the identity kind).

#### `verification.signers`

`verification.signers` is **populated by AMPEL** from the signer identities it
actually verified on the attestation. Unlike `verification.identities`, it is
populated **even when no allowlist is configured**, so a policy can read who
really signed the evidence regardless of whether signer identities were pinned:

```cel
// At least one signer used a sigstore (keyless) identity:
predicate.verification.signers.exists(s, has(s.sigstore))

// The attestation was signed by someone in a given domain:
predicate.verification.signers.exists(s, has(s.sigstore) && s.sigstore.identity.endsWith("@example.com"))
```

AMPEL's CEL environment enables
[optional types](https://github.com/google/cel-spec/wiki/proposal-246), so the
`has()` guards can also be written with the optional selection syntax, where
selecting an absent field yields an empty optional instead of an error:

```cel
// Same checks using optional types:
predicate.verification.signers.exists(s, s.?sigstore.hasValue())
predicate.verification.signers.exists(s, s.?sigstore.?identity.orValue("").endsWith("@example.com"))
```

> [!IMPORTANT]
> `verification.signers` is **distinct from `verification.identities`**.
> `identities` is the subset that matched a pinned allowlist (and is empty
> without one), while `signers` is always the full set of actual verified
> signers. `verification.signers` is an **AMPEL-provided view**: it is *not*
> part of the `carabiner-dev/signer` Verification proto.

#### `matchesId`

The `verification` object also exposes a `matchesId` member function that
matches an [identity slug](#identity-slugs) against the verification's identity
set:

```cel
predicate.verification.matchesId("sigstore::https://accounts.google.com::joe@example.com")
```

With `verification.signers` now available, policies can additionally inspect the
real signers directly using the `.exists`/`.all` comprehensions shown above.
