# Policy Groups

Policy Groups provide a way to organize policies into logical blocks within a
PolicySet. While a PolicySet can contain individual policies directly, groups
add an intermediate layer that bundles related policies together under a common
identity, control mapping and assertion logic.

## Why Policy Groups?

Individual policies in a PolicySet are evaluated independently. This works well
for simple scenarios but falls short when you need to:

- **Map multiple policies to a single framework control.** A security control
  like "MFA must be enabled for all maintainers" may require checking more than
  one attestation. A group ties these policies together under the control.
- **Express alternative compliance paths.** A group block can use `OR` assertion
  mode so that any one of several policies can satisfy the requirement.
- **Reuse curated collections.** Groups can be referenced from remote sources,
  letting you maintain shared policy bundles across repositories.

## Structure

A PolicyGroup is a JSON/HJSON document with three main parts:

```json
{
    "id": "OSPS-BR-01",
    "meta": {
        "description": "Build pipelines MUST NOT permit untrusted input",
        "controls": [
            { "framework": "OSPS", "class": "BR", "id": "01" }
        ]
    },
    "blocks": [
        {
            "id": "check-workflows",
            "policies": [
                {
                    "source": {
                        "location": { "uri": "git+https://example.com/policies#scorecard/dangerous-workflow.json" }
                    }
                }
            ]
        }
    ]
}
```

### ID

The group identifier. This shows up in evaluation results and is used to
reference the group in output tables.

### Metadata

The `meta` block carries information about the group:

- **description**: Human-readable description of what the group verifies.
- **controls**: A list of framework control mappings (framework, class, id).
  These tie the group to compliance framework requirements.
- **enforce**: Set to `"OFF"` to make the group produce `SOFTFAIL` instead of
  `FAIL` when evaluation does not pass.

### Blocks

A group contains one or more _blocks_. Each block is a collection of policies
that are evaluated together. Blocks have their own assertion logic:

```json
{
    "id": "mfa-checks",
    "meta": {
        "assert_mode": "AND",
        "controls": [
            { "framework": "OSPS", "class": "AC", "id": "01" }
        ]
    },
    "policies": [
        { "source": { "location": { "uri": "git+https://example.com/policies#mfa-all.json" } } },
        { "source": { "location": { "uri": "git+https://example.com/policies#mfa-admin.json" } } }
    ]
}
```

## A Runnable Example

[`examples/group/breakfast.hjson`](examples/group/breakfast.hjson) is a tiny,
deliberately silly group built to make the block structure obvious: it requires
something to drink AND something to eat, accepting coffee OR tea for the first
and toast OR cereal for the second. It ships with the attestation it reads, so
it runs with no setup. See the [examples README](examples/README.md).

## Block Assertion Modes

Each block has an assertion mode that determines how its policies combine:

- **AND** (default): All policies in the block must pass for the block to pass.
- **OR**: At least one policy in the block must pass for the block to pass.

The assertion mode is set in the block's metadata:

```json
"meta": { "assert_mode": "OR" }
```

For the group itself to pass, all of its blocks must pass.

## Using Groups in a PolicySet

A PolicySet references groups in its `groups` field. Groups are typically
fetched from remote sources:

```json
{
    "id": "MyPolicySet",
    "groups": [
        {
            "source": {
                "location": {
                    "uri": "git+https://github.com/example/policies@main#groups/ac-01.hjson"
                }
            }
        },
        {
            "source": {
                "location": {
                    "uri": "git+https://github.com/example/policies@main#groups/br-01.hjson"
                }
            }
        }
    ]
}
```

When the set and its groups live in the same repository, the references can
be written with `$/` and the path of the file from the root of the repository.
The groups are then read from the revision the set itself was read from:

```json
{
    "id": "MyPolicySet",
    "groups": [
        { "source": { "location": { "uri": "$/groups/ac-01.hjson" } } },
        { "source": { "location": { "uri": "$/groups/br-01.hjson" } } }
    ]
}
```

The same works inside a group, for the policies of its blocks. See
[Referencing Policies](03-ampel-policy-guide.md#references-to-the-same-repository)
in the policy guide.

A PolicySet can contain both individual `policies` and `groups`. Both are
evaluated and their results are combined in the final ResultSet.

## Evaluation Results

When AMPEL evaluates a PolicySet containing groups, the results are structured
hierarchically:

```
ResultSet
 +-- Results       (from individual policies in the set)
 +-- Groups        (from policy groups)
      +-- Blocks   (block evaluation results within each group)
           +-- Results (individual policy results within each block)
```

In the default TTY output, each group is displayed as a single row showing:

| Column   | Content                                                   |
|----------|-----------------------------------------------------------|
| Policy   | The group ID                                              |
| Controls | Framework control labels from the group metadata          |
| Status   | Overall PASS/FAIL for the group                          |
| Details  | Assessment messages (pass) or error messages (fail)       |

Use `--policy-out` to get detailed per-policy output that expands each group
into its individual block and policy results.

## Common Context

Like PolicySets, groups can define common context values that are shared across
all policies in the group. See the
[policy guide](03-ampel-policy-guide.md#common-context-in-policysets) for
details on how context values work.

```json
{
    "id": "my-group",
    "common": {
        "context": {
            "repo_name": {
                "required": true
            }
        }
    },
    "blocks": [ ... ]
}
```

## Example: OSPS Baseline

The [OSPS Security Baseline](https://github.com/carabiner-dev/policies) policy
set is a real-world example that uses groups extensively. It defines 36 groups,
each mapping to a specific OSPS framework control:

```json
{
    "id": "OSPS",
    "groups": [
        { "source": { "location": { "uri": "git+https://github.com/carabiner-dev/policies@main#groups/osps-baseline/osps-ac-01.hjson" } } },
        { "source": { "location": { "uri": "git+https://github.com/carabiner-dev/policies@main#groups/osps-baseline/osps-br-01.hjson" } } }
    ]
}
```

To evaluate the baseline against a subject:

```bash
ampel verify my-binary \
    -c jsonl:attestations.jsonl \
    -p 'git+https://github.com/carabiner-dev/policies#sets/baseline/osps-baseline.policy.json'
```
