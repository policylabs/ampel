// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockPredicate is a minimal attestation.Predicate for testing verification.
type mockPredicate struct {
	verification attestation.Verification
}

func (m *mockPredicate) GetType() attestation.PredicateType        { return "" }
func (m *mockPredicate) SetType(attestation.PredicateType) error   { return nil }
func (m *mockPredicate) GetParsed() any                            { return nil }
func (m *mockPredicate) GetData() []byte                           { return []byte("{}") }
func (m *mockPredicate) GetVerification() attestation.Verification { return m.verification }
func (m *mockPredicate) GetOrigin() attestation.Subject            { return nil }
func (m *mockPredicate) SetOrigin(attestation.Subject)             {}
func (m *mockPredicate) SetVerification(attestation.Verification)  {}

var _ attestation.Predicate = (*mockPredicate)(nil)

// newTestEnv creates a CEL environment with the predicate variable and
// matchesId function registered, mirroring the real evaluator setup.
func newTestEnv(t *testing.T) *cel.Env {
	t.Helper()
	vco := verificationCompileOptions()
	opts := make([]cel.EnvOption, 0, 2+len(vco))
	// Optional types mirror the production environment (see the envOpts in
	// implementation.go) so tests can pin the optional syntax
	// (s.?field.orValue(...)) policies rely on.
	opts = append(opts, cel.Variable("predicate", cel.AnyType), cel.OptionalTypes())
	opts = append(opts, vco...)
	env, err := cel.NewEnv(opts...)
	require.NoError(t, err)
	return env
}

// testPredicateVars builds a vars map with a PredicateVal for the given mock.
func testPredicateVars(pred attestation.Predicate) map[string]any {
	sv, _ := structpb.NewValue(map[string]any{ //nolint:errcheck // test helper with static input
		"predicate_type": "",
		"data":           map[string]any{},
	})
	return map[string]any{
		"predicate": NewPredicateVal(sv, pred),
	}
}

func evalBool(t *testing.T, env *cel.Env, code string, vars map[string]any) bool {
	t.Helper()
	ast, iss := env.Compile(code)
	require.NoError(t, iss.Err(), "compile %q", code)

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)

	result, _, err := program.Eval(vars)
	require.NoError(t, err, "eval %q", code)

	b, ok := result.Value().(bool)
	require.True(t, ok, "expected bool from %q, got %T", code, result.Value())
	return b
}

func evalErr(t *testing.T, env *cel.Env, code string, vars map[string]any) {
	t.Helper()
	ast, iss := env.Compile(code)
	require.NoError(t, iss.Err(), "compile %q", code)

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)

	_, _, err = program.Eval(vars)
	require.Error(t, err, "expected error from %q", code)
}

func TestPredicateVerificationMatchesIdSigstore(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	pred := &mockPredicate{
		verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{
				Verified: true,
				Identities: []*sapi.Identity{
					{
						Sigstore: &sapi.IdentitySigstore{
							Issuer:   "https://accounts.google.com",
							Identity: "user@example.com",
						},
					},
				},
			},
		},
	}

	vars := testPredicateVars(pred)

	t.Run("matching", func(t *testing.T) {
		t.Parallel()
		got := evalBool(t, env, `predicate.verification.matchesId("sigstore::https://accounts.google.com::user@example.com")`, vars)
		require.True(t, got)
	})

	t.Run("non-matching", func(t *testing.T) {
		t.Parallel()
		got := evalBool(t, env, `predicate.verification.matchesId("sigstore::https://accounts.google.com::other@example.com")`, vars)
		require.False(t, got)
	})
}

func TestPredicateVerificationMatchesIdKey(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	pred := &mockPredicate{
		verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{
				Verified: true,
				Identities: []*sapi.Identity{
					{
						Key: &sapi.IdentityKey{
							Id:   "SHA256:abc123",
							Type: "ssh-ed25519",
						},
					},
				},
			},
		},
	}

	vars := testPredicateVars(pred)

	got := evalBool(t, env, `predicate.verification.matchesId("key::ssh-ed25519::SHA256:abc123")`, vars)
	require.True(t, got)
}

func TestPredicateVerificationMatchesIdNilDefault(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	// nil predicate → default verification (verified=false)
	vars := testPredicateVars(nil)

	got := evalBool(t, env, `predicate.verification.matchesId("sigstore::https://accounts.google.com::user@example.com")`, vars)
	require.False(t, got)
}

func TestPredicateVerificationMatchesIdInvalidSlug(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	pred := &mockPredicate{
		verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{
				Verified: true,
			},
		},
	}
	vars := testPredicateVars(pred)

	evalErr(t, env, `predicate.verification.matchesId("invalid-slug-no-separator")`, vars)
}

func TestPredicateVerificationFieldAccess(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	t.Run("verified true", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicate{
			verification: &sapi.Verification{
				Signature: &sapi.SignatureVerification{
					Verified: true,
					Identities: []*sapi.Identity{
						{
							Sigstore: &sapi.IdentitySigstore{
								Issuer:   "https://accounts.google.com",
								Identity: "user@example.com",
							},
						},
					},
				},
			},
		}
		vars := testPredicateVars(pred)
		got := evalBool(t, env, `predicate.verification.verified == true`, vars)
		require.True(t, got)
	})

	t.Run("verified false (nil predicate)", func(t *testing.T) {
		t.Parallel()
		vars := testPredicateVars(nil)
		got := evalBool(t, env, `predicate.verification.verified == false`, vars)
		require.True(t, got)
	})

	t.Run("identities access", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicate{
			verification: &sapi.Verification{
				Signature: &sapi.SignatureVerification{
					Verified: true,
					Identities: []*sapi.Identity{
						{
							Sigstore: &sapi.IdentitySigstore{
								Issuer:   "https://accounts.google.com",
								Identity: "user@example.com",
							},
						},
					},
				},
			},
		}
		vars := testPredicateVars(pred)
		got := evalBool(t, env, `predicate.verification.identities[0].sigstore.identity == "user@example.com"`, vars)
		require.True(t, got)
	})
}

// mockPredicateSigners extends mockPredicate with the actual verified signer
// identities, mirroring verifier.matchedPredicate. It satisfies SignersProvider
// so verification.signers is populated from Signers() rather than from the
// verification's (matched-subset) identities.
type mockPredicateSigners struct {
	mockPredicate
	signers []*sapi.Identity
}

func (m *mockPredicateSigners) Signers() []*sapi.Identity { return m.signers }

var (
	_ attestation.Predicate = (*mockPredicateSigners)(nil)
	_ SignersProvider       = (*mockPredicateSigners)(nil)
)

func TestPredicateVerificationSigners(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	signerA := &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://accounts.google.com",
			Identity: "alice@example.com",
		},
	}
	signerB := &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://accounts.google.com",
			Identity: "bob@example.com",
		},
	}

	// No allowlist: the verification's identities subset is empty while signers
	// carries the actual signer AMPEL verified.
	t.Run("no-allowlist", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicateSigners{
			mockPredicate: mockPredicate{
				verification: &sapi.Verification{
					Signature: &sapi.SignatureVerification{
						Verified:   true,
						Identities: nil, // no allowlist supplied → empty subset
					},
				},
			},
			signers: []*sapi.Identity{signerA},
		}
		vars := testPredicateVars(pred)

		require.True(t, evalBool(t, env, `size(predicate.verification.identities) == 0`, vars))
		require.True(t, evalBool(t, env, `size(predicate.verification.signers) == 1`, vars))
		require.True(t, evalBool(t, env, `predicate.verification.signers[0].sigstore.identity == "alice@example.com"`, vars))
		require.True(t, evalBool(t, env, `predicate.verification.signers.exists(s, has(s.sigstore))`, vars))

		// The optional-types syntax must work on signer elements: presence
		// checks, safe chained selection and safe traversal of absent fields.
		require.True(t, evalBool(t, env, `predicate.verification.signers.exists(s, s.?sigstore.hasValue())`, vars))
		require.True(t, evalBool(t, env, `predicate.verification.signers.exists(s, s.?sigstore.?identity.orValue("") == "alice@example.com")`, vars))
		require.True(t, evalBool(t, env, `predicate.verification.signers.all(s, s.?key.?id.orValue("none") == "none")`, vars))
	})

	// With an allowlist: identities is the matched subset (signerA only) while
	// signers remains the full actual set (signerA and signerB).
	t.Run("with-allowlist", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicateSigners{
			mockPredicate: mockPredicate{
				verification: &sapi.Verification{
					Signature: &sapi.SignatureVerification{
						Verified:   true,
						Identities: []*sapi.Identity{signerA}, // matched subset
					},
				},
			},
			signers: []*sapi.Identity{signerA, signerB}, // full actual set
		}
		vars := testPredicateVars(pred)

		require.True(t, evalBool(t, env, `size(predicate.verification.identities) == 1`, vars))
		require.True(t, evalBool(t, env, `predicate.verification.identities[0].sigstore.identity == "alice@example.com"`, vars))
		require.True(t, evalBool(t, env, `size(predicate.verification.signers) == 2`, vars))
		require.True(t, evalBool(t, env, `predicate.verification.signers.exists(s, s.sigstore.identity == "bob@example.com")`, vars))
	})

	// A predicate that does not implement SignersProvider exposes an empty
	// signers list (never absent), so policies can safely reference it.
	t.Run("no-signers-provider", func(t *testing.T) {
		t.Parallel()
		pred := &mockPredicate{
			verification: &sapi.Verification{
				Signature: &sapi.SignatureVerification{
					Verified:   true,
					Identities: []*sapi.Identity{signerA},
				},
			},
		}
		vars := testPredicateVars(pred)
		require.True(t, evalBool(t, env, `size(predicate.verification.signers) == 0`, vars))
	})

	// A nil predicate yields the default value with an empty signers list.
	t.Run("nil-predicate", func(t *testing.T) {
		t.Parallel()
		vars := testPredicateVars(nil)
		require.True(t, evalBool(t, env, `size(predicate.verification.signers) == 0`, vars))
	})
}

func TestPredicateDataAccess(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	// Verify that non-verification fields still work through PredicateVal
	sv, err := structpb.NewValue(map[string]any{
		"predicate_type": "https://example.com/predicate/v1",
		"data":           map[string]any{"key": "value"},
	})
	require.NoError(t, err)

	vars := map[string]any{
		"predicate": NewPredicateVal(sv, nil),
	}

	got := evalBool(t, env, `predicate.predicate_type == "https://example.com/predicate/v1"`, vars)
	require.True(t, got)

	got = evalBool(t, env, `predicate.data.key == "value"`, vars)
	require.True(t, got)
}
