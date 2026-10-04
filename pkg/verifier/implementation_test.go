// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"
	"time"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/statement/intoto"
	papi "github.com/policylabs/policy/api/v1"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/policylabs/ampel/pkg/evaluator"
	"github.com/policylabs/ampel/pkg/evaluator/class"
	eoptions "github.com/policylabs/ampel/pkg/evaluator/options"
)

func TestEvaluateChain(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	factory := evaluator.Factory{}

	def, err := factory.Get(&eoptions.Default, DefaultVerificationOptions.DefaultEvaluator)
	require.NoError(t, err)
	evaluators := map[class.Class]evaluator.Evaluator{
		defaultEvaluatorClass: def,
		DefaultVerificationOptions.DefaultEvaluator.BaseClass(): def,
	}

	defaultSubject := &gointoto.ResourceDescriptor{
		Name: "test",
		Digest: map[string]string{
			"sha256": "851074691728c479a4c83628de8310eaca792cc7",
		},
	}
	for _, tt := range []struct {
		name             string
		mustErr          bool
		expectedSubjects int
		subject          attestation.Subject
		attestationPaths []string
		chainLinks       []*papi.ChainLink
	}{
		{
			"self", false, 0, defaultSubject, []string{}, []*papi.ChainLink{},
		},
		{
			// test final multi
			"sbom", false, 170, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: `predicates[0].data.packages.filter(pkg, has(pkg.checksums) && size(pkg.checksums) > 0).map(pkg, { "name": has(pkg.name) ? pkg.name : "", "digest": pkg.checksums.map(checksum, { string(checksum.algorithm).lowerAscii(): dyn(checksum.checksumValue) })[0], 'uri': has(pkg.externalRefs) && size(pkg.externalRefs) > 0 ? dyn(pkg.externalRefs.filter(ref, ref.referenceType == 'purl')[0].referenceLocator) : dyn('')   })`,
						},
					},
				},
			},
		},
		// test intermediates not multi
		// test final single
		{
			// test final multi
			"multi", false, 2, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type: "https://spdx.dev/Document",
							// Selector: "predicates[0].data.packages",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
			},
		},
		{
			// test final multi
			"no-matching-attestations", true, 0, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://cyclonedx.org/bom",
							Selector: `"sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b"`,
						},
					},
				},
			},
		},
		{
			"ensure-multi-intermediates-fail", true, 0, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b'",
						},
					},
				},
			},
		},
		{
			"ensure-final-can-be-multi", false, 2, defaultSubject,
			[]string{
				"testdata/wtf-frontend.spdx.json",
				"testdata/link1.json",
				"testdata/link2.json",
			},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha1:856314ba21181a746186c24f1647d06e45048964'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://example.com/",
							Selector: "'sha1:93836eee21527f010b77faa3379ccba2f3dbc1b3'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://example.com/",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
			},
		},
		{
			// Test that sha1: subject prefix works with gitCommit: attestation digest type
			// This is the exact bug reported in the GitHub issue: https://github.com/policylabs/ampel/issues/175
			// Subject with sha1: should match attestations with gitCommit: digest
			"gitCommit-sha1-matching-bug-fix", false, 1, &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					// User specifies subject with sha1: prefix (as with ampel verify --subject=sha1:...)
					"sha1": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			[]string{
				// Attestation file has subject with gitCommit digest type
				"testdata/gitcommit-attestation.json",
			},
			[]*papi.ChainLink{
				{
					// Chain selector returns a simple subject
					// The key test is that the initial subject (sha1:...) matches
					// the attestation (gitCommit:...) to trigger this selector
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft",
							Selector: `[{ "name": "test-repo-output" }]`,
						},
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Load the attestations required by the test
			// Copy the struct to avoid races when parallel subtests modify AttestationFiles
			opts := DefaultVerificationOptions
			opts.AttestationFiles = tt.attestationPaths
			attestations, err := di.ParseAttestations(t.Context(), &opts, tt.subject)
			require.NoError(t, err)

			// Create a local copy of evaluators to avoid races when parallel subtests
			// add new evaluators for different runtimes
			localEvaluators := make(map[class.Class]evaluator.Evaluator, len(evaluators))
			for k, v := range evaluators {
				localEvaluators[k] = v
			}

			// Check if there is an evaluator for the link's runtime
			for _, l := range tt.chainLinks {
				runtime := l.GetPredicate().GetRuntime()
				if runtime == "" {
					continue
				}
				rt := class.MustParseClass(runtime)
				if _, ok := localEvaluators[rt.BaseClass()]; ok {
					continue
				}
				ev, err := factory.Get(&eoptions.Default, rt)
				require.NoError(t, err)
				localEvaluators[rt.BaseClass()] = ev
			}

			// should we test policyFail?
			subjects, chain, _, err := di.evaluateChain(
				t.Context(), &opts, localEvaluators,
				nil, // the vollector agent should not be required
				tt.chainLinks,
				nil, // no context values in tests
				tt.subject, attestations, []*sapi.Identity{}, "",
			)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			t.Logf("Got subjects:\n%+v", subjects)
			t.Logf("Got chain:\n%+v", chain)

			require.Len(t, subjects, tt.expectedSubjects)
		})
	}
}

func TestCheckPolicy(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mustErr bool
		opts    *VerificationOptions
		policy  *papi.Policy
	}{
		{"normal", false, &DefaultVerificationOptions, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(1 * time.Hour))}}},
		{"expired", true, &DefaultVerificationOptions, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour))}}},
		{"nil-expiration", false, &DefaultVerificationOptions, &papi.Policy{Meta: &papi.Meta{Expiration: nil}}},
		{"expire-off-normal", false, &VerificationOptions{EnforceExpiration: false}, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(1 * time.Hour))}}},
		{"expire-off-expired", false, &VerificationOptions{EnforceExpiration: false}, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour))}}},
		{"expire-off-nil-expiration", false, &VerificationOptions{EnforceExpiration: false}, &papi.Policy{Meta: &papi.Meta{Expiration: nil}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			di := &defaultIplementation{}
			err := di.CheckPolicy(t.Context(), tt.opts, tt.policy)
			if tt.mustErr {
				require.Error(t, err)
				require.IsType(t, PolicyError{}, err) //nolint:testifylint // Checking for type, not value
				return
			}
			require.NoError(t, err)
		})
	}
}

type fakePredicate struct {
	ver attestation.Verification
}

func (fp *fakePredicate) GetType() attestation.PredicateType        { return "" }
func (fp *fakePredicate) SetType(attestation.PredicateType) error   { return nil }
func (fp *fakePredicate) GetParsed() any                            { return nil }
func (fp *fakePredicate) GetData() []byte                           { return []byte("{}") }
func (fp *fakePredicate) GetVerification() attestation.Verification { return fp.ver }
func (fp *fakePredicate) GetOrigin() attestation.Subject            { return nil }
func (fp *fakePredicate) SetOrigin(attestation.Subject)             {}
func (fp *fakePredicate) SetVerification(v attestation.Verification) {
	fp.ver = v
}

var _ attestation.Predicate = &fakePredicate{}

type fakeEnvelope struct {
	ver  attestation.Verification
	pred attestation.Predicate
	// verOnVerify, when set, is recorded as the envelope's verification by
	// Verify, mimicking real envelopes that cache their verification result
	// when their signatures are checked.
	verOnVerify attestation.Verification
}

func (fe *fakeEnvelope) GetStatement() attestation.Statement {
	return &intoto.Statement{Predicate: fe.pred}
}
func (fe *fakeEnvelope) GetPredicate() attestation.Predicate       { return fe.pred }
func (fe *fakeEnvelope) GetSignatures() []attestation.Signature    { return nil }
func (fe *fakeEnvelope) GetCertificate() attestation.Certificate   { return nil }
func (fe *fakeEnvelope) GetVerification() attestation.Verification { return fe.ver }
func (fe *fakeEnvelope) Verify(...any) error {
	if fe.verOnVerify != nil {
		fe.ver = fe.verOnVerify
	}
	return nil
}

var _ attestation.Envelope = &fakeEnvelope{}

func TestNormalizeSubjectDigests(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name           string
		subject        attestation.Subject
		enableHack     bool
		expectedDigest map[string]string
	}{
		{
			name: "gitCommit-to-sha1-hack-enabled",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "sha1-to-gitCommit-hack-enabled",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"sha1": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "gitCommit-to-sha1-hack-disabled",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: false,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "both-present-no-normalization",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
					"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "invalid-length-sha1-no-normalization",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"sha1": "tooshort",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"sha1": "tooshort",
			},
		},
		{
			name: "sha256-no-normalization",
			subject: &gointoto.ResourceDescriptor{
				Name: "artifact",
				Digest: map[string]string{
					"sha256": "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"sha256": "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
			},
		},
		{
			name: "multiple-digests-with-gitCommit",
			subject: &gointoto.ResourceDescriptor{
				Name: "multi",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
					"sha256":    "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha256":    "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := normalizeSubjectDigests(tt.subject, tt.enableHack)
			require.Equal(t, tt.expectedDigest, result.GetDigest())
		})
	}
}

func TestCheckIdentities(t *testing.T) {
	t.Parallel()
	idSigstore := &sapi.Identity{
		Id: "abc",
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://example.com",
			Identity: "joe@example.com",
		},
	}
	idSigstoreOther := &sapi.Identity{
		Id: "abc",
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://nonexistent.com",
			Identity: "mark@hami-ll.com",
		},
	}
	di := defaultIplementation{}
	for _, tt := range []struct {
		name             string
		opts             VerificationOptions
		policyIdentities []*sapi.Identity
		envelopes        []attestation.Envelope
		mustErr          bool
		mustAllow        bool
		admitted         int  // number of envelopes expected to be admitted
		explicit         bool // publish the envelopes as explicit evidence on the context
	}{
		{"no-allowedIdentities-defined", DefaultVerificationOptions, []*sapi.Identity{}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}}},
			},
		}, false, true, 1, false},
		{"no-matching-identities-opts", VerificationOptions{IdentityStrings: []string{idSigstore.Spec()}}, []*sapi.Identity{}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstoreOther}}},
			},
		}, false, false, 0, false},
		{"no-matching-identities-policy", VerificationOptions{IdentityStrings: []string{}}, []*sapi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstoreOther}}},
			},
		}, false, false, 0, false},
		{"ids-in-opts", VerificationOptions{IdentityStrings: []string{idSigstore.Spec()}}, []*sapi.Identity{}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}}},
			},
		}, false, true, 1, false},
		{"ids-in-policy", VerificationOptions{IdentityStrings: []string{}}, []*sapi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{
					Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}},
				},
			},
		}, false, true, 1, false},
		{"ids-in-policy-over-opts-pass", VerificationOptions{IdentityStrings: []string{idSigstoreOther.Spec()}}, []*sapi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{
					Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}},
				},
			},
		}, false, true, 1, false},
		{"ids-in-policy-over-opts-fail", VerificationOptions{IdentityStrings: []string{idSigstore.Spec()}}, []*sapi.Identity{idSigstoreOther}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{
					Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}},
				},
			},
		}, false, false, 0, false},
		// Mixed envelopes: one matches, others don't — should pass and
		// silently discard non-matching envelopes.
		{"mixed-envelopes-one-matches", VerificationOptions{}, []*sapi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}}},
			},
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstoreOther}}},
			},
			&fakeEnvelope{
				ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}},
			},
		}, false, true, 1, false},
		// All envelopes unverified — should fail.
		{"all-unverified", VerificationOptions{}, []*sapi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
		}, false, false, 0, false},
		// No identity constraint: the signature gate still applies. Unverified
		// and unsigned (nil verification) envelopes are rejected, and when
		// nothing survives the check fails with ErrUnverifiedAttestations.
		{"no-constraint-unverified-rejected", VerificationOptions{}, nil, []attestation.Envelope{
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
		}, false, false, 0, false},
		{"no-constraint-unsigned-rejected", VerificationOptions{}, nil, []attestation.Envelope{
			&fakeEnvelope{},
		}, false, false, 0, false},
		{"no-constraint-mixed-keeps-verified", VerificationOptions{}, nil, []attestation.Envelope{
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idSigstore}}}},
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
			&fakeEnvelope{},
		}, false, true, 1, false},
		{"no-constraint-no-evidence", VerificationOptions{}, nil, []attestation.Envelope{}, false, true, 0, false},
		// AdmitUnverified only covers evidence passed explicitly...
		{"admit-unverified-not-explicit", VerificationOptions{AdmitUnverified: true}, nil, []attestation.Envelope{
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
		}, false, false, 0, false},
		{"admit-unverified-explicit", VerificationOptions{AdmitUnverified: true}, nil, []attestation.Envelope{
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
			&fakeEnvelope{},
		}, false, true, 2, true},
		// ... and never applies once signer identities are pinned.
		{"admit-unverified-explicit-with-policy-ids", VerificationOptions{AdmitUnverified: true}, []*sapi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{ver: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false}}},
		}, false, false, 0, true},
		{"admit-unverified-explicit-with-opts-ids", VerificationOptions{AdmitUnverified: true, IdentityStrings: []string{idSigstore.Spec()}}, nil, []attestation.Envelope{
			&fakeEnvelope{},
		}, false, false, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tt.explicit {
				ctx = withExplicitEvidence(ctx, tt.envelopes)
			}
			allow, admissions, idErrors, err := di.CheckIdentities(
				ctx, &tt.opts, tt.policyIdentities, tt.envelopes,
			)

			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.mustAllow, allow)
			require.Len(t, admissions, len(tt.envelopes), "one admission per envelope")
			admitted := 0
			for i, a := range admissions {
				if !a.admitted {
					continue
				}
				admitted++
				v := tt.envelopes[i].GetVerification()
				require.Equal(t, v != nil && v.GetVerified(), a.verified, "admission must carry the real verification outcome")
			}
			require.Equal(t, tt.admitted, admitted)
			if !allow {
				require.NotEmpty(t, idErrors, "a rejected evidence set must explain why")
			}
		})
	}
}

func TestCheckIdentitiesMixedSigners(t *testing.T) {
	t.Parallel()

	idMatch := &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://example.com",
			Identity: "alice@example.com",
		},
	}
	idOther := &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://other.com",
			Identity: "bob@other.com",
		},
	}

	di := defaultIplementation{}
	allow, ids, errs, err := di.CheckIdentities(
		t.Context(),
		&VerificationOptions{},
		[]*sapi.Identity{idMatch},
		[]attestation.Envelope{
			// envelope 0: matches
			&fakeEnvelope{ver: &sapi.Verification{
				Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idMatch}},
			}},
			// envelope 1: wrong identity
			&fakeEnvelope{ver: &sapi.Verification{
				Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idOther}},
			}},
			// envelope 2: not verified
			&fakeEnvelope{ver: &sapi.Verification{
				Signature: &sapi.SignatureVerification{Verified: false},
			}},
		},
	)
	require.NoError(t, err)
	require.True(t, allow, "should allow when at least one envelope matches")
	require.Nil(t, errs)

	// Matching envelope is admitted with its identity; the others are not.
	require.Len(t, ids, 3)
	require.True(t, ids[0].admitted, "envelope 0 should be admitted")
	require.Len(t, ids[0].identities, 1, "envelope 0 should have a matched identity")
	require.False(t, ids[1].admitted, "envelope 1 (wrong identity) must not be admitted")
	require.False(t, ids[2].admitted, "envelope 2 (unverified) must not be admitted")
}

// TestFilterAttestationsAdmissions verifies that FilterAttestations follows the
// admission list: every admitted envelope produces a predicate, and a list that
// does not line up with the envelopes is refused rather than guessed at.
func TestFilterAttestationsAdmissions(t *testing.T) {
	t.Parallel()

	di := defaultIplementation{}
	envs := []attestation.Envelope{
		&fakeEnvelope{pred: &fakePredicate{}},
		&fakeEnvelope{pred: &fakePredicate{}},
		&fakeEnvelope{pred: &fakePredicate{}},
	}
	preds, err := di.FilterAttestations(
		&VerificationOptions{}, nil, envs, []admission{{admitted: true}, {admitted: true}, {admitted: true}},
	)
	require.NoError(t, err)
	require.Len(t, preds, 3, "all admitted envelopes must pass through")

	_, err = di.FilterAttestations(&VerificationOptions{}, nil, envs, nil)
	require.Error(t, err, "a missing admission list must not admit anything")

	_, err = di.FilterAttestations(&VerificationOptions{}, nil, envs, []admission{{admitted: true}})
	require.Error(t, err, "a short admission list must be refused")
}

func TestFilterAttestationsSkipsNonAdmitted(t *testing.T) {
	t.Parallel()

	idMatch := &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://example.com",
			Identity: "alice@example.com",
		},
	}

	di := defaultIplementation{}
	preds, err := di.FilterAttestations(
		&VerificationOptions{},
		nil,
		[]attestation.Envelope{
			&fakeEnvelope{
				pred: &fakePredicate{},
				ver: &sapi.Verification{
					Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idMatch}},
				},
			},
			&fakeEnvelope{
				pred: &fakePredicate{},
				ver: &sapi.Verification{
					Signature: &sapi.SignatureVerification{Verified: false},
				},
			},
			&fakeEnvelope{
				pred: &fakePredicate{},
				ver: &sapi.Verification{
					Signature: &sapi.SignatureVerification{Verified: true, Identities: []*sapi.Identity{idMatch}},
				},
			},
		},
		// Only envelope 0 and 2 were admitted.
		[]admission{
			{admitted: true, verified: true, identities: []*sapi.Identity{idMatch}},
			{},
			{admitted: true, verified: true, identities: []*sapi.Identity{idMatch}},
		},
	)
	require.NoError(t, err)
	require.Len(t, preds, 2, "only admitted envelopes should produce predicates")
}

// TestFilterAttestationsCarriesSigners verifies that FilterAttestations records
// the attestation's actual verified signers on the matchedPredicate (surfaced
// to policies as verification.signers) independently of the matched allowlist
// subset carried on the verification (verification.identities).
func TestFilterAttestationsCarriesSigners(t *testing.T) {
	t.Parallel()

	signerA := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://example.com", Identity: "alice@example.com"}}
	signerB := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://example.com", Identity: "bob@example.com"}}

	di := defaultIplementation{}

	newEnv := func() attestation.Envelope {
		return &fakeEnvelope{
			pred: &fakePredicate{},
			ver: &sapi.Verification{Signature: &sapi.SignatureVerification{
				Verified:   true,
				Identities: []*sapi.Identity{signerA, signerB},
			}},
		}
	}

	// No allowlist (CheckIdentities returns nil ids): identities subset is empty
	// but signers carries the full actual signer set.
	t.Run("no-allowlist", func(t *testing.T) {
		t.Parallel()
		preds, err := di.FilterAttestations(&VerificationOptions{}, nil, []attestation.Envelope{newEnv()}, []admission{{admitted: true, verified: true}})
		require.NoError(t, err)
		require.Len(t, preds, 1)

		mp, ok := preds[0].(*matchedPredicate)
		require.True(t, ok)

		v, ok := mp.GetVerification().(*sapi.Verification)
		require.True(t, ok)
		require.Empty(t, v.GetSignature().GetIdentities(), "matched identities must be empty without an allowlist")

		require.Len(t, mp.Signers(), 2, "signers must carry the full actual signer set")
		require.Same(t, signerA, mp.Signers()[0])
		require.Same(t, signerB, mp.Signers()[1])
	})

	// With an allowlist that matched only signerA: identities is the matched
	// subset while signers remains the full actual set.
	t.Run("with-allowlist", func(t *testing.T) {
		t.Parallel()
		preds, err := di.FilterAttestations(
			&VerificationOptions{}, nil, []attestation.Envelope{newEnv()},
			[]admission{{admitted: true, verified: true, identities: []*sapi.Identity{signerA}}},
		)
		require.NoError(t, err)
		require.Len(t, preds, 1)

		mp, ok := preds[0].(*matchedPredicate)
		require.True(t, ok)

		v, ok := mp.GetVerification().(*sapi.Verification)
		require.True(t, ok)
		require.Len(t, v.GetSignature().GetIdentities(), 1, "identities must be the matched subset")
		require.Same(t, signerA, v.GetSignature().GetIdentities()[0])

		require.Len(t, mp.Signers(), 2, "signers must remain the full actual set")
	})

	// An admitted envelope without verification (explicit unverified evidence)
	// reaches the policy honestly marked as not verified, with no signers.
	t.Run("nil-verification", func(t *testing.T) {
		t.Parallel()
		preds, err := di.FilterAttestations(
			&VerificationOptions{}, nil,
			[]attestation.Envelope{&fakeEnvelope{pred: &fakePredicate{}}}, []admission{{admitted: true}},
		)
		require.NoError(t, err)
		require.Len(t, preds, 1)
		mp, ok := preds[0].(*matchedPredicate)
		require.True(t, ok)
		require.Empty(t, mp.Signers())
		require.False(t, mp.GetVerification().GetVerified(), "unverified evidence must not be stamped as verified")
	})
}

// TestCheckIdentitiesNoAllowlistVerifies verifies that CheckIdentities still
// verifies the envelope signatures when no identity allowlist is defined, so
// the actual signers get recorded on the envelope verification and surface to
// policies as verification.signers (via FilterAttestations).
func TestCheckIdentitiesNoAllowlistVerifies(t *testing.T) {
	t.Parallel()

	signer := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://example.com", Identity: "alice@example.com"}}
	env := &fakeEnvelope{
		pred: &fakePredicate{},
		verOnVerify: &sapi.Verification{Signature: &sapi.SignatureVerification{
			Verified:   true,
			Identities: []*sapi.Identity{signer},
		}},
	}

	di := defaultIplementation{}
	pass, ids, idErrors, err := di.CheckIdentities(context.Background(), &VerificationOptions{}, nil, []attestation.Envelope{env})
	require.NoError(t, err)
	require.Empty(t, idErrors)
	require.True(t, pass)
	require.Len(t, ids, 1)
	require.True(t, ids[0].admitted)
	require.True(t, ids[0].verified)
	require.Empty(t, ids[0].identities, "no allowlist means no matched identities")

	preds, err := di.FilterAttestations(&VerificationOptions{}, nil, []attestation.Envelope{env}, ids)
	require.NoError(t, err)
	require.Len(t, preds, 1)
	mp, ok := preds[0].(*matchedPredicate)
	require.True(t, ok)
	require.True(t, mp.GetVerification().GetVerified(), "verified evidence must be stamped as verified")
	require.Len(t, mp.Signers(), 1, "signers must carry the identities recorded during verification")
	require.Same(t, signer, mp.Signers()[0])
}

// TestProcessChainedSubjectsPropagatesFailFlag verifies that ProcessChainedSubjects
// propagates policyFail=true when evaluateChain returns both an error and fail=true.
// This covers the bug where the fail flag was discarded (hardcoded false) on error.
//
// The scenario: a chain link requires predicate type "https://example.com/nonexistent"
// but the loaded attestation is an SPDX document. evaluateChain finds no matching
// attestations and returns (nil, nil, true, PolicyError{...}). ProcessChainedSubjects
// must surface fail=true to the caller unchanged.
func TestProcessChainedSubjectsPropagatesFailFlag(t *testing.T) {
	t.Parallel()

	di := &defaultIplementation{}
	factory := evaluator.Factory{}

	def, err := factory.Get(&eoptions.Default, DefaultVerificationOptions.DefaultEvaluator)
	require.NoError(t, err)
	evaluators := map[class.Class]evaluator.Evaluator{
		defaultEvaluatorClass:                       def,
		DefaultVerificationOptions.DefaultEvaluator: def,
	}

	subject := &gointoto.ResourceDescriptor{
		Name: "test",
		Digest: map[string]string{
			"sha256": "851074691728c479a4c83628de8310eaca792cc7",
		},
	}

	// Build a policy with a chain link that requires a predicate type that does
	// not exist in the loaded attestation. evaluateChain will return fail=true
	// with a PolicyError when no matching attestations are found.
	policy := &papi.Policy{
		Chain: []*papi.ChainLink{
			{
				Source: &papi.ChainLink_Predicate{
					Predicate: &papi.ChainedPredicate{
						Type:     "https://example.com/nonexistent",
						Selector: `"sha256:0000000000000000000000000000000000000000000000000000000000000000"`,
					},
				},
			},
		},
	}

	opts := DefaultVerificationOptions
	opts.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json"}

	attestations, err := di.ParseAttestations(t.Context(), &opts, subject)
	require.NoError(t, err)

	_, _, fail, gotErr := di.ProcessChainedSubjects(
		t.Context(), &opts, evaluators,
		nil, // collector agent not required for this test
		policy,
		nil, // no context values
		subject,
		attestations,
	)

	require.Error(t, gotErr, "ProcessChainedSubjects must return an error when the chain cannot be satisfied")
	require.True(t, fail, "policyFail must be true when evaluateChain returns fail=true with an error")
	require.IsType(t, PolicyError{}, gotErr, "error must be a PolicyError") //nolint:testifylint // Checking for type, not value
}

// TestProcessPolicySetChainedSubjectsPropagatesFailFlag is the PolicySet
// equivalent of TestProcessChainedSubjectsPropagatesFailFlag. It verifies that
// ProcessPolicySetChainedSubjects propagates policyFail=true when evaluateChain
// returns both an error and fail=true, rather than hardcoding false.
func TestProcessPolicySetChainedSubjectsPropagatesFailFlag(t *testing.T) {
	t.Parallel()

	di := &defaultIplementation{}
	factory := evaluator.Factory{}

	def, err := factory.Get(&eoptions.Default, DefaultVerificationOptions.DefaultEvaluator)
	require.NoError(t, err)
	evaluators := map[class.Class]evaluator.Evaluator{
		defaultEvaluatorClass:                       def,
		DefaultVerificationOptions.DefaultEvaluator: def,
	}

	subject := &gointoto.ResourceDescriptor{
		Name: "test",
		Digest: map[string]string{
			"sha256": "851074691728c479a4c83628de8310eaca792cc7",
		},
	}

	policySet := &papi.PolicySet{
		Chain: []*papi.ChainLink{
			{
				Source: &papi.ChainLink_Predicate{
					Predicate: &papi.ChainedPredicate{
						Type:     "https://example.com/nonexistent",
						Selector: `"sha256:0000000000000000000000000000000000000000000000000000000000000000"`,
					},
				},
			},
		},
	}

	opts := DefaultVerificationOptions
	opts.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json"}

	attestations, err := di.ParseAttestations(t.Context(), &opts, subject)
	require.NoError(t, err)

	_, _, fail, gotErr := di.ProcessPolicySetChainedSubjects(
		t.Context(), &opts, evaluators,
		nil,
		policySet,
		nil,
		subject,
		attestations,
	)

	require.Error(t, gotErr)
	require.True(t, fail, "policyFail must be true when evaluateChain returns fail=true with an error")
	require.IsType(t, PolicyError{}, gotErr, "error must be a PolicyError") //nolint:testifylint // Checking for type, not value
}

// TestVerifySubjectErrOnMissingAttestations covers the ErrOnMissingAttestations
// option: when off (default) a tenet that requires predicates but receives none
// produces a failed EvalResult with the sentinel in Error.Message and no
// top-level error; when on, the same condition additionally returns the
// sentinel as a Go error so callers can detect it via errors.Is.
func TestVerifySubjectErrOnMissingAttestations(t *testing.T) {
	t.Parallel()

	policy := &papi.Policy{
		Id: "needs-predicate",
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: "true",
			Predicates: &papi.PredicateSpec{
				Types: []string{"https://example.com/predicate"},
			},
		}},
	}
	subject := &gointoto.ResourceDescriptor{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
	}
	evaluators := map[class.Class]evaluator.Evaluator{}

	for _, tc := range []struct {
		name             string
		errOnMissing     bool
		wantErrIsMissing bool
	}{
		{"off-default", false, false},
		{"on", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			di := &defaultIplementation{}
			opts := &VerificationOptions{
				EvaluatorOptions:         eoptions.Default,
				DefaultEvaluator:         DefaultVerificationOptions.DefaultEvaluator,
				ErrOnMissingAttestations: tc.errOnMissing,
			}

			result, err := di.VerifySubject(
				context.Background(), opts, evaluators, policy,
				map[string]any{}, subject, []attestation.Predicate{},
			)

			if tc.wantErrIsMissing {
				require.ErrorIs(t, err, ErrMissingAttestations)
			} else {
				require.NoError(t, err)
			}

			// Result is populated identically in both cases — the EvalResult
			// always carries the sentinel string so consumers retain detail.
			require.NotNil(t, result)
			require.Len(t, result.EvalResults, 1)
			require.Equal(t, papi.StatusFAIL, result.EvalResults[0].GetStatus())
			require.NotNil(t, result.EvalResults[0].GetError())
			require.Equal(t, ErrMissingAttestations.Error(), result.EvalResults[0].GetError().GetMessage())
		})
	}
}

func TestRenderIdentities(t *testing.T) {
	t.Parallel()
	sigstoreID := func(issuer, id string) *sapi.Identity {
		return &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: issuer, Identity: id}}
	}

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "(none)", renderIdentities(nil, (*sapi.Identity).Principal))
	})

	t.Run("dedup", func(t *testing.T) {
		t.Parallel()
		id := sigstoreID("https://issuer", "user@example.com")
		require.Equal(t,
			"sigstore::https://issuer::user@example.com",
			renderIdentities([]*sapi.Identity{id, id}, (*sapi.Identity).Principal),
		)
	})

	t.Run("multiple", func(t *testing.T) {
		t.Parallel()
		got := renderIdentities([]*sapi.Identity{
			sigstoreID("https://issuer", "a"),
			sigstoreID("https://issuer", "b"),
		}, (*sapi.Identity).Principal)
		require.Contains(t, got, "sigstore::https://issuer::a")
		require.Contains(t, got, "sigstore::https://issuer::b")
		require.Contains(t, got, ", ")
	})
}

func TestIdentityMismatchError(t *testing.T) {
	t.Parallel()
	wanted := []*sapi.Identity{{Sigstore: &sapi.IdentitySigstore{Issuer: "https://issuer", Identity: "expected"}}}

	t.Run("no-signer-observed", func(t *testing.T) {
		t.Parallel()
		err := identityMismatchError(wanted, nil, 0)
		require.Contains(t, err.Error(), "no attestation carried a verified signer identity")
		require.Contains(t, err.Error(), "sigstore::https://issuer::expected")
	})

	t.Run("mismatch", func(t *testing.T) {
		t.Parallel()
		got := []*sapi.Identity{{Sigstore: &sapi.IdentitySigstore{Issuer: "https://issuer", Identity: "actual"}}}
		err := identityMismatchError(wanted, got, 0)
		require.Contains(t, err.Error(), "does not match an accepted identity")
		require.Contains(t, err.Error(), "wanted one of: sigstore::https://issuer::expected")
		require.Contains(t, err.Error(), "got: sigstore::https://issuer::actual")
	})
}
