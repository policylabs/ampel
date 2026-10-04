// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/policy"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/signer"
	"github.com/policylabs/signer/key"
	soptions "github.com/policylabs/signer/options"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/policylabs/ampel/pkg/verifier"
)

// The admission matrix. Evidence is admitted only when its signature verified
// (bundles against the sigstore roots, DSSE envelopes against the keys the
// verifier holds); bare statements and envelopes signed with unknown keys are
// unverified. AdmitUnverified admits unverified evidence passed explicitly,
// and never applies once the policy pins signer identities. The outcome must
// be the same whichever way the attestation was signed. Sigstore verification
// of the genuine bundle hits the trust root over TUF (network).

const (
	dssePredicateType   = "https://example.com/ampel/admission/v1"
	bundlePredicateType = "https://slsa.dev/provenance/v0.2"
	// Digest of the DSSE / bare fixture subject.
	dsseSubjectDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// Digest of the subject in testdata/github-actions-bundle.json.
	bundleSubjectDigest = "76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751"

	unverifiedFailure = "no verified attestations available to evaluate the policy"
	identityFailure   = "attestation identity validation failed"
)

// keyPair is an ECDSA P-256 key in the PEM forms the signer library reads.
type keyPair struct {
	privPEM, pubPEM []byte
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return keyPair{
		privPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pubPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
	}
}

func (kp keyPair) provider(t *testing.T) key.PublicKeyProvider {
	t.Helper()
	p, err := key.NewParser().ParsePublicKeyProvider(kp.pubPEM)
	require.NoError(t, err)
	return p
}

// tamperPayload rewrites a JSON file, appending a byte to the base64 payload
// found under the given key path so the signature no longer covers it.
func tamperPayload(t *testing.T, in, out string, path ...string) {
	t.Helper()
	data, err := os.ReadFile(in)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	node := doc
	for _, k := range path[:len(path)-1] {
		next, ok := node[k].(map[string]any)
		require.True(t, ok, "missing %q in %s", k, in)
		node = next
	}
	last := path[len(path)-1]
	payload, ok := node[last].(string)
	require.True(t, ok)
	raw, err := base64.StdEncoding.DecodeString(payload)
	require.NoError(t, err)
	node[last] = base64.StdEncoding.EncodeToString(append(raw, ' '))
	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, tampered, 0o600))
}

// fixtures writes the evidence files: a bare statement, the same statement
// signed as a DSSE envelope with signingKey, a tampered copy of it, and a
// tampered copy of the genuine GitHub Actions bundle.
type fixtures struct {
	bare, dsse, dsseTampered, bundle, bundleTampered string
}

func makeFixtures(t *testing.T, signingKey keyPair) fixtures {
	t.Helper()
	dir := t.TempDir()

	pred, err := structpb.NewStruct(map[string]any{"a": 1})
	require.NoError(t, err)
	stmt := &gointoto.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []*gointoto.ResourceDescriptor{{Name: "artifact", Digest: map[string]string{"sha256": dsseSubjectDigest}}},
		PredicateType: dssePredicateType,
		Predicate:     pred,
	}
	stmtJSON, err := protojson.Marshal(stmt)
	require.NoError(t, err)

	f := fixtures{
		bare:           filepath.Join(dir, "bare.json"),
		dsse:           filepath.Join(dir, "dsse.json"),
		dsseTampered:   filepath.Join(dir, "dsse-tampered.json"),
		bundle:         "testdata/github-actions-bundle.json",
		bundleTampered: filepath.Join(dir, "bundle-tampered.json"),
	}
	require.NoError(t, os.WriteFile(f.bare, stmtJSON, 0o600))

	priv, err := key.NewParser().ParsePrivateKeyProvider(signingKey.privPEM)
	require.NoError(t, err)
	env, err := signer.NewSigner().SignStatementToDSSE(stmtJSON, soptions.WithKey(priv))
	require.NoError(t, err)
	envJSON, err := protojson.Marshal(env)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.dsse, envJSON, 0o600))

	tamperPayload(t, f.dsse, f.dsseTampered, "payload")
	tamperPayload(t, f.bundle, f.bundleTampered, "dsseEnvelope", "payload")
	return f
}

// compilePolicy builds a policy requiring one predicate of the given type,
// optionally pinning signer identities (a JSON array fragment).
func compilePolicy(t *testing.T, predicateType, identities string) any {
	t.Helper()
	ids := ""
	if identities != "" {
		ids = fmt.Sprintf(`"identities": %s,`, identities)
	}
	src := fmt.Sprintf(`{
		"id": "admission",
		%s
		"tenets": [{
			"id": "t",
			"code": "size(predicates) > 0",
			"predicates": {"types": [%q]}
		}]
	}`, ids, predicateType)
	set, pcy, _, err := policy.NewCompiler().Compile([]byte(src))
	require.NoError(t, err)
	if set != nil {
		return set
	}
	require.NotNil(t, pcy)
	return pcy
}

func keyIdentity(t *testing.T, kp keyPair) string {
	t.Helper()
	data, err := json.Marshal(string(kp.pubPEM))
	require.NoError(t, err)
	return fmt.Sprintf(`[{"key": {"data": %s}}]`, data)
}

func sigstoreIdentity(repo string) string {
	return fmt.Sprintf(`[{"sigstore": {
		"issuerMatch": {"exact": "https://token.actions.githubusercontent.com"},
		"sourceRepositoryUriMatch": {"exact": %q}
	}}]`, repo)
}

func failureMessages(t *testing.T, res papi.Results) []string {
	t.Helper()
	var results []*papi.Result
	switch r := res.(type) {
	case *papi.Result:
		results = []*papi.Result{r}
	case *papi.ResultSet:
		results = r.GetResults()
	default:
		t.Fatalf("unexpected results type %T", res)
	}
	var msgs []string
	for _, r := range results {
		for _, er := range r.GetEvalResults() {
			if er.GetError() != nil {
				msgs = append(msgs, er.GetError().GetMessage())
			}
		}
	}
	return msgs
}

func TestSignatureAdmissionMatrix(t *testing.T) {
	right, wrong := newKeyPair(t), newKeyPair(t)
	fx := makeFixtures(t, right)

	dsseSubject := &gointoto.ResourceDescriptor{Digest: map[string]string{"sha256": dsseSubjectDigest}}
	bundleSubject := &gointoto.ResourceDescriptor{Digest: map[string]string{"sha512": bundleSubjectDigest}}

	for _, tc := range []struct {
		name       string
		evidence   string
		subject    *gointoto.ResourceDescriptor
		policyType string
		identities string // policy identities JSON fragment, "" for none
		keys       []key.PublicKeyProvider
		admit      bool // AdmitUnverified (the CLI's -a opt-in)
		status     string
		failure    string // expected failure message when status is FAIL
	}{
		// --- sigstore bundle -------------------------------------------------
		{"bundle/genuine", fx.bundle, bundleSubject, bundlePredicateType, "", nil, false, papi.StatusPASS, ""},
		{"bundle/tampered", fx.bundleTampered, bundleSubject, bundlePredicateType, "", nil, false, papi.StatusFAIL, unverifiedFailure},
		{"bundle/tampered/opt-in", fx.bundleTampered, bundleSubject, bundlePredicateType, "", nil, true, papi.StatusPASS, ""},
		{"bundle/genuine/identity-match", fx.bundle, bundleSubject, bundlePredicateType, sigstoreIdentity("https://github.com/sigstore/sigstore-js"), nil, false, papi.StatusPASS, ""},
		{"bundle/genuine/identity-mismatch", fx.bundle, bundleSubject, bundlePredicateType, sigstoreIdentity("https://github.com/evil/repo"), nil, false, papi.StatusFAIL, identityFailure},
		{"bundle/tampered/identity/opt-in", fx.bundleTampered, bundleSubject, bundlePredicateType, sigstoreIdentity("https://github.com/sigstore/sigstore-js"), nil, true, papi.StatusFAIL, identityFailure},

		// --- key-signed DSSE envelope ---------------------------------------
		{"dsse/right-key", fx.dsse, dsseSubject, dssePredicateType, "", []key.PublicKeyProvider{right.provider(t)}, false, papi.StatusPASS, ""},
		{"dsse/wrong-key", fx.dsse, dsseSubject, dssePredicateType, "", []key.PublicKeyProvider{wrong.provider(t)}, false, papi.StatusFAIL, unverifiedFailure},
		{"dsse/no-key", fx.dsse, dsseSubject, dssePredicateType, "", nil, false, papi.StatusFAIL, unverifiedFailure},
		{"dsse/no-key/opt-in", fx.dsse, dsseSubject, dssePredicateType, "", nil, true, papi.StatusPASS, ""},
		{"dsse/tampered/right-key", fx.dsseTampered, dsseSubject, dssePredicateType, "", []key.PublicKeyProvider{right.provider(t)}, false, papi.StatusFAIL, unverifiedFailure},
		{"dsse/policy-key-match", fx.dsse, dsseSubject, dssePredicateType, keyIdentity(t, right), nil, false, papi.StatusPASS, ""},
		{"dsse/policy-key-mismatch", fx.dsse, dsseSubject, dssePredicateType, keyIdentity(t, wrong), nil, false, papi.StatusFAIL, identityFailure},
		{"dsse/policy-key-mismatch/opt-in", fx.dsse, dsseSubject, dssePredicateType, keyIdentity(t, wrong), nil, true, papi.StatusFAIL, identityFailure},
		{"dsse/tampered/policy-key/opt-in", fx.dsseTampered, dsseSubject, dssePredicateType, keyIdentity(t, right), nil, true, papi.StatusFAIL, identityFailure},

		// --- bare (unsigned) statement --------------------------------------
		{"bare", fx.bare, dsseSubject, dssePredicateType, "", nil, false, papi.StatusFAIL, unverifiedFailure},
		{"bare/opt-in", fx.bare, dsseSubject, dssePredicateType, "", nil, true, papi.StatusPASS, ""},
		{"bare/identity/opt-in", fx.bare, dsseSubject, dssePredicateType, keyIdentity(t, right), nil, true, papi.StatusFAIL, identityFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ampel, err := verifier.New()
			require.NoError(t, err)
			opts := verifier.NewVerificationOptions()
			opts.EnforceExpiration = false
			opts.AttestationFiles = []string{tc.evidence}
			opts.Keys = tc.keys
			opts.AdmitUnverified = tc.admit

			res, err := ampel.Verify(t.Context(), &opts, compilePolicy(t, tc.policyType, tc.identities), tc.subject)
			require.NoError(t, err)
			require.Equal(t, tc.status, res.GetStatus(), "failures: %v", failureMessages(t, res))
			if tc.failure != "" {
				require.Contains(t, failureMessages(t, res), tc.failure)
			}
		})
	}
}
