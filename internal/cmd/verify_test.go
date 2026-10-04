// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"

	signerOpts "github.com/carabiner-dev/signer/options"

	"github.com/carabiner-dev/ampel/pkg/verifier"
)

// TestVerifyOptions_SignGate locks in the rule that --sign is valid
// only when there is somewhere to write the produced attestation:
// either --attest-results (file output) or --format=attestation|
// vsa|svr (stdout output). Catches regressions of the gap where
// --sign was wired only to --attest-results.
func TestVerifyOptions_SignGate(t *testing.T) {
	const wantSignSubstr = "--sign requires --attest-results"

	base := func() verifyOptions {
		o := verifyOptions{
			VerificationOptions: verifier.NewVerificationOptions(),
			SignerSet:           signerOpts.DefaultSignerSet(),
			SubjectHash:         "sha256:abc123",
			PolicyLocation:      "/tmp/policy.json",
			Format:              "tty",
		}
		// Satisfy the unrelated "no attestation sources" check so
		// Validate doesn't short-circuit before the --sign gate.
		o.AttestationFiles = []string{"x"}
		return o
	}

	cases := []struct {
		name          string
		sign          bool
		attestResults bool
		format        string
		wantSignError bool
	}{
		{"no sign no gate", false, false, "tty", false},
		{"sign without target", true, false, "tty", true},
		{"sign with attest-results", true, true, "tty", false},
		{"sign with format=attestation", true, false, "attestation", false},
		{"sign with format=vsa", true, false, "vsa", false},
		{"sign with format=svr", true, false, "svr", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			o.Sign = tc.sign
			o.AttestResults = tc.attestResults
			o.Format = tc.format
			err := o.Validate()
			// Validate may surface unrelated errors (e.g. nonexistent
			// policy path); we only care about the --sign gate
			// message here.
			haveSignError := err != nil && strings.Contains(err.Error(), wantSignSubstr)
			if haveSignError != tc.wantSignError {
				t.Errorf("haveSignError=%v want=%v; full err=%v", haveSignError, tc.wantSignError, err)
			}
		})
	}
}
