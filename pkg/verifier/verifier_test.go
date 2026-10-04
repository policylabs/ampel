// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"
	"time"

	gointoto "github.com/in-toto/attestation/go/v1"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/policylabs/ampel/pkg/evaluator/options"
)

func TestPolicySetExpiration(t *testing.T) {
	sub := &gointoto.ResourceDescriptor{}
	t.Parallel()
	for _, tt := range []struct {
		name      string
		mustPass  bool
		mustErr   bool
		opts      *VerificationOptions
		policySet *papi.PolicySet
	}{
		{
			"normal", true, false, &DefaultVerificationOptions,
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
		{
			"expired", false, false, &DefaultVerificationOptions,
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
		{
			"valid-with-opts-disabled", true, false, &VerificationOptions{EnforceExpiration: false, EvaluatorOptions: options.Default},
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
		{
			"expired-with-opts-disabled", true, false, &VerificationOptions{EnforceExpiration: false, EvaluatorOptions: options.Default},
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ampel := &Ampel{
				impl: &defaultIplementation{},
			}
			res, err := ampel.Verify(t.Context(), tt.opts, tt.policySet, sub)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.mustPass, res.GetStatus() == papi.StatusPASS)
		})
	}
}
