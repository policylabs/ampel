// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"os"
	"testing"

	"github.com/carabiner-dev/osv/go/osv"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/openvex"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func vexPathsToPredicates(t *testing.T, paths []string) []attestation.Predicate {
	t.Helper()
	ret := make([]attestation.Predicate, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		pred, err := openvex.New().Parse(data)
		require.NoError(t, err)
		ret = append(ret, pred)
	}
	return ret
}

func TestApplyVEX(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		vexes            []string
		expectedPackages int
		// expectedVulns []string
	}{
		{name: "test", vexes: nil, expectedPackages: 2},
		{name: "test", vexes: []string{"testdata/CVE-2025-27144.openvex.json"}, expectedPackages: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xform := Transformer{}

			data, err := os.ReadFile("testdata/osv.json")
			require.NoError(t, err)
			results := osv.Results{}

			require.NoError(t, protojson.UnmarshalOptions{
				DiscardUnknown: true,
			}.Unmarshal(data, &results))
			require.NoError(t, err)

			// Parse all predicates
			res, err := xform.ApplyVEX(&gointoto.ResourceDescriptor{
				Digest: map[string]string{
					gointoto.AlgorithmSHA256.String(): "9579c854c652497e48a7bfc278149b12bdd0e3c2189f0c3b42bda4366cf9b15d",
				},
			}, &results, vexPathsToPredicates(t, tc.vexes))
			require.NoError(t, err)

			require.NotNil(t, res)
			require.NotNil(t, res.GetParsed())
			osvReport, ok := res.GetParsed().(*osv.Results)
			require.True(t, ok)

			require.Len(t, osvReport.GetResults(), 1)
			require.Len(t, osvReport.GetResults()[0].Packages, tc.expectedPackages)
		})
	}
}
