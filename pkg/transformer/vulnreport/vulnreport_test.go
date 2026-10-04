// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"os"
	"testing"

	"github.com/carabiner-dev/osv/go/osv"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/generic"
	cosv "github.com/policylabs/collector/predicate/osv"
	ctrivy "github.com/policylabs/collector/predicate/trivy"
	cvulns "github.com/policylabs/collector/predicate/vulns"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func predicate(t *testing.T, predType attestation.PredicateType, path string) attestation.Predicate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return &generic.Predicate{Type: predType, Data: data}
}

func TestMutate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		inputType attestation.PredicateType
		dataPath  string
		output    string
		wantType  attestation.PredicateType
		validate  func(*testing.T, attestation.Predicate)
	}{
		{
			name:      "trivy-default-osv",
			inputType: ctrivy.PredicateType,
			dataPath:  "testdata/trivy.json",
			output:    "",
			wantType:  cosv.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				results, ok := pred.GetParsed().(*osv.Results)
				require.True(t, ok, "parsed predicate must be *osv.Results")
				require.NotEmpty(t, results.GetResults())
			},
		},
		{
			name:      "trivy-vulnreport",
			inputType: ctrivy.PredicateType,
			dataPath:  "testdata/trivy.json",
			output:    OutputVulnReport,
			wantType:  cvulns.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				report, ok := pred.GetParsed().(*v02.Vulns)
				require.True(t, ok, "parsed predicate must be *v02.Vulns")
				require.Equal(t, "https://trivy.dev", report.GetScanner().GetUri())
				require.NotEmpty(t, report.GetScanner().GetResult())
				first := report.GetScanner().GetResult()[0]
				require.NotEmpty(t, first.GetId())
				require.NotEmpty(t, first.GetAnnotations())
			},
		},
		{
			name:      "grype-vulnreport",
			inputType: GrypePredicateType,
			dataPath:  "testdata/grype.json",
			output:    OutputVulnReport,
			wantType:  cvulns.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				report, ok := pred.GetParsed().(*v02.Vulns)
				require.True(t, ok, "parsed predicate must be *v02.Vulns")
				require.Equal(t, "https://github.com/anchore/grype", report.GetScanner().GetUri())
				require.NotEmpty(t, report.GetScanner().GetResult())
			},
		},
		{
			name:      "grype-default-osv",
			inputType: GrypePredicateType,
			dataPath:  "testdata/grype.json",
			output:    OutputOSV,
			wantType:  cosv.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				results, ok := pred.GetParsed().(*osv.Results)
				require.True(t, ok, "parsed predicate must be *osv.Results")
				require.NotEmpty(t, results.GetResults())
			},
		},
		{
			name:      "osvscanner-passthrough-osv",
			inputType: cosv.PredicateType,
			dataPath:  "testdata/osv-scanner.json",
			output:    OutputOSV,
			wantType:  cosv.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				results, ok := pred.GetParsed().(*osv.Results)
				require.True(t, ok, "parsed predicate must be *osv.Results")
				require.NotEmpty(t, results.GetResults())
			},
		},
		{
			name:      "osvscanner-vulnreport",
			inputType: cosv.PredicateType,
			dataPath:  "testdata/osv-scanner.json",
			output:    OutputVulnReport,
			wantType:  cvulns.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				report, ok := pred.GetParsed().(*v02.Vulns)
				require.True(t, ok, "parsed predicate must be *v02.Vulns")
				require.Equal(t, "https://github.com/google/osv-scanner", report.GetScanner().GetUri())
			},
		},
		{
			// A predicate still typed with the legacy @v1.6.7 OSV type (i.e. not
			// normalized upstream) is accepted via the parser's dual-read and
			// emitted as the current @v1 OSV type.
			name:      "osvscanner-legacy-type-accepted",
			inputType: legacyOSVPredicateType,
			dataPath:  "testdata/osv-scanner.json",
			output:    OutputOSV,
			wantType:  cosv.PredicateType,
			validate: func(t *testing.T, pred attestation.Predicate) {
				t.Helper()
				results, ok := pred.GetParsed().(*osv.Results)
				require.True(t, ok, "parsed predicate must be *osv.Results")
				require.NotEmpty(t, results.GetResults())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			xformer := New()
			var config *structpb.Struct
			if tc.output != "" {
				config = mustStruct(t, map[string]any{"output": tc.output})
			}
			require.NoError(t, xformer.Init(config))

			_, ret, err := xformer.Mutate(nil, []attestation.Predicate{
				predicate(t, tc.inputType, tc.dataPath),
			})
			require.NoError(t, err)
			require.Len(t, ret, 1)
			require.Equal(t, tc.wantType, ret[0].GetType())
			if tc.validate != nil {
				tc.validate(t, ret[0])
			}
		})
	}
}

func TestMutateSkipsUnknownPredicate(t *testing.T) {
	t.Parallel()
	xformer := New()
	require.NoError(t, xformer.Init(nil))
	_, ret, err := xformer.Mutate(nil, []attestation.Predicate{
		&generic.Predicate{Type: attestation.PredicateType("https://example.com/unknown"), Data: []byte("{}")},
	})
	require.NoError(t, err)
	require.Empty(t, ret)
}

func TestInitRejectsUnknownOutput(t *testing.T) {
	t.Parallel()
	xformer := New()
	err := xformer.Init(mustStruct(t, map[string]any{"output": "totally-bogus"}))
	require.Error(t, err)
}

func TestMutateParseError(t *testing.T) {
	t.Parallel()
	xformer := New()
	require.NoError(t, xformer.Init(nil))
	// A predicate of a supported type whose payload is not valid scanner JSON
	// must surface a conversion error rather than being silently dropped.
	_, _, err := xformer.Mutate(nil, []attestation.Predicate{
		&generic.Predicate{Type: ctrivy.PredicateType, Data: []byte("not json")},
	})
	require.Error(t, err)
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}
