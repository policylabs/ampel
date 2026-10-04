// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

// sampleData mirrors the JSON shape of an OSV results predicate: two
// vulnerabilities across two packages — a critical, aliased, already-fixed Go
// finding and an unfixed medium PyPI finding.
func sampleData() map[string]any {
	return map[string]any{
		"results": []any{
			map[string]any{
				"source": map[string]any{"path": "go.mod", "type": "lockfile"},
				"packages": []any{
					map[string]any{
						"package": map[string]any{"name": "github.com/x/y", "ecosystem": "Go"},
						"vulnerabilities": []any{
							map[string]any{
								"id":      "GHSA-aaaa-bbbb-cccc",
								"aliases": []any{"CVE-2026-0001"},
								"severity": []any{
									map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
								},
								"affected": []any{
									map[string]any{
										"package": map[string]any{"name": "github.com/x/y", "ecosystem": "Go", "purl": "pkg:golang/github.com/x/y@1.2.0"},
										"ranges": []any{
											map[string]any{"type": "ECOSYSTEM", "events": []any{
												map[string]any{"introduced": "0"},
												map[string]any{"fixed": "1.3.0"},
											}},
										},
									},
								},
								"references": []any{
									map[string]any{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"},
									map[string]any{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
								},
								"database_specific": map[string]any{
									"severity":        "CRITICAL",
									"risk":            0.34,
									"epss":            0.88,
									"known_exploited": true,
									"cwe_ids":         []any{"CWE-89"},
								},
							},
						},
					},
					map[string]any{
						"package": map[string]any{"name": "requests", "ecosystem": "PyPI"},
						"vulnerabilities": []any{
							map[string]any{
								"id": "CVE-2026-0002",
								"severity": []any{
									map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"},
								},
								"affected": []any{
									map[string]any{
										"package": map[string]any{"name": "requests", "ecosystem": "PyPI", "purl": "pkg:pypi/requests@2.0"},
										"ranges": []any{
											map[string]any{"type": "ECOSYSTEM", "events": []any{
												map[string]any{"introduced": "0"},
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func run(t *testing.T, expr string, data any) any {
	t.Helper()
	p := New()
	env, err := cel.NewEnv(p.Library(), cel.Variable("data", cel.DynType))
	require.NoError(t, err)
	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err(), "compile %q", expr)
	program, err := env.Program(ast)
	require.NoError(t, err)
	vars := p.VarValues(nil, nil, nil)
	vars["data"] = data
	result, _, err := program.Eval(vars)
	require.NoError(t, err, "eval %q", expr)
	return result.Value()
}

func TestVulnsAndIDs(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(2), run(t, "size(osv.vulns(data))", sampleData()))
	require.Equal(t, true, run(t, "osv.ids(data) == ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0002']", sampleData()))
	// The returned vulns are usable objects.
	require.Equal(t, "GHSA-aaaa-bbbb-cccc", run(t, "osv.vulns(data)[0].id", sampleData()))
}

func TestAliasesAndMatchesID(t *testing.T) {
	t.Parallel()
	require.Equal(t, true, run(t, "osv.aliases(osv.vulns(data)[0]) == ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001']", sampleData()))
	// Match by primary id and by alias, and reject a non-match.
	require.Equal(t, true, run(t, "osv.matchesID(osv.vulns(data)[0], 'GHSA-aaaa-bbbb-cccc')", sampleData()))
	require.Equal(t, true, run(t, "osv.matchesID(osv.vulns(data)[0], 'CVE-2026-0001')", sampleData()))
	require.Equal(t, false, run(t, "osv.matchesID(osv.vulns(data)[0], 'CVE-9999-9999')", sampleData()))
	// The alias-aware form composes into a document-level check.
	require.Equal(t, true, run(t, "osv.vulns(data).exists(v, osv.matchesID(v, 'CVE-2026-0001'))", sampleData()))
}

func TestCVSS(t *testing.T) {
	t.Parallel()
	require.InDelta(t, 9.8, run(t, "osv.cvss(osv.vulns(data)[0])", sampleData()), 0.05)
	// A realistic policy: any fixable-or-not critical present.
	require.Equal(t, true, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0)", sampleData()))
	require.Equal(t, false, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0 && osv.matchesID(v, 'CVE-2026-0002'))", sampleData()))
}

func TestUnwrapsPredicate(t *testing.T) {
	t.Parallel()
	// Passing a whole predicate (with a data key) works the same as its data.
	pred := map[string]any{
		"predicate_type": "https://ossf.github.io/osv-schema/results@v1",
		"data":           sampleData(),
	}
	require.Equal(t, int64(2), run(t, "size(osv.vulns(data))", pred))
}

func TestFixStatus(t *testing.T) {
	t.Parallel()
	require.Equal(t, true, run(t, "osv.isFixed(osv.vulns(data)[0])", sampleData()))
	require.Equal(t, false, run(t, "osv.isFixed(osv.vulns(data)[1])", sampleData()))
	require.Equal(t, true, run(t, "osv.fixedVersions(osv.vulns(data)[0]) == ['1.3.0']", sampleData()))
	require.Equal(t, int64(0), run(t, "size(osv.fixedVersions(osv.vulns(data)[1]))", sampleData()))
}

func TestSeverityLabel(t *testing.T) {
	t.Parallel()
	// Derived from the highest CVSS vector.
	require.Equal(t, "CRITICAL", run(t, "osv.severityLabel(osv.vulns(data)[0])", sampleData()))
	// Falls back to the scanner's own label (upper-cased) when there is no CVSS.
	require.Equal(t, "HIGH", run(t, "osv.severityLabel({'database_specific': {'severity': 'high'}})", sampleData()))
	require.Empty(t, run(t, "osv.severityLabel({})", sampleData()))
}

func TestPackageAccessors(t *testing.T) {
	t.Parallel()
	require.Equal(t, "pkg:golang/github.com/x/y@1.2.0", run(t, "osv.purl(osv.vulns(data)[0])", sampleData()))
	require.Equal(t, "Go", run(t, "osv.ecosystem(osv.vulns(data)[0])", sampleData()))
	require.Equal(t, "PyPI", run(t, "osv.ecosystem(osv.vulns(data)[1])", sampleData()))
	require.Empty(t, run(t, "osv.purl({})", sampleData()))
}

func TestFilters(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(1), run(t, "size(osv.forEcosystem(data, 'Go'))", sampleData()))
	// Ecosystem match is case-insensitive.
	require.Equal(t, "GHSA-aaaa-bbbb-cccc", run(t, "osv.forEcosystem(data, 'go')[0].id", sampleData()))
	require.Equal(t, int64(1), run(t, "size(osv.forEcosystem(data, 'PyPI'))", sampleData()))
	// forPackage matches by bare name appearing in the PURL.
	require.Equal(t, "GHSA-aaaa-bbbb-cccc", run(t, "osv.forPackage(data, 'github.com/x/y')[0].id", sampleData()))
	require.Equal(t, int64(0), run(t, "size(osv.forPackage(data, 'nonexistent'))", sampleData()))
}

func TestCompositePolicy(t *testing.T) {
	t.Parallel()
	// "no unpatched critical" — the critical vuln here is fixed, so this passes.
	require.Equal(t, false, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0 && !osv.isFixed(v))", sampleData()))
	// A critical fixable vuln does exist.
	require.Equal(t, true, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0 && osv.isFixed(v))", sampleData()))
	// Every Go vulnerability is fixed.
	require.Equal(t, true, run(t, "osv.forEcosystem(data, 'Go').all(v, osv.isFixed(v))", sampleData()))
}

func TestReferences(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(2), run(t, "size(osv.references(osv.vulns(data)[0]))", sampleData()))
	require.Equal(t, "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", run(t, "osv.references(osv.vulns(data)[0])[0]", sampleData()))
	require.Equal(t, int64(0), run(t, "size(osv.references(osv.vulns(data)[1]))", sampleData()))
}

func TestEnrichment(t *testing.T) {
	t.Parallel()
	// Present on the first (Go) finding.
	require.InDelta(t, 0.88, run(t, "osv.epss(osv.vulns(data)[0])", sampleData()), 0.001)
	require.InDelta(t, 0.34, run(t, "osv.risk(osv.vulns(data)[0])", sampleData()), 0.001)
	require.Equal(t, true, run(t, "osv.isKEV(osv.vulns(data)[0])", sampleData()))
	require.Equal(t, true, run(t, "osv.cwes(osv.vulns(data)[0]) == ['CWE-89']", sampleData()))

	// Absent on the second finding — safe zero values.
	require.InDelta(t, 0.0, run(t, "osv.epss(osv.vulns(data)[1])", sampleData()), 0.001)
	require.Equal(t, false, run(t, "osv.isKEV(osv.vulns(data)[1])", sampleData()))
	require.Equal(t, int64(0), run(t, "size(osv.cwes(osv.vulns(data)[1]))", sampleData()))

	// A realistic triage policy: fail only on exploited-or-likely critical vulns.
	require.Equal(t, true, run(t, "osv.vulns(data).exists(v, osv.cvss(v) >= 9.0 && (osv.isKEV(v) || osv.epss(v) >= 0.5))", sampleData()))
}

func TestEmptyAndMalformed(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(0), run(t, "size(osv.vulns(data))", map[string]any{}))
	require.Equal(t, int64(0), run(t, "size(osv.ids(data))", map[string]any{"results": []any{}}))
	require.InDelta(t, 0.0, run(t, "osv.cvss({})", sampleData()), 0.001)
}
