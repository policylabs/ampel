// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"errors"
	"fmt"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"google.golang.org/protobuf/proto"
)

// resolvePolicyIdentities returns copies of the identities with any from_context
// matcher binding filled from the assembled context. Only
// source_repository_uri_match may use from_context; it resolves to an exact
// match of the whole context value. It runs before CheckIdentities so the value
// lands inside the identity (AND-ed) and fails closed: a missing or empty
// context value errors, and the policy proto is cloned, never mutated.
func resolvePolicyIdentities(identities []*sapi.Identity, contextValues map[string]any) ([]*sapi.Identity, error) {
	if len(identities) == 0 {
		return identities, nil
	}
	out := make([]*sapi.Identity, 0, len(identities))
	for _, id := range identities {
		clone, ok := proto.Clone(id).(*sapi.Identity)
		if !ok {
			return nil, fmt.Errorf("cloning identity %q", id.GetId())
		}
		if err := resolveIdentityContext(clone, contextValues); err != nil {
			return nil, fmt.Errorf("identity %q: %w", id.GetId(), err)
		}
		out = append(out, clone)
	}
	return out, nil
}

// resolveIdentityContext fills the source_repository_uri_match from_context
// binding and rejects from_context on any other matcher (it is the only
// in-scope field).
func resolveIdentityContext(id *sapi.Identity, contextValues map[string]any) error {
	if ss := id.GetSigstore(); ss != nil && ss.GetSourceRepositoryUriMatch().GetFromContext() != "" {
		v, err := contextString(contextValues, ss.GetSourceRepositoryUriMatch().GetFromContext())
		if err != nil {
			return err
		}
		ss.SourceRepositoryUriMatch = &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: v}}
	}
	for _, m := range nonSourceRepoMatchers(id) {
		if m.GetFromContext() != "" {
			return errors.New("from_context is only supported on source_repository_uri_match")
		}
	}
	return nil
}

// contextString returns the named context value as a non-empty string.
func contextString(contextValues map[string]any, name string) (string, error) {
	v, ok := contextValues[name]
	if !ok || v == nil {
		return "", fmt.Errorf("context value %q is not set", name)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("context value %q must be a non-empty string", name)
	}
	return s, nil
}

// nonSourceRepoMatchers returns every non-nil StringMatcher on the identity
// except source_repository_uri_match, so from_context can be rejected on them.
// Keep this in sync with the signer Identity matcher fields.
func nonSourceRepoMatchers(id *sapi.Identity) []*sapi.StringMatcher {
	var ms []*sapi.StringMatcher
	add := func(m *sapi.StringMatcher) {
		if m != nil {
			ms = append(ms, m)
		}
	}
	if ss := id.GetSigstore(); ss != nil {
		add(ss.GetIssuerMatch())
		add(ss.GetIdentityMatch())
	}
	if k := id.GetKey(); k != nil {
		add(k.GetIdMatch())
		add(k.GetTypeMatch())
		add(k.GetSigningFingerprintMatch())
	}
	if sp := id.GetSpiffe(); sp != nil {
		add(sp.GetSvidMatch())
		add(sp.GetTrustDomainMatch())
		add(sp.GetPathMatch())
	}
	for _, m := range id.GetMatchers() {
		add(m.GetString_())
	}
	return ms
}
