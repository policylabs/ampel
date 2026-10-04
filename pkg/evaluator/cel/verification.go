// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"errors"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// SignersProvider is implemented by predicate wrappers that can expose the
// actual verified signer identities observed on an attestation. This is the
// full set of signers AMPEL verified, as distinct from verification.identities
// (the subset that matched a pinned allowlist, which is empty when none was
// supplied). AMPEL's per-policy predicate wrapper (verifier.matchedPredicate)
// implements this; when a predicate does, its signers are surfaced to policies
// as verification.signers.
//
// Note: signers is an AMPEL-provided view. It is NOT part of the
// carabiner-dev/signer Verification proto.
type SignersProvider interface {
	// Signers returns the actual verified signer identities of the attestation.
	Signers() []*sapi.Identity
}

// identitiesToAny converts a slice of signer identities into the CEL-friendly
// []any representation. It is shared by verification.identities and
// verification.signers so both fields expose the same element shape
// (.id / .sigstore / .key / .ref).
func identitiesToAny(ids []*sapi.Identity) []any {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		idMap := map[string]any{
			"id": id.GetId(),
		}
		if ss := id.GetSigstore(); ss != nil {
			idMap["sigstore"] = map[string]any{
				"issuer":   ss.GetIssuer(),
				"identity": ss.GetIdentity(),
				"mode":     ss.GetMode(),
			}
		}
		if k := id.GetKey(); k != nil {
			idMap["key"] = map[string]any{
				"id":    k.GetId(),
				"type":  k.GetType(),
				keyData: k.GetData(),
			}
		}
		if r := id.GetRef(); r != nil {
			idMap["ref"] = map[string]any{
				"id": r.GetId(),
			}
		}
		out = append(out, idMap)
	}
	return out
}

// extractVerificationData converts the verification data from a predicate into
// a map[string]any suitable for structpb serialization into the CEL environment.
func extractVerificationData(pred attestation.Predicate) map[string]any {
	v, ok := pred.GetVerification().(*sapi.Verification)
	if !ok || v == nil {
		return nil
	}

	sig := v.GetSignature()
	if sig == nil {
		return nil
	}

	data := map[string]any{
		"verified":   sig.GetVerified(),
		"identities": identitiesToAny(sig.GetIdentities()),
		// signers is populated by AMPEL from the actual verified signer
		// identities (see SignersProvider). Unlike identities (the matched
		// allowlist subset), it is populated even when no allowlist was
		// supplied. It is an AMPEL-provided view, NOT part of the signer proto.
		"signers": []any{},
	}
	if sp, ok := pred.(SignersProvider); ok {
		data["signers"] = identitiesToAny(sp.Signers())
	}
	return data
}

// --- VerificationVal: custom CEL value with matchesId support ---

// VerificationType is the CEL object type for verification values.
var VerificationType = cel.ObjectType("verification", traits.ReceiverType, traits.IndexerType)

// VerificationVal wraps signer verification data as a CEL value. It exposes
// field access (.verified, .identities, .signers) via an embedded structpb CEL
// map and provides a matchesId member function for identity matching.
//
// .identities is the subset of signers that matched a pinned allowlist (empty
// when no allowlist was supplied). .signers is the full set of actual verified
// signers AMPEL observed, populated regardless of any allowlist. matchesId
// still matches against the verification's identity set; with .signers now
// available, a policy can also inspect the real signers directly, e.g.
// verification.signers.exists(s, has(s.sigstore)).
type VerificationVal struct {
	verification *sapi.Verification
	celMap       ref.Val
}

// NewVerificationVal creates a VerificationVal from a predicate. If the
// predicate is nil or has no verification, a default (unverified, no
// identities, no signers) value is returned.
func NewVerificationVal(pred attestation.Predicate) *VerificationVal {
	vv := &VerificationVal{}

	vdata := map[string]any{
		"verified":   false,
		"identities": []any{},
		"signers":    []any{},
	}

	if pred != nil {
		if v, ok := pred.GetVerification().(*sapi.Verification); ok && v != nil {
			vv.verification = v
			if vd := extractVerificationData(pred); vd != nil {
				vdata = vd
			}
		}
	}

	sv, err := structpb.NewValue(vdata)
	if err == nil {
		vv.celMap = types.DefaultTypeAdapter.NativeToValue(sv)
	} else {
		vv.celMap = types.NewErr("failed to build verification map: %v", err)
	}

	return vv
}

func (v *VerificationVal) Type() ref.Type { return VerificationType }
func (v *VerificationVal) Value() any     { return v.verification }
func (v *VerificationVal) Equal(_ ref.Val) ref.Val {
	return types.NewErr("verification objects cannot be compared")
}

func (v *VerificationVal) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("verification cannot be converted to native")
}

func (v *VerificationVal) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return VerificationType
	}
	return types.NewErr("type conversion not supported for verification")
}

// Get implements traits.Indexer, delegating field access to the underlying
// structpb map so that .verified and .identities work.
func (v *VerificationVal) Get(index ref.Val) ref.Val {
	if indexer, ok := v.celMap.(traits.Indexer); ok {
		return indexer.Get(index)
	}
	return types.NewErr("verification map does not support indexing")
}

// --- PredicateVal: wraps a structpb predicate to inject VerificationVal ---

// PredicateValType is the CEL object type for predicate wrapper values.
var PredicateValType = cel.ObjectType("predicateVal", traits.IndexerType)

// PredicateVal wraps a CEL predicate (structpb map) and intercepts access to
// the "verification" key to return a VerificationVal that supports matchesId.
type PredicateVal struct {
	celMap       ref.Val
	verification *VerificationVal
}

// NewPredicateVal creates a PredicateVal from a structpb value and a predicate.
// The structpb value backs field access for data/predicate_type; the predicate
// provides verification data for the VerificationVal.
func NewPredicateVal(sv *structpb.Value, pred attestation.Predicate) *PredicateVal {
	return &PredicateVal{
		celMap:       types.DefaultTypeAdapter.NativeToValue(sv),
		verification: NewVerificationVal(pred),
	}
}

func (p *PredicateVal) Type() ref.Type { return PredicateValType }
func (p *PredicateVal) Value() any     { return p }
func (p *PredicateVal) Equal(_ ref.Val) ref.Val {
	return types.NewErr("predicate objects cannot be compared")
}

func (p *PredicateVal) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("predicate cannot be converted to native")
}

func (p *PredicateVal) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return PredicateValType
	}
	return types.NewErr("type conversion not supported for predicate")
}

// Get implements traits.Indexer. Access to "verification" returns the
// VerificationVal (which supports matchesId); all other keys delegate
// to the underlying structpb map.
func (p *PredicateVal) Get(index ref.Val) ref.Val {
	if key, ok := index.Value().(string); ok && key == "verification" {
		return p.verification
	}
	if indexer, ok := p.celMap.(traits.Indexer); ok {
		return indexer.Get(index)
	}
	return types.NewErr("predicate map does not support indexing")
}

// --- matchesId function implementation ---

// matchIdImpl parses a slug string into an Identity and checks it against
// the verification data. matchesId matches against the verification's identity
// set (the matched allowlist subset). With verification.signers now exposing
// the actual verified signers, a policy can additionally inspect the real
// signers directly (e.g. verification.signers.exists(s, has(s.sigstore))).
var matchIdImpl = func(lhs ref.Val, rhs ref.Val) ref.Val {
	vv, ok := lhs.(*VerificationVal)
	if !ok {
		return types.NewErr("matchesId: unexpected receiver type %T", lhs)
	}

	slug, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("matchesId: argument must be a string")
	}

	id, err := sapi.NewIdentityFromSpec(slug)
	if err != nil {
		return types.NewErr("matchesId: invalid identity slug: %v", err)
	}

	if vv.verification == nil {
		return types.Bool(false)
	}

	return types.Bool(vv.verification.MatchesIdentity(id))
}

// --- CEL environment registration ---

// verificationCompileOptions returns the CEL environment options that register
// the matchesId member function and type adapter. No variable is declared;
// verification is accessed as predicate.verification via PredicateVal.
func verificationCompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(VerificationType),
		cel.CustomTypeAdapter(&VerificationTypeAdapter{}),
		cel.Function(
			"matchesId",
			cel.MemberOverload(
				"verification_matchesId_binding",
				[]*cel.Type{cel.DynType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(matchIdImpl),
			),
		),
	}
}

// VerificationTypeAdapter adapts VerificationVal for the CEL runtime.
type VerificationTypeAdapter struct{}

// NativeToValue implements the cel.TypeAdapter interface.
func (VerificationTypeAdapter) NativeToValue(value any) ref.Val {
	switch v := value.(type) {
	case *VerificationVal:
		return v
	case *PredicateVal:
		return v
	default:
		return types.DefaultTypeAdapter.NativeToValue(value)
	}
}

// Compile-time interface checks.
var (
	_ ref.Val        = (*VerificationVal)(nil)
	_ traits.Indexer = (*VerificationVal)(nil)
	_ ref.Val        = (*PredicateVal)(nil)
	_ traits.Indexer = (*PredicateVal)(nil)
)
