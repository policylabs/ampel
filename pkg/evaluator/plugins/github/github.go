// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	keyScheme = "scheme"
	keyHost   = "host"
	keyOrg    = "org"
	keyRepo   = "repo"
	keyName   = "name"
	keyURI    = "uri"
	keyDigest = "digest"
	keySHA256 = "sha256"
)

type GitHubUtil struct{}

var GitHubType = cel.ObjectType("github", traits.ReceiverType)

func (ut *GitHubUtil) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function(
			"parseRepo",
			cel.MemberOverload(
				"github_parse_repo",
				[]*cel.Type{GitHubType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(parseRepo),
			),
		),
		cel.Function(
			"orgDescriptorFromURI",
			cel.MemberOverload(
				"github_orgDescriptorFromURI",
				[]*cel.Type{GitHubType, cel.AnyType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(uriToOrgDescriptor),
			),
		),
		cel.Function(
			"repoDescriptorFromURI",
			cel.MemberOverload(
				"github_repoDescriptorFromURI",
				[]*cel.Type{GitHubType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(uriToRepoDescriptor),
			),
		),
		cel.Function(
			"branchDescriptorFromURI",
			cel.MemberOverload(
				"github_branchDescriptorFromURI",
				[]*cel.Type{GitHubType, cel.StringType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.FunctionBinding(uriToBranchDescriptor),
			),
		),
	}
}

func parseRepoURI(uri string) (map[string]string, error) {
	if strings.HasPrefix(uri, "github.com/") {
		uri = "https://" + uri
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing uri string: %w", err)
	}

	path := strings.TrimPrefix(parsed.Path, "/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	// URL has no path
	if path == "" {
		return nil, errors.New("could not parse repository url")
	}

	// URL has no org/repo
	repo := ""
	if len(parts) > 1 {
		repo = parts[1]
		// If the original string was a locator, the repo can have
		// the revision appended. Cut it.
		repo, _, _ = strings.Cut(repo, "@")
	}

	return map[string]string{
		keyScheme: strings.TrimPrefix(parsed.Scheme, "git+"),
		keyHost:   parsed.Hostname(),
		keyOrg:    parts[0],
		keyRepo:   repo,
	}, nil
}

var uriToRepoDescriptor = func(_ ref.Val, rhs ref.Val) ref.Val {
	if v, ok := rhs.Value().([]ref.Val); ok {
		if len(v) == 0 {
			return types.String("")
		}
		rhs = v[0]
	}

	switch v := rhs.Value().(type) {
	case string:
		parts, err := parseRepoURI(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		if parts[keyRepo] == "" {
			return types.NewErrFromString("unable to create descriptor, no repo name defined in URL")
		}
		name := fmt.Sprintf("%s/%s/%s", parts[keyHost], parts[keyOrg], parts[keyRepo])

		h := sha256.New()
		h.Write([]byte(name))
		digest := fmt.Sprintf("%x", h.Sum(nil))

		mapa := map[string]any{
			keyName: name,
			keyURI:  fmt.Sprintf("https://%s", name),
			keyDigest: map[string]any{
				keySHA256: digest,
			},
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		s, err := structpb.NewStruct(mapa)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		return types.NewJSONStruct(reg, s)
	default:
		return types.NewErrFromString("unsupported type for repo parse")
	}
}

var uriToOrgDescriptor = func(_ ref.Val, rhs ref.Val) ref.Val {
	if v, ok := rhs.Value().([]ref.Val); ok {
		if len(v) == 0 {
			return types.String("")
		}
		rhs = v[0]
	}

	switch v := rhs.Value().(type) {
	case string:
		parts, err := parseRepoURI(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		if parts[keyOrg] == "" || parts[keyHost] == "" {
			return types.NewErrFromString("could not parse org from repo uri")
		}
		name := fmt.Sprintf("%s/%s", parts[keyHost], parts[keyOrg])

		h := sha256.New()
		h.Write([]byte(name))
		digest := fmt.Sprintf("%x", h.Sum(nil))

		mapa := map[string]any{
			keyDigest: map[string]any{
				keySHA256: digest,
			},
			keyName: name,
			keyURI:  fmt.Sprintf("https://%s", name),
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		s, err := structpb.NewStruct(mapa)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		return types.NewJSONStruct(reg, s)

	default:
		return types.NewErrFromString(fmt.Sprintf("unsupported type for repo parse %T", rhs.Value()))
	}
}

var uriToBranchDescriptor = func(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NewErrFromString("missing arguments for branch descriptor")
	}

	uri := args[1]
	if v, ok := uri.Value().([]ref.Val); ok {
		if len(v) == 0 {
			return types.String("")
		}
		uri = v[0]
	}

	repoUri, ok := uri.Value().(string)
	if !ok {
		return types.NewErrFromString("unsupported type for repository uri")
	}

	branch, ok := args[2].Value().(string)
	if !ok {
		return types.NewErrFromString("branch name is not a string")
	}

	if branch == "" {
		return types.NewErrFromString("branch name not set")
	}

	parts, err := parseRepoURI(repoUri)
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	if parts[keyRepo] == "" {
		return types.NewErrFromString("unable to create descriptor, no repo name defined in URL")
	}
	name := fmt.Sprintf("%s/%s/%s@%s", parts[keyHost], parts[keyOrg], parts[keyRepo], branch)

	h := sha256.New()
	h.Write([]byte(name))
	digest := fmt.Sprintf("%x", h.Sum(nil))

	mapa := map[string]any{
		keyName: name,
		keyURI:  fmt.Sprintf("git+https://%s", name),
		keyDigest: map[string]any{
			keySHA256: digest,
		},
	}

	reg, err := types.NewRegistry()
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	s, err := structpb.NewStruct(mapa)
	if err != nil {
		return types.NewErrFromString(err.Error())
	}

	return types.NewJSONStruct(reg, s)
}

var parseRepo = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parts, err := parseRepoURI(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}

		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.NewStringStringMap(reg, parts)

	default:
		return types.NewErrFromString("unsupported type for repo parse")
	}
}

func (ut *GitHubUtil) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return GitHubType

	default:
		return types.NewErr("type conversion not allowed for github utility")
	}
}

func (*GitHubUtil) Type() ref.Type {
	return GitHubType
}

func (*GitHubUtil) Equal(other ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (ut *GitHubUtil) Value() any {
	return ut
}

func (*GitHubUtil) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, errors.New("url cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	val, ok := value.(GitHubUtil)
	if ok {
		return &val
	} else {
		// let the default adapter handle other cases
		return types.DefaultTypeAdapter.NativeToValue(value)
	}
}

// CompileOptions and ProgramOptions implement the cel.Library interface

func (ut *GitHubUtil) CompileOptions() []cel.EnvOption {
	funcs := ut.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(GitHubType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("github", GitHubType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (ut *GitHubUtil) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
