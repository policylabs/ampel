// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

// Shared map-key / CEL identifier literals used across the package.
const (
	keyPredicateType = "predicate_type"
	keyData          = "data"
)

type CelEvaluatorImplementation interface {
	CompileCode(*cel.Env, string) (*cel.Ast, error)
	CreateEnvironment(*options.EvaluatorOptions, map[string]Plugin) (*cel.Env, error)
	BuildVariables(*options.EvaluatorOptions, map[string]Plugin, *papi.Tenet, *evalcontext.EvaluationContext, []attestation.Predicate) (*map[string]any, error)
	EnsurePredicates(*papi.Tenet, *map[string]any) (*papi.EvalResult, error)
	EvaluateOutputs(*cel.Env, map[string]*cel.Ast, *map[string]any) (map[string]any, error)
	Evaluate(*cel.Env, *cel.Ast, *map[string]any) (*papi.EvalResult, error)
	Assert(*papi.ResultSet) bool
	BuildSelectorVariables(*options.EvaluatorOptions, map[string]Plugin, *evalcontext.EvaluationContext, *papi.Policy, attestation.Subject, *papi.ChainedPredicate, attestation.Predicate) (*map[string]any, error)
	EvaluateChainedSelector(*cel.Env, *cel.Ast, *map[string]any) ([]attestation.Subject, error)
	BuildExpressionVariables(*options.EvaluatorOptions, map[string]Plugin, *evalcontext.EvaluationContext) (*map[string]any, error)
	EvaluateExpression(*cel.Env, *cel.Ast, *map[string]any) (any, error)
}

type defaulCelEvaluator struct{}

// compileCode compiles CEL code from the tenets or output into their syntax trees.
func (dce *defaulCelEvaluator) CompileCode(env *cel.Env, code string) (*cel.Ast, error) {
	// Compile the tenets into their ASTs
	if env == nil {
		return nil, fmt.Errorf("unable to compile CEL code, environment is nil")
	}
	ast, iss := env.Compile(code)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compiling CEL code %w", iss.Err())
	}

	return ast, nil
}

// CreateEnvironment
func (dce *defaulCelEvaluator) CreateEnvironment(_ *options.EvaluatorOptions, plugins map[string]Plugin) (*cel.Env, error) {
	envOpts := make([]cel.EnvOption, 0, 12+len(plugins))
	envOpts = append(envOpts,
		cel.Variable(VarNamePredicates, cel.ListType(cel.AnyType)),
		cel.Variable(VarNamePredicate, cel.AnyType),
		cel.Variable(VarNameContext, cel.AnyType),
		cel.Variable(VarNameOutputs, cel.AnyType),
		cel.Variable(VarNameSubject, cel.AnyType),
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
		ext.Lists(),
		ext.Encoders(),
		ext.TwoVarComprehensions(),
	)

	envOpts = append(envOpts, verificationCompileOptions()...)

	for _, plugin := range plugins {
		envOpts = append(envOpts, plugin.Library())
	}

	env, err := cel.NewEnv(
		envOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	return env, nil
}

// BuildVariables builds the set of variables that will be exposed in the
// CEL runtime.
//
//nolint:gocritic // This passes around a large struct in vars
func (dce *defaulCelEvaluator) BuildVariables(
	opts *options.EvaluatorOptions, plugins map[string]Plugin, tenet *papi.Tenet,
	evalContext *evalcontext.EvaluationContext, predicates []attestation.Predicate,
) (*map[string]any, error) {
	// List of variables to return
	ret := map[string]any{}
	// Collected predicates
	preds := []any{}
	fpreds := []attestation.Predicate{}
	for _, p := range predicates {
		// I think we can remove this filter
		if tenet.Predicates != nil {
			if len(tenet.GetPredicates().GetTypes()) > 0 && !slices.Contains(tenet.GetPredicates().GetTypes(), string(p.GetType())) {
				logrus.Debugf("skipping predicate of type %q (not in tenet predicate types)", p.GetType())
				continue
			}
		}
		d := map[string]any{}
		if err := json.Unmarshal(p.GetData(), &d); err != nil {
			return nil, fmt.Errorf("unmarshalling predicate data: %w", err)
		}
		predMap := map[string]any{
			keyPredicateType: string(p.GetType()),
			keyData:          d,
		}
		val, err := structpb.NewValue(predMap)
		if err != nil {
			return nil, fmt.Errorf("serializing predicate: %w", err)
		}
		preds = append(preds, NewPredicateVal(val, p))
		fpreds = append(fpreds, p)
	}
	ret[VarNamePredicates] = preds
	if len(preds) > 0 {
		ret[VarNamePredicate] = preds[0]
	}

	s, err := structpb.NewStruct(evalContext.ContextValues)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}
	ret[VarNameContext] = s

	subdata, err := extractSubjectData(evalContext.Subject)
	if err != nil {
		return nil, fmt.Errorf("loading subject data to runtime: %w", err)
	}
	ret[VarNameSubject] = subdata

	logrus.Debugf("%d CEL plugins loaded into the eval engine. Querying for variables", len(plugins))
	for _, p := range plugins {
		maps.Copy(ret, p.VarValues(evalContext.Policy, evalContext.Subject, fpreds))
	}
	return &ret, nil
}

func extractSubjectData(subject attestation.Subject) (*structpb.Struct, error) {
	// Add the subject data to the runtime variables
	subjectData := map[string]any{
		"name":              "",
		"uri":               "",
		"download_location": "",
		"digest":            map[string]any{},
	}

	// If the context has the subject add it to the environment
	if subject != nil {
		subjectData["name"] = subject.GetName()
		subjectData["uri"] = subject.GetUri()

		for algo, val := range subject.GetDigest() {
			subjectData["digest"].(map[string]any)[algo] = val //nolint:errcheck,forcetypeassert
		}
	}

	if rd, ok := subject.(*intoto.ResourceDescriptor); ok {
		subjectData["download_location"] = rd.GetDownloadLocation()
	}

	sd, err := structpb.NewStruct(subjectData)
	if err != nil {
		return nil, fmt.Errorf("structuring subject data: %w", err)
	}

	return sd, nil
}

// EnsurePredicates ensures variable processing produced at least one predicate
// for the tenet to evaluate against.
//
//nolint:gocritic // This passes around a large struct in vars
func (dce *defaulCelEvaluator) EnsurePredicates(tenet *papi.Tenet, vars *map[string]any) (*papi.EvalResult, error) {
	// Fiorst, check if the tenet needs them
	if tenet.Predicates == nil {
		return nil, nil
	}

	if len(tenet.Predicates.Types) == 0 {
		return nil, nil
	}

	predFail := false

	// Short cirtcuit here if there are no suitable predicates
	predLlist, ok := (*vars)[VarNamePredicates]
	if !ok {
		predFail = true
	} else {
		l, ok := predLlist.([]any)
		if !ok {
			predFail = true
		}
		if len(l) == 0 {
			predFail = true
		}
	}

	if predFail {
		return &papi.EvalResult{
			Id:         tenet.Id,
			Status:     papi.StatusFAIL,
			Date:       timestamppb.Now(),
			Output:     &structpb.Struct{},
			Statements: []*papi.StatementRef{},
			Error: &papi.Error{
				Message:  "No suitable predicates found",
				Guidance: "None of the loaded attestations match the tenet requirements",
			},
		}, nil
	}

	return nil, nil
}

// EvaluateOutputs
func (dce *defaulCelEvaluator) EvaluateOutputs(
	//nolint:gocritic // This passes around a large struct in vars
	env *cel.Env, outputAsts map[string]*cel.Ast, vars *map[string]any,
) (map[string]any, error) {
	evalResult := map[string]any{}
	dataResult := outputDataResult{}
	if env == nil {
		return nil, fmt.Errorf("CEL environment not set")
	}
	if vars == nil {
		return nil, fmt.Errorf("variable set undefined")
	}
	for id, ast := range outputAsts {
		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("generating program from AST: %w", err)
		}

		// First evaluate the tenet.
		result, _, err := program.Eval(*vars)
		if err != nil {
			return nil, &EvaluationError{
				Message:   "CEL evaluation error",
				EvalError: err,
			}
		}

		evalResult[id] = result
		dr := result.Value()

		// If the result value is a list of ref.Vals, we need to
		// resolve it for it to marshal to json:
		if rv, ok := dr.([]ref.Val); ok {
			dr = deRefList(rv)
		}
		dataResult[id] = dr
	}

	// Round tripit
	data, err := json.Marshal(&dataResult)
	if err != nil {
		return nil, fmt.Errorf("marshaling output evals: %w", err)
	}

	// Unmarshal to generic
	ret := map[string]any{}
	if err := json.Unmarshal(data, &ret); err != nil {
		return nil, fmt.Errorf("unmarshaling data: %w", err)
	}

	// We add to the variables the native CEL types
	(*vars)["outputs"] = evalResult

	// And return the normalized data structure after roundtripping
	return ret, nil
}

// serializeOutputs converts a snapshot of evaluated outputs (ref.Val values)
// to a JSON-normalized map[string]any suitable for serialization into the
// tenet result. Only the evaluated outputs are included.
func serializeOutputs(snapshot map[string]ref.Val) (map[string]any, error) {
	dataResult := outputDataResult{}
	for id, result := range snapshot {
		dr := result.Value()
		if rv, ok := dr.([]ref.Val); ok {
			dr = deRefList(rv)
		}
		dataResult[id] = dr
	}

	data, err := json.Marshal(&dataResult)
	if err != nil {
		return nil, fmt.Errorf("marshaling output evals: %w", err)
	}

	ret := map[string]any{}
	if err := json.Unmarshal(data, &ret); err != nil {
		return nil, fmt.Errorf("unmarshaling data: %w", err)
	}
	return ret, nil
}

type outputDataResult map[string]any

func (odr *outputDataResult) MarshalJSON() ([]byte, error) {
	premarshal := map[string]json.RawMessage{}
	marshaler := protojson.MarshalOptions{
		Multiline:         true,
		Indent:            "  ",
		EmitUnpopulated:   true,
		EmitDefaultValues: true,
	}
	for id, output := range *odr {
		if pb, ok := output.(proto.Message); ok {
			data, err := marshaler.Marshal(pb)
			if err != nil {
				return nil, fmt.Errorf("proto marshaling %s: %w", id, err)
			}
			premarshal[id] = data
			continue
		}

		if mapmap, ok := output.(map[ref.Val]ref.Val); ok {
			newoutput := map[string]any{}
			for k, v := range mapmap {
				kstring, ok := k.Value().(string)
				if !ok {
					return nil, fmt.Errorf("unable to marshal output value, map is not keyed with strings")
				}
				newoutput[kstring] = v.Value()
			}
			output = newoutput
		}

		// Any other values
		data, err := json.Marshal(output)
		if err != nil {
			return nil, fmt.Errorf("marshalling %s: %w", id, err)
		}

		premarshal[id] = data
	}

	return json.Marshal(premarshal)
}

// deRefList recurses through ref lists as .Value() in the ref Lists
// will not extract the value of the list members
func deRefList(refList []ref.Val) []any {
	r := []any{}
	for _, v := range refList {
		if rl, ok := v.Value().([]ref.Val); ok {
			r = append(r, deRefList(rl))
			continue
		}
		r = append(r, v.Value())
	}
	return r
}

// decodeValue
func decodeValue(val ref.Val) (attestation.Subject, error) {
	switch v := val.Value().(type) {
	case string:
		algo, val, ok := strings.Cut(v, ":")
		if !ok {
			return nil, fmt.Errorf("string returned not formatted as algorithm:value")
		}
		if _, ok := intoto.HashAlgorithms[strings.ToLower(algo)]; !ok {
			return nil, fmt.Errorf("invalid hash algorithm returned from selector (%q)", v)
		}
		return &intoto.ResourceDescriptor{
			Digest: map[string]string{strings.ToLower(algo): val},
		}, nil
	case map[ref.Val]ref.Val, *structpb.Struct:
		res, err := val.ConvertToNative(reflect.TypeOf(&intoto.ResourceDescriptor{}))
		if err != nil {
			return nil, fmt.Errorf("converting eval result to Subject %+v: %w", v, err)
		}
		subj, ok := res.(*intoto.ResourceDescriptor)
		if !ok {
			return nil, errors.New("selectror must return a string or cel.Subject struct")
		}

		// Normalize digest algorithm keys to the canonical intoto casing
		// (sha1, sha256, gitCommit, ...) and lowercase the hex values so
		// comparisons match regardless of how the CEL expression built them.
		canonicalAlgo := make(map[string]string, len(intoto.HashAlgorithms))
		for name := range intoto.HashAlgorithms {
			canonicalAlgo[strings.ToLower(name)] = name
		}
		normalized := make(map[string]string, len(subj.Digest))
		for k, h := range subj.Digest {
			if canonical, ok := canonicalAlgo[strings.ToLower(k)]; ok {
				k = canonical
			}
			normalized[k] = strings.ToLower(h)
		}
		subj.Digest = normalized

		// We add here a little hack to copy gitCommit hashes to sha1s (and viceversa)
		// to ensure maximum matching chances

		// Handle algos of type gitCommit
		if h, ok := subj.Digest[intoto.AlgorithmGitCommit.String()]; ok {
			if _, ok := subj.Digest[intoto.AlgorithmSHA1.String()]; !ok && len(h) == 40 {
				subj.Digest[intoto.AlgorithmSHA1.String()] = h
			} else if _, ok := subj.Digest[intoto.AlgorithmSHA256.String()]; !ok && len(h) == 64 {
				subj.Digest[intoto.AlgorithmSHA256.String()] = h
			}
		}

		// If we have a sha1 (but no gitCommit), mirror it
		if h, ok := subj.Digest[intoto.AlgorithmSHA1.String()]; ok {
			if _, ok := subj.Digest[intoto.AlgorithmGitCommit.String()]; !ok {
				subj.Digest[intoto.AlgorithmGitCommit.String()] = h
			}
		}
		return subj, nil
	default:
		return nil, fmt.Errorf("predicate selector must return string or resource descr (got %T)", val.Value())
	}
}

// EvaluateChainedSelector runs the cahin selector and returns the list of subjects
// extracted from the attestation data. This function returns a list of subjects,
// depending on the context used it must only one, or a list.
func (dce *defaulCelEvaluator) EvaluateChainedSelector(
	//nolint:gocritic // This is passing a potentially large data set
	env *cel.Env, ast *cel.Ast, vars *map[string]any,
) ([]attestation.Subject, error) {
	if env == nil {
		return nil, fmt.Errorf("CEL environment not set")
	}
	if vars == nil {
		return nil, fmt.Errorf("variable set undefined")
	}

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}

	// First evaluate the tenet.
	result, _, err := program.Eval(*vars)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}
	ret := []attestation.Subject{}
	switch v := result.Value().(type) {
	case []ref.Val:
		for _, val := range v {
			sub, err := decodeValue(val)
			if err != nil {
				return nil, err
			}
			ret = append(ret, sub)
		}
	default:
		s, err := decodeValue(result)
		if err != nil {
			return nil, err
		}
		ret = append(ret, s)
	}
	return ret, nil
}

// Evaluate the precompiled ASTs
//
//nolint:gocritic // This is passing a potentially large data set
func (dce *defaulCelEvaluator) Evaluate(env *cel.Env, ast *cel.Ast, variables *map[string]any) (*papi.EvalResult, error) {
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}

	if variables == nil {
		return nil, fmt.Errorf("variable set undefined")
	}

	// First evaluate the tenet.
	result, _, err := program.Eval(*variables)
	if err != nil {
		return nil, &EvaluationError{
			Message:   "CEL evaluation error",
			EvalError: err,
		}
	}

	// Tenets must evaluate to true always
	evalResult, ok := result.Value().(bool)
	if !ok {
		return nil, fmt.Errorf("eval error: tenet must evaluate to boolean")
	}

	st := papi.StatusFAIL
	if evalResult {
		st = papi.StatusPASS
	}

	// Convert cel result to an api.Result
	return &papi.EvalResult{
		Status: st,
		Date:   timestamppb.New(time.Now()),
		// Policy:     &api.PolicyRef{},
		Statements: []*papi.StatementRef{},
	}, nil
}

func (dce *defaulCelEvaluator) Assert(*papi.ResultSet) bool {
	return false
}

// BuildSelectorVariables
//
//nolint:gocritic // This passes around a large struct in vars
func (dce *defaulCelEvaluator) BuildSelectorVariables(
	opts *options.EvaluatorOptions, plugins map[string]Plugin,
	evalContext *evalcontext.EvaluationContext,
	policy *papi.Policy, subject attestation.Subject, _ *papi.ChainedPredicate,
	predicate attestation.Predicate,
) (*map[string]any, error) {
	ret := map[string]any{}

	// Collected predicates
	d := map[string]any{}
	if err := json.Unmarshal(predicate.GetData(), &d); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	predMap := map[string]any{
		keyPredicateType: string(predicate.GetType()),
		keyData:          d,
	}
	val, err := structpb.NewValue(predMap)
	if err != nil {
		return nil, fmt.Errorf("serializing predicate: %w", err)
	}
	pv := NewPredicateVal(val, predicate)

	ret[VarNamePredicates] = []any{pv}
	ret[VarNamePredicate] = pv
	subdata, err := extractSubjectData(subject)
	if err != nil {
		return nil, fmt.Errorf("loading subject data onto selector evaluation runtime: %w", err)
	}
	ret[VarNameSubject] = subdata

	// // Add the context to the runtime environment
	s, err := structpb.NewStruct(evalContext.ContextValues)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}
	ret[VarNameContext] = s

	logrus.Debugf("%d CEL plugins loaded into the eval engine. Querying for variables", len(plugins))
	for _, p := range plugins {
		maps.Copy(ret, p.VarValues(policy, subject, []attestation.Predicate{predicate}))
	}

	return &ret, nil
}

// BuildExpressionVariables builds the variable set available to standalone
// expressions (used to resolve dynamic ContextVal expressions). It exposes
// `subject`, the already-resolved `context` and any plugin-provided globals,
// but intentionally omits `predicate` and `predicates` since those are not
// available at context-assembly time.
//
//nolint:gocritic // *map return type matches BuildVariables/BuildSelectorVariables
func (dce *defaulCelEvaluator) BuildExpressionVariables(
	opts *options.EvaluatorOptions, plugins map[string]Plugin,
	evalContext *evalcontext.EvaluationContext,
) (*map[string]any, error) {
	ret := map[string]any{}

	subdata, err := extractSubjectData(evalContext.Subject)
	if err != nil {
		return nil, fmt.Errorf("loading subject data onto expression runtime: %w", err)
	}
	ret[VarNameSubject] = subdata

	s, err := structpb.NewStruct(evalContext.ContextValues)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}
	ret[VarNameContext] = s

	for _, p := range plugins {
		maps.Copy(ret, p.VarValues(evalContext.Policy, evalContext.Subject, nil))
	}

	return &ret, nil
}

// EvaluateExpression runs a compiled standalone expression and returns the
// resolved Go value (via ref.Val.Value()).
func (dce *defaulCelEvaluator) EvaluateExpression(
	//nolint:gocritic // vars is intentionally passed by pointer to match siblings
	env *cel.Env, ast *cel.Ast, vars *map[string]any,
) (any, error) {
	if env == nil {
		return nil, fmt.Errorf("CEL environment not set")
	}
	if vars == nil {
		return nil, fmt.Errorf("variable set undefined")
	}

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}

	result, _, err := program.Eval(*vars)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}
	return result.Value(), nil
}
