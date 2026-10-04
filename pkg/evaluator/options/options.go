// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package options

// EvaluatorOptions are assembled by the verifier and passed deep to
// the evaluator when executing the policy tenets.
type EvaluatorOptions struct {
	LoadDefaultPlugins bool
	ParallelWorkers    int8

	// SkipUnsupportedRuntime makes the evaluator factory soft-fail (skip) tenets
	// whose policy declares a runtime engine version or plugins that this binary
	// does not provide, instead of failing them. This lets a policy set combine
	// policies that rely on newer engine features with older engines that skip
	// them rather than reporting a hard failure. The default (false) preserves
	// the failing behavior.
	SkipUnsupportedRuntime bool
}

var Default = EvaluatorOptions{
	LoadDefaultPlugins: true,
	ParallelWorkers:    4,
}

type OptFunc func(*EvaluatorOptions) error

func WithDefaultPlugins(sino bool) OptFunc {
	return func(eo *EvaluatorOptions) error {
		eo.LoadDefaultPlugins = sino
		return nil
	}
}
