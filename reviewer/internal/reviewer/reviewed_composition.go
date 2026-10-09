package reviewer

import "strings"

type reviewedComposition struct {
	Coverage    []ReviewedCoverage
	MissReason  string
	MissCommand int
}

func compositionOutputRedirections(ir ShellIR, indexes []int) bool {
	if len(indexes) > 1 {
		return false
	}
	for _, index := range indexes {
		if index < 0 || index >= len(ir.Redirections) {
			return false
		}
		redirection := ir.Redirections[index]
		if !redirection.Static || redirection.Operator != ">&" || redirection.FD != "2" || redirection.Target != "1" {
			return false
		}
	}
	return true
}

func evaluateReviewedComposition(request Request, ir ShellIR, options Options, config Config, stateDir string) (result reviewedComposition, ok bool) {
	result.MissCommand = -1
	if ir.ParseError != "" || ir.Dynamic || len(ir.Executions) == 0 || len(ir.Commands) < 2 && len(ir.Redirections) == 0 {
		result.MissReason = "unsupported or non-composite program"
		return result, false
	}
	evaluator := newPolicyEvaluator(request, options)
	miss := func(index int, reason string) bool {
		result.MissCommand = index
		result.MissReason = reason
		return false
	}
	evaluator.acceptPolicyCommand = func(execution IRExecution, state policyState) bool {
		command := ir.Commands[execution.CommandIndex]
		for _, index := range execution.RedirectionIndexes {
			if ir.Redirections[index].WriteCapable && ir.Redirections[index].Operator != ">&" {
				return miss(execution.CommandIndex, "policy output may change later launch inputs")
			}
		}
		if command.Name == "rm" || command.Name == "mkdir" || command.Name == "printf" && len(command.Arguments) > 1 && strings.HasPrefix(command.Arguments[1], "-v") {
			return miss(execution.CommandIndex, "policy action may change later launch context")
		}
		if command.Static && evaluator.matchesAddition(command, state.cwd) {
			return miss(execution.CommandIndex, "operator-specific policy action has unknown composition effects")
		}
		rule := autoAllowRule(ShellIR{Commands: []IRCommand{command}}, false)
		result.Coverage = append(result.Coverage, ReviewedCoverage{CommandIndex: execution.CommandIndex, Source: SourceAutoAllow, Rule: rule})
		return true
	}
	evaluator.pipelineSafe = func(pipeline IRExecution, state policyState) bool {
		policyOnly := newPolicyEvaluator(request, options)
		if safe, _ := policyOnly.evaluateExecution(ir, pipeline, state, false); safe {
			return true
		}
		for _, execution := range pipeline.Children[1:] {
			if execution.Kind != "command" || execution.CommandIndex < 0 || execution.CommandIndex >= len(ir.Commands) {
				return miss(-1, "unsupported output consumer")
			}
			command := ir.Commands[execution.CommandIndex]
			if command.Name != "head" && command.Name != "tail" || !compositionOutputRedirections(ir, execution.RedirectionIndexes) {
				return miss(execution.CommandIndex, "unsupported output consumer or redirections")
			}
		}
		return true
	}
	evaluator.reviewedCommand = func(execution IRExecution, state policyState, pipelineInput, inputProvided bool) bool {
		index := execution.CommandIndex
		if state.contextChanged || state.cwd != evaluator.originalCWD {
			return miss(index, "cwd or environment changed before development launch")
		}
		if pipelineInput || inputProvided || !compositionOutputRedirections(ir, execution.RedirectionIndexes) {
			return miss(index, "development launch stdin or redirections changed")
		}
		command := ir.Commands[index]
		if !command.Static || command.Span.Start < 0 || command.Span.End > len(request.Command) || command.Span.Start >= command.Span.End {
			return miss(index, "incomplete static launch")
		}
		nodeRequest := request
		nodeRequest.Command = request.Command[command.Span.Start:command.Span.End]
		launch, reason := developmentLaunchFor(nodeRequest, config)
		if reason != "" {
			return miss(index, reason)
		}
		launch.Generation = readReviewedTrust(reviewedTrustPath(stateDir, launch.Project), launch.Project).Generation
		entry, hit := findReviewedTrust(stateDir, launch)
		if !hit {
			return miss(index, "no current individual reviewed launch")
		}
		current, reason := developmentLaunchFor(nodeRequest, config)
		current.Generation = readReviewedTrust(reviewedTrustPath(stateDir, current.Project), current.Project).Generation
		if reason != "" || launchDigest(current) != launchDigest(launch) {
			return miss(index, "launch conditions changed while reading trust")
		}
		result.Coverage = append(result.Coverage, ReviewedCoverage{CommandIndex: index, Source: SourceReviewedTrust, OriginAuditID: entry.AuditID})
		return true
	}
	state := policyState{cwd: evaluator.originalCWD}
	for _, execution := range ir.Executions {
		safe, next := evaluator.evaluateExecution(ir, execution, state, false)
		if !safe {
			if result.MissReason == "" {
				result.MissReason = "unsupported or branch-dependent launch context"
			}
			return result, false
		}
		state = next
	}
	for _, coverage := range result.Coverage {
		if coverage.Source == SourceReviewedTrust {
			return result, true
		}
	}
	result.MissReason = "no individual reviewed launch used"
	return result, false
}
