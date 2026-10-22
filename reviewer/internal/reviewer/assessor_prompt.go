package reviewer

type assessorParserHints struct {
	Commands        []assessorCommandHint `json:"commands,omitempty"`
	Dynamic         bool                  `json:"dynamic"`
	DynamicFeatures []string              `json:"dynamicFeatures,omitempty"`
	ParseError      string                `json:"parseError,omitempty"`
}

type assessorCommandHint struct {
	Argv   []string `json:"argv,omitempty"`
	Source string   `json:"source,omitempty"`
}

type assessorPathHint struct {
	Source                 string `json:"source"`
	Role                   string `json:"role"`
	CommandIndex           *int   `json:"commandIndex,omitempty"`
	ArgumentIndex          *int   `json:"argumentIndex,omitempty"`
	ResolvedFromInitialCWD string `json:"resolvedFromInitialCWD,omitempty"`
	Exists                 bool   `json:"exists"`
	Protected              bool   `json:"protected"`
	InsideWorkspace        bool   `json:"insideWorkspace"`
	InsideTemporary        bool   `json:"insideTemporary"`
	Unresolved             bool   `json:"unresolved"`
}

func compactParserHints(source string, ir ShellIR) assessorParserHints {
	hints := assessorParserHints{
		Dynamic:         ir.Dynamic,
		DynamicFeatures: append([]string(nil), ir.DynamicFeatures...),
		ParseError:      ir.ParseError,
	}
	for _, command := range ir.Commands {
		hint := assessorCommandHint{}
		if command.Static {
			hint.Argv = append([]string(nil), command.Arguments...)
		} else {
			hint.Source = sourceSpan(source, command.Span)
		}
		hints.Commands = append(hints.Commands, hint)
	}
	return hints
}

func compactPathHint(source string, ir ShellIR, candidate IRPathCandidate, fact pathFact) assessorPathHint {
	hint := assessorPathHint{
		Source:                 sourceSpan(source, candidate.Span),
		Role:                   candidate.Role,
		ResolvedFromInitialCWD: fact.Resolved,
		Exists:                 fact.ResolvedExisting,
		Protected:              fact.Protected,
		InsideWorkspace:        fact.InsideWorkspace,
		InsideTemporary:        fact.InsideTemporary,
		Unresolved:             fact.Unresolved,
	}
	if candidate.Role == "argument" {
		hint.Role = "unclassified-argument"
		for commandIndex, command := range ir.Commands {
			for argumentIndex, argument := range command.ArgumentFacts {
				if argument.Span == candidate.Span {
					hint.CommandIndex = &commandIndex
					hint.ArgumentIndex = &argumentIndex
					return hint
				}
			}
		}
	}
	return hint
}
