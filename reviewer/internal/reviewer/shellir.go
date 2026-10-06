package reviewer

import (
	"fmt"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShellIR is the only representation policy code receives from the parser.
// No mvdan AST node is exposed outside this file.
type ShellIR struct {
	SchemaVersion   string            `json:"schemaVersion"`
	Nodes           []IRNode          `json:"nodes"`
	Commands        []IRCommand       `json:"commands"`
	Executions      []IRExecution     `json:"executions"`
	Operators       []IROperator      `json:"operators"`
	Redirections    []IRRedirection   `json:"redirections"`
	Dynamic         bool              `json:"dynamic"`
	DynamicFeatures []string          `json:"dynamicFeatures,omitempty"`
	PathCandidates  []IRPathCandidate `json:"pathCandidates,omitempty"`
	AccessModes     []string          `json:"accessModes,omitempty"`
	ParseError      string            `json:"parseError,omitempty"`
}

type IRSpan struct {
	Start       int `json:"start"`
	End         int `json:"end"`
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type IRNode struct {
	Kind    string `json:"kind"`
	Dynamic bool   `json:"dynamic"`
	Span    IRSpan `json:"span"`
}

type IRCommand struct {
	Name            string       `json:"name"`
	Arguments       []string     `json:"arguments"`
	Static          bool         `json:"static"`
	Span            IRSpan       `json:"span"`
	ArgumentFacts   []IRArgument `json:"argumentFacts,omitempty"`
	DynamicFeatures []string     `json:"dynamicFeatures,omitempty"`
	AccessModes     []string     `json:"accessModes,omitempty"`
}

type IRArgument struct {
	Value           string   `json:"value"`
	Static          bool     `json:"static"`
	Span            IRSpan   `json:"span"`
	DynamicFeatures []string `json:"dynamicFeatures,omitempty"`
	Raw             string   `json:"raw,omitempty"`
}

type IROperator struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Dynamic bool   `json:"dynamic"`
	Span    IRSpan `json:"span"`
}

type IRRedirection struct {
	Operator         string   `json:"operator"`
	FD               string   `json:"fd,omitempty"`
	Target           string   `json:"target"`
	TargetSpan       IRSpan   `json:"targetSpan"`
	Static           bool     `json:"static"`
	HereDocument     bool     `json:"hereDocument"`
	WriteCapable     bool     `json:"writeCapable"`
	DynamicFeatures  []string `json:"dynamicFeatures,omitempty"`
	Span             IRSpan   `json:"span"`
	HereDocumentBody string   `json:"-"`
}

type IRPathCandidate struct {
	Value      string `json:"value"`
	Static     bool   `json:"static"`
	Role       string `json:"role"`
	AccessMode string `json:"accessMode"`
	Span       IRSpan `json:"span"`
}

// IRExecution preserves the complete command composition independently of the
// parser AST. CommandIndex points into ShellIR.Commands for simple commands.
// Compound constructs remain dynamic even when their children happen to be
// statically recoverable.
type IRExecution struct {
	Kind               string        `json:"kind"`
	Operator           string        `json:"operator,omitempty"`
	CommandIndex       int           `json:"commandIndex"`
	Children           []IRExecution `json:"children,omitempty"`
	RedirectionIndexes []int         `json:"redirectionIndexes,omitempty"`
	Dynamic            bool          `json:"dynamic"`
	Span               IRSpan        `json:"span"`
}

type wordFact struct {
	value           string
	static          bool
	span            IRSpan
	dynamicFeatures []string
}

type shellConverter struct {
	source string
	ir     ShellIR
}

// ParseShell returns a versioned, reviewer-owned IR. The default branch is
// intentionally dynamic: adding a syntax node upstream can only reduce
// automatic trust until this converter handles it explicitly.
func ParseShell(source string) ShellIR {
	converter := shellConverter{
		source: source,
		ir: ShellIR{
			SchemaVersion: ShellIRSchemaVersion,
		},
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		converter.markDynamic("parse-error")
		converter.ir.ParseError = err.Error()
		converter.ir.Nodes = append(converter.ir.Nodes, IRNode{Kind: "parse-error", Dynamic: true})
		return converter.ir
	}

	converter.ir.Executions = converter.convertStatements(file.Stmts)
	return converter.ir
}

func (c *shellConverter) convertStatements(stmts []*syntax.Stmt) []IRExecution {
	executions := make([]IRExecution, 0, len(stmts))
	for _, stmt := range stmts {
		if stmt == nil {
			c.markDynamic("unknown-statement")
			continue
		}
		executions = append(executions, c.convertStmt(stmt))
	}
	for index := 1; index < len(executions); index++ {
		c.ir.Operators = append(c.ir.Operators, IROperator{
			Kind:  "sequence",
			Value: ";",
			Span:  executions[index-1].Span,
		})
	}
	return executions
}

func (c *shellConverter) convertStmt(stmt *syntax.Stmt) IRExecution {
	execution := c.convertCommand(stmt.Cmd)
	if stmt.Cmd == nil {
		execution = IRExecution{Kind: "unknown", CommandIndex: -1, Dynamic: true, Span: spanFor(stmt)}
		c.markDynamic("empty-statement")
	}

	for _, redirection := range stmt.Redirs {
		index := c.addRedirection(redirection)
		execution.RedirectionIndexes = append(execution.RedirectionIndexes, index)
		if !c.ir.Redirections[index].Static || c.ir.Redirections[index].HereDocument {
			execution.Dynamic = true
		}
	}

	if stmt.Negated {
		c.markDynamic("negation")
		execution.Dynamic = true
	}
	if stmt.Background {
		c.markDynamic("background")
		execution.Dynamic = true
	}
	if stmt.Coprocess {
		c.markDynamic("coprocess")
		execution.Dynamic = true
	}
	if stmt.Disown {
		c.markDynamic("disown")
		execution.Dynamic = true
	}

	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "statement", Dynamic: execution.Dynamic, Span: spanFor(stmt)})
	return execution
}

func (c *shellConverter) convertCommand(command syntax.Command) IRExecution {
	switch current := command.(type) {
	case *syntax.CallExpr:
		return c.convertCall(current)
	case *syntax.BinaryCmd:
		return c.convertBinary(current)
	case *syntax.FuncDecl:
		c.markDynamic("function")
		c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "function", Dynamic: true, Span: spanFor(current)})
		if current.Body != nil {
			c.convertStmt(current.Body)
		}
		return IRExecution{Kind: "function", CommandIndex: -1, Dynamic: true, Span: spanFor(current)}
	case *syntax.Subshell:
		return c.convertCompound("subshell", current, current.Stmts)
	case *syntax.Block:
		return c.convertCompound("block", current, current.Stmts)
	case *syntax.IfClause:
		return c.convertIf(current)
	case *syntax.WhileClause:
		return c.convertLoop("while", current, current.Cond, current.Do, spanFor(current))
	case *syntax.ForClause:
		c.markDynamic("loop")
		c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "loop", Dynamic: true, Span: spanFor(current)})
		c.convertStatements(current.Do)
		return IRExecution{Kind: "loop", CommandIndex: -1, Dynamic: true, Span: spanFor(current)}
	case *syntax.CaseClause:
		c.markDynamic("case")
		c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "case", Dynamic: true, Span: spanFor(current)})
		for _, item := range current.Items {
			c.convertStatements(item.Stmts)
		}
		return IRExecution{Kind: "case", CommandIndex: -1, Dynamic: true, Span: spanFor(current)}
	case *syntax.ArithmCmd:
		return c.convertUnsupported("arithmetic-command", current)
	case *syntax.TestClause:
		return c.convertUnsupported("test-clause", current)
	case *syntax.DeclClause:
		return c.convertUnsupported("declaration", current)
	case *syntax.LetClause:
		return c.convertUnsupported("let-clause", current)
	case *syntax.TimeClause:
		if current.Stmt != nil {
			c.convertStmt(current.Stmt)
		}
		return c.convertUnsupported("time-clause", current)
	case *syntax.CoprocClause:
		if current.Stmt != nil {
			c.convertStmt(current.Stmt)
		}
		return c.convertUnsupported("coprocess-clause", current)
	case *syntax.TestDecl:
		if current.Body != nil {
			c.convertStmt(current.Body)
		}
		return c.convertUnsupported("test-declaration", current)
	case nil:
		c.markDynamic("unknown-command")
		return IRExecution{Kind: "unknown", CommandIndex: -1, Dynamic: true}
	default:
		return c.convertUnsupported("unknown-command", current)
	}
}

func (c *shellConverter) convertCall(call *syntax.CallExpr) IRExecution {
	command := IRCommand{
		Static: true,
		Span:   spanFor(call),
	}
	for _, assignment := range call.Assigns {
		c.markDynamic("environment-assignment")
		command.Static = false
		if assignment != nil {
			c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "assignment", Dynamic: true, Span: spanFor(assignment)})
			if assignment.Value != nil {
				c.recoverWord(assignment.Value)
			}
		}
	}
	if len(call.Args) == 0 && len(call.Assigns) > 0 {
		return IRExecution{Kind: "assignment", CommandIndex: -1, Dynamic: true, Span: spanFor(call)}
	}
	for _, word := range call.Args {
		fact := c.recoverWord(word)
		argument := IRArgument{
			Value:           fact.value,
			Static:          fact.static,
			Span:            fact.span,
			DynamicFeatures: append([]string(nil), fact.dynamicFeatures...),
			Raw:             sourceSpan(c.source, fact.span),
		}
		command.ArgumentFacts = append(command.ArgumentFacts, argument)
		if fact.static {
			command.Arguments = append(command.Arguments, fact.value)
		} else {
			command.Arguments = append(command.Arguments, "")
			command.Static = false
		}
		for _, feature := range fact.dynamicFeatures {
			command.DynamicFeatures = appendUnique(command.DynamicFeatures, feature)
		}
	}
	if len(command.ArgumentFacts) == 0 {
		command.Static = false
		c.markDynamic("empty-command")
	}
	if len(command.ArgumentFacts) > 0 {
		command.Name = command.ArgumentFacts[0].Value
		if !command.ArgumentFacts[0].Static {
			command.Static = false
		}
	}
	if command.Name == "alias" || command.Name == "unalias" {
		c.markDynamic("alias")
		command.Static = false
		command.DynamicFeatures = appendUnique(command.DynamicFeatures, "alias")
	}
	command.AccessModes = inferAccessModes(command.Name)
	for _, mode := range command.AccessModes {
		c.ir.AccessModes = appendUnique(c.ir.AccessModes, mode)
	}
	optionsEnded, optionValue := false, false
	for index, argument := range command.ArgumentFacts {
		if index == 0 {
			continue
		}
		if optionValue {
			optionValue = false
			continue
		}
		if !optionsEnded && argument.Static && argument.Value == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && command.Name == "mkdir" && argument.Static && (argument.Value == "-m" || argument.Value == "--mode" || argument.Value == "--context") {
			optionValue = true
			continue
		}
		if !optionsEnded && argument.Static && strings.HasPrefix(argument.Value, "-") && !strings.ContainsAny(argument.Value, "/\\") {
			continue
		}
		mode := "unknown"
		if command.Name == "mkdir" {
			mode = "create"
		} else if command.Name == "rm" {
			mode = "delete"
		}
		c.ir.PathCandidates = append(c.ir.PathCandidates, IRPathCandidate{
			Value:      argument.Value,
			Static:     argument.Static,
			Role:       "argument",
			AccessMode: mode,
			Span:       argument.Span,
		})
		c.ir.AccessModes = appendUnique(c.ir.AccessModes, mode)
	}

	index := len(c.ir.Commands)
	c.ir.Commands = append(c.ir.Commands, command)
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "call", Dynamic: !command.Static, Span: command.Span})
	if !command.Static {
		for _, feature := range command.DynamicFeatures {
			c.markDynamic(feature)
		}
	}
	return IRExecution{
		Kind:         "command",
		CommandIndex: index,
		Dynamic:      !command.Static,
		Span:         command.Span,
	}
}

func (c *shellConverter) convertBinary(binary *syntax.BinaryCmd) IRExecution {
	operator := binary.Op.String()
	kind := "sequence"
	dynamic := false
	switch binary.Op {
	case syntax.Pipe, syntax.PipeAll:
		kind = "pipeline"
	case syntax.AndStmt:
		kind = "and"
	case syntax.OrStmt:
		kind = "or"
	default:
		c.markDynamic("unknown-operator")
		dynamic = true
	}
	c.ir.Operators = append(c.ir.Operators, IROperator{
		Kind:    kind,
		Value:   operator,
		Dynamic: dynamic,
		Span:    spanFor(binary),
	})
	left := c.convertStmt(binary.X)
	right := c.convertStmt(binary.Y)
	dynamic = dynamic || left.Dynamic || right.Dynamic
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: kind, Dynamic: dynamic, Span: spanFor(binary)})
	return IRExecution{
		Kind:         kind,
		Operator:     operator,
		Children:     []IRExecution{left, right},
		Dynamic:      dynamic,
		Span:         spanFor(binary),
		CommandIndex: -1,
	}
}

func (c *shellConverter) convertCompound(kind string, node syntax.Node, stmts []*syntax.Stmt) IRExecution {
	c.markDynamic(kind)
	children := c.convertStatements(stmts)
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: kind, Dynamic: true, Span: spanFor(node)})
	return IRExecution{Kind: kind, CommandIndex: -1, Children: children, Dynamic: true, Span: spanFor(node)}
}

func (c *shellConverter) convertIf(clause *syntax.IfClause) IRExecution {
	c.markDynamic("conditional")
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "conditional", Dynamic: true, Span: spanFor(clause)})
	c.convertStatements(clause.Cond)
	c.convertStatements(clause.Then)
	if clause.Else != nil {
		c.convertIf(clause.Else)
	}
	return IRExecution{Kind: "conditional", CommandIndex: -1, Dynamic: true, Span: spanFor(clause)}
}

func (c *shellConverter) convertLoop(kind string, node syntax.Node, condition, body []*syntax.Stmt, span IRSpan) IRExecution {
	c.markDynamic(kind)
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: kind, Dynamic: true, Span: span})
	c.convertStatements(condition)
	c.convertStatements(body)
	return IRExecution{Kind: kind, CommandIndex: -1, Dynamic: true, Span: span}
}

func (c *shellConverter) convertUnsupported(kind string, node syntax.Node) IRExecution {
	c.markDynamic(kind)
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: kind, Dynamic: true, Span: spanFor(node)})
	return IRExecution{Kind: kind, CommandIndex: -1, Dynamic: true, Span: spanFor(node)}
}

func (c *shellConverter) addRedirection(redirection *syntax.Redirect) int {
	if redirection == nil {
		c.markDynamic("unknown-redirection")
		c.ir.Redirections = append(c.ir.Redirections, IRRedirection{Static: false, DynamicFeatures: []string{"unknown-redirection"}})
		return len(c.ir.Redirections) - 1
	}
	fact := c.recoverWord(redirection.Word)
	writeCapable := redirectionWriteCapable(redirection.Op)
	features := append([]string(nil), fact.dynamicFeatures...)
	hereDocument := redirection.Hdoc != nil || isHereDocument(redirection.Op)
	if hereDocument {
		features = appendUnique(features, "heredoc")
	}
	fd := ""
	if redirection.N != nil {
		fd = redirection.N.Value
	}
	outputDuplication := redirection.Op == syntax.DplOut && (fd == "" || fd == "1" || fd == "2") && (fact.value == "1" || fact.value == "2")
	if redirection.Op == syntax.DplIn || redirection.Op == syntax.DplOut && !outputDuplication {
		features = appendUnique(features, "file-descriptor-duplication")
	}
	static := fact.static && !hereDocument && (redirection.Op != syntax.DplIn && redirection.Op != syntax.DplOut || outputDuplication)
	for _, feature := range features {
		if feature != "" {
			c.markDynamic(feature)
		}
	}
	accessMode := "read"
	if outputDuplication {
		accessMode = "stdout"
	} else if writeCapable {
		accessMode = "write"
	}
	c.ir.AccessModes = appendUnique(c.ir.AccessModes, accessMode)
	if !hereDocument && !outputDuplication {
		c.ir.PathCandidates = append(c.ir.PathCandidates, IRPathCandidate{
			Value:      fact.value,
			Static:     fact.static,
			Role:       "redirection-target",
			AccessMode: accessMode,
			Span:       fact.span,
		})
	}
	c.ir.Redirections = append(c.ir.Redirections, IRRedirection{
		Operator:        redirection.Op.String(),
		FD:              fd,
		Target:          fact.value,
		TargetSpan:      fact.span,
		Static:          static,
		HereDocument:    hereDocument,
		WriteCapable:    writeCapable,
		DynamicFeatures: features,
		Span:            spanFor(redirection),
		HereDocumentBody: func() string {
			if redirection.Hdoc == nil {
				return ""
			}
			return sourceSpan(c.source, spanFor(redirection.Hdoc))
		}(),
	})
	c.ir.Nodes = append(c.ir.Nodes, IRNode{Kind: "redirection", Dynamic: !static, Span: spanFor(redirection)})
	return len(c.ir.Redirections) - 1
}

func (c *shellConverter) recoverWord(word *syntax.Word) wordFact {
	if word == nil {
		c.markDynamic("unknown-word")
		return wordFact{static: false, dynamicFeatures: []string{"unknown-word"}}
	}
	fact := wordFact{static: true, span: spanFor(word)}
	var value strings.Builder
	var recoverPart func(syntax.WordPart, bool)
	recoverPart = func(part syntax.WordPart, quoted bool) {
		switch current := part.(type) {
		case *syntax.Lit:
			if !quoted && hasUnquotedExpansionMarker(current.Value) {
				feature := "globbing"
				if strings.ContainsAny(current.Value, "{}") {
					feature = "brace-expansion"
				}
				fact.static = false
				fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, feature)
				return
			}
			value.WriteString(current.Value)
		case *syntax.SglQuoted:
			if current.Dollar {
				decoded, err := decodeANSIQuote(current.Value)
				if err != nil {
					fact.static = false
					fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "ansi-c-quote")
					return
				}
				value.WriteString(decoded)
				return
			}
			value.WriteString(current.Value)
		case *syntax.DblQuoted:
			if current.Dollar {
				fact.static = false
				fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "locale-quote")
				return
			}
			for _, nested := range current.Parts {
				recoverPart(nested, true)
			}
		case *syntax.ParamExp:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "parameter-expansion")
			c.collectParamChildren(current)
		case *syntax.CmdSubst:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "command-substitution")
			c.convertStatements(current.Stmts)
		case *syntax.ArithmExp:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "arithmetic-expansion")
		case *syntax.ProcSubst:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "process-substitution")
			c.convertStatements(current.Stmts)
		case *syntax.ExtGlob:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "globbing")
		case *syntax.BraceExp:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "brace-expansion")
		default:
			fact.static = false
			fact.dynamicFeatures = appendUnique(fact.dynamicFeatures, "unknown-word-part")
		}
	}
	for _, part := range word.Parts {
		recoverPart(part, false)
	}
	if !fact.static {
		fact.value = ""
		for _, feature := range fact.dynamicFeatures {
			c.markDynamic(feature)
		}
	} else {
		fact.value = value.String()
	}
	return fact
}

func (c *shellConverter) collectParamChildren(param *syntax.ParamExp) {
	if param.NestedParam != nil {
		if nested, ok := param.NestedParam.(*syntax.CmdSubst); ok {
			c.convertStatements(nested.Stmts)
		}
	}
	if param.Exp != nil && param.Exp.Word != nil {
		c.recoverWord(param.Exp.Word)
	}
	if param.Repl != nil {
		if param.Repl.Orig != nil {
			c.recoverWord(param.Repl.Orig)
		}
		if param.Repl.With != nil {
			c.recoverWord(param.Repl.With)
		}
	}
}

func (c *shellConverter) markDynamic(feature string) {
	if feature == "" {
		return
	}
	c.ir.Dynamic = true
	c.ir.DynamicFeatures = appendUnique(c.ir.DynamicFeatures, feature)
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func spanFor(node syntax.Node) IRSpan {
	if node == nil {
		return IRSpan{}
	}
	start := node.Pos()
	end := node.End()
	return IRSpan{
		Start:       int(start.Offset()),
		End:         int(end.Offset()),
		StartLine:   int(start.Line()),
		StartColumn: int(start.Col()),
		EndLine:     int(end.Line()),
		EndColumn:   int(end.Col()),
	}
}

func hasUnquotedExpansionMarker(value string) bool {
	return strings.ContainsAny(value, "*?[]{}~")
}

func decodeANSIQuote(value string) (string, error) {
	var decoded strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			return "", fmt.Errorf("unterminated ANSI-C escape")
		}
		index++
		switch value[index] {
		case 'a':
			decoded.WriteByte('\a')
		case 'b':
			decoded.WriteByte('\b')
		case 'e', 'E':
			decoded.WriteByte('\x1b')
		case 'f':
			decoded.WriteByte('\f')
		case 'n':
			decoded.WriteByte('\n')
		case 'r':
			decoded.WriteByte('\r')
		case 't':
			decoded.WriteByte('\t')
		case 'v':
			decoded.WriteByte('\v')
		case '\\', '\'', '"', '?':
			decoded.WriteByte(value[index])
		case '\n':
			// A backslash-newline is removed by the shell.
		case 'x':
			start := index + 1
			end := start
			for end < len(value) && end < start+2 && isHexDigit(value[end]) {
				end++
			}
			if end == start {
				return "", fmt.Errorf("invalid ANSI-C hexadecimal escape")
			}
			number, err := strconv.ParseUint(value[start:end], 16, 8)
			if err != nil {
				return "", err
			}
			decoded.WriteByte(byte(number))
			index = end - 1
		case 'u', 'U':
			start := index + 1
			digits := 4
			if value[index] == 'U' {
				digits = 8
			}
			end := start + digits
			if end > len(value) {
				return "", fmt.Errorf("invalid ANSI-C Unicode escape")
			}
			number, err := strconv.ParseUint(value[start:end], 16, 32)
			if err != nil || number > 0x10ffff || number >= 0xd800 && number <= 0xdfff {
				return "", fmt.Errorf("invalid ANSI-C Unicode escape")
			}
			decoded.WriteRune(rune(number))
			index = end - 1
		case 'c':
			if index+1 >= len(value) {
				return "", fmt.Errorf("invalid ANSI-C control escape")
			}
			index++
			control := value[index]
			if control == '?' {
				decoded.WriteByte(0x7f)
			} else {
				decoded.WriteByte(control & 0x1f)
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			start := index
			end := start + 1
			for end < len(value) && end < start+3 && value[end] >= '0' && value[end] <= '7' {
				end++
			}
			number, err := strconv.ParseUint(value[start:end], 8, 8)
			if err != nil {
				return "", err
			}
			decoded.WriteByte(byte(number))
			index = end - 1
		default:
			return "", fmt.Errorf("unsupported ANSI-C escape \\%c", value[index])
		}
	}
	return decoded.String(), nil
}

func isHexDigit(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
}

func redirectionWriteCapable(operator syntax.RedirOperator) bool {
	switch operator {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrInOut, syntax.RdrClob,
		syntax.AppClob, syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return true
	default:
		return false
	}
}

func isHereDocument(operator syntax.RedirOperator) bool {
	return operator == syntax.Hdoc || operator == syntax.DashHdoc || operator == syntax.WordHdoc
}

func inferAccessModes(name string) []string {
	switch name {
	case "mkdir":
		return []string{"create"}
	case "rm":
		return []string{"delete"}
	case "pwd", "cd", "basename", "dirname", "realpath", "readlink":
		return []string{"metadata"}
	case "cat", "head", "tail", "less", "more", "file", "stat", "du", "df", "wc", "sort", "uniq", "cut", "tr", "diff", "cmp", "comm", "sed", "awk", "git":
		return []string{"read"}
	case "ls", "tree", "find", "grep", "rg", "ripgrep":
		return []string{"search"}
	case "echo", "printf", "true", "false", "command", "type", "which":
		return []string{"stdout"}
	default:
		return []string{"unknown"}
	}
}

func (ir ShellIR) String() string {
	return fmt.Sprintf("%s commands=%d dynamic=%t", ir.SchemaVersion, len(ir.Commands), ir.Dynamic)
}
