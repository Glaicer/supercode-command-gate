package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aar check | aar doctor | aar stats | aar cleanup | aar trust-reset --project <directory> | aar explain --audit-id <id> | aar grant --session <id> --fingerprint <fp> --scope once|session | aar deny-note --session <id> --fingerprint <fp> | aar session-event --session <id> --event end|clear|new-intent|goal-change")
	}
	if args[0] == "--version" || args[0] == "version" {
		if len(args) != 1 {
			return errors.New("usage: aar --version")
		}
		_, err := fmt.Fprintf(stdout, "aar %s\n", version)
		return err
	}
	if args[0] == "doctor" {
		if len(args) != 1 {
			return errors.New("usage: aar doctor")
		}
		return runDoctor(stdout)
	}
	if args[0] == "trust-reset" {
		flags, err := namedFlags(args[1:])
		if err != nil {
			return err
		}
		if len(flags) != 1 || flags["project"] == "" {
			return errors.New("usage: aar trust-reset --project <directory>")
		}
		if err := reviewer.ResetReviewedTrust(flags["project"], reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")}); err != nil {
			return err
		}
		return writeStatus(stdout, map[string]string{"status": "reset"})
	}
	if args[0] == "stats" {
		if len(args) != 1 {
			return errors.New("usage: aar stats")
		}
		stats, err := reviewer.Stats(reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")})
		if err != nil {
			return err
		}
		period := stats.StartedAt
		if period == "" {
			period = "not started"
		}
		_, err = fmt.Fprintf(stdout, "Reviewer statistics (since %s)\nProcessed: %d\nApproved by policy: %d\nApproved by LLM: %d (fresh: %d, reused: %d)\nApproved by human: %d\nDenied: %d\nAsk: %d\nErrors: %d\nReviewer outcomes only; repeated checks count again. Ask remains Ask under Gate never-ask; execution and native permissions are not counted.\n", period, stats.Processed, stats.Policy, stats.LLMFresh+stats.LLMReused, stats.LLMFresh, stats.LLMReused, stats.Human, stats.Denied, stats.Ask, stats.Errors)
		return err
	}
	if args[0] == "cleanup" {
		if len(args) != 1 {
			return errors.New("usage: aar cleanup")
		}
		removed, err := reviewer.Cleanup(reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")})
		if err != nil {
			return fmt.Errorf("aar cleanup: %w", err)
		}
		return writeStatus(stdout, map[string]string{"status": "cleaned", "auditFiles": fmt.Sprint(removed), "reviewTrace": "cleared"})
	}
	if args[0] == "explain" {
		flags, err := namedFlags(args[1:])
		if err != nil {
			return err
		}
		auditID := flags["audit-id"]
		if auditID == "" {
			return errors.New("--audit-id is required")
		}
		if len(flags) != 1 {
			return errors.New("usage: aar explain --audit-id <id>")
		}
		payload, err := reviewer.Explain(auditID, reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")})
		if err != nil {
			return err
		}
		_, err = stdout.Write(payload)
		return err
	}
	if args[0] == "grant" || args[0] == "deny-note" || args[0] == "session-event" {
		flags, err := namedFlags(args[1:])
		if err != nil {
			return err
		}
		sessionID := flags["session"]
		if sessionID == "" {
			return errors.New("--session is required")
		}
		options := reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")}
		switch args[0] {
		case "grant":
			fingerprint := flags["fingerprint"]
			if fingerprint == "" {
				return errors.New("--fingerprint is required")
			}
			if err := reviewer.Grant(sessionID, fingerprint, flags["scope"], options); err != nil {
				return err
			}
			return writeStatus(stdout, map[string]string{"status": "granted", "scope": flags["scope"]})
		case "deny-note":
			fingerprint := flags["fingerprint"]
			if fingerprint == "" {
				return errors.New("--fingerprint is required")
			}
			if err := reviewer.DenyNote(sessionID, fingerprint, options); err != nil {
				return err
			}
			return writeStatus(stdout, map[string]string{"status": "denied"})
		case "session-event":
			event := flags["event"]
			if event == "" {
				return errors.New("--event is required")
			}
			if err := reviewer.SessionEvent(sessionID, event, options); err != nil {
				return err
			}
			return writeStatus(stdout, map[string]string{"status": "invalidated", "event": event})
		}
	}
	if len(args) != 1 || args[0] != "check" {
		return errors.New("usage: aar check")
	}

	var request reviewer.Request
	decoder := json.NewDecoder(stdin)
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("read aar request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("aar check accepts exactly one JSON request")
		}
		return fmt.Errorf("read trailing request data: %w", err)
	}

	decision, err := reviewer.Check(request, reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")})
	if err != nil {
		return err
	}
	if decision.StatsError != "" {
		fmt.Fprintln(stderr, decision.StatsError)
	}
	payload, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("encode aar decision: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "%s\n", payload)
	return err
}

func runDoctor(stdout io.Writer) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve doctor working directory: %w", err)
	}
	workspaceRoot := strings.TrimSpace(os.Getenv("AAR_WORKSPACE_ROOT"))
	if workspaceRoot == "" {
		workspaceRoot = cwd
	}
	request := reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		CWD:           cwd,
		WorkspaceRoot: &workspaceRoot,
		Session:       reviewer.Session{Host: "opencode"},
	}
	report, err := reviewer.Doctor(request, reviewer.Options{StateDir: os.Getenv("AAR_STATE_DIR")})
	if err != nil {
		return fmt.Errorf("aar doctor: %w", err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode doctor report: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "%s\n", payload)
	return err
}

func namedFlags(args []string) (map[string]string, error) {
	flags := map[string]string{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") {
			return nil, fmt.Errorf("unexpected argument %q", argument)
		}
		argument = strings.TrimPrefix(argument, "--")
		if argument == "" {
			return nil, errors.New("empty flag")
		}
		if separator := strings.IndexByte(argument, '='); separator >= 0 {
			key, value := argument[:separator], argument[separator+1:]
			if key == "" || value == "" {
				return nil, fmt.Errorf("flag --%s requires a value", key)
			}
			flags[key] = value
			continue
		}
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return nil, fmt.Errorf("flag --%s requires a value", argument)
		}
		flags[argument] = args[index+1]
		index++
	}
	return flags, nil
}

func writeStatus(stdout io.Writer, status map[string]string) error {
	payload, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("encode aar action result: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "%s\n", payload)
	return err
}
