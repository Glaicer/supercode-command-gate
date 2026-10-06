package reviewer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type UsageStats struct {
	Version   int    `json:"version"`
	StartedAt string `json:"startedAt"`
	Processed uint64 `json:"processed"`
	Policy    uint64 `json:"approvedByPolicy"`
	LLMFresh  uint64 `json:"approvedByLLMFresh"`
	LLMReused uint64 `json:"approvedByLLMReused"`
	Human     uint64 `json:"approvedByHuman"`
	Denied    uint64 `json:"denied"`
	Ask       uint64 `json:"ask"`
	Errors    uint64 `json:"errors"`
}

func Stats(options Options) (UsageStats, error) {
	request := Request{CWD: currentWorkingDirectory(), WorkspaceRoot: workspaceRootFromEnvironment()}
	config, err := resolveReviewerConfig(request, options)
	if err != nil {
		return UsageStats{}, err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return UsageStats{}, err
	}
	if _, err := os.Lstat(stateDir); errors.Is(err, os.ErrNotExist) {
		return UsageStats{Version: 1}, nil
	}
	root, unlock, err := statsRoot(stateDir, false)
	if err != nil {
		return UsageStats{}, fmt.Errorf("usage statistics: %w", err)
	}
	defer root.Close()
	defer unlock()
	return readStats(root)
}

func statsRoot(stateDir string, write bool) (*os.Root, func(), error) {
	if write {
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return nil, nil, err
		}
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("statistics state directory must not be a symlink")
	}
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, nil, err
	}
	file, err := root.OpenFile("stats.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	mode := unix.LOCK_SH
	if write {
		mode = unix.LOCK_EX
	}
	if err := unix.Flock(int(file.Fd()), mode); err != nil {
		file.Close()
		root.Close()
		return nil, nil, err
	}
	return root, func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
}

func readStats(root *os.Root) (UsageStats, error) {
	file, err := root.OpenFile("stats.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return UsageStats{Version: 1}, nil
	}
	if err != nil {
		return UsageStats{}, fmt.Errorf("read usage statistics: %w", err)
	}
	defer file.Close()
	var stats UsageStats
	decoder := json.NewDecoder(io.LimitReader(file, 16384))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stats); err != nil {
		return UsageStats{}, fmt.Errorf("invalid usage statistics: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return UsageStats{}, errors.New("invalid usage statistics: trailing data")
	}
	_, timeErr := time.Parse(time.RFC3339Nano, stats.StartedAt)
	total := uint64(0)
	for _, value := range []uint64{stats.Policy, stats.LLMFresh, stats.LLMReused, stats.Human, stats.Denied, stats.Ask, stats.Errors} {
		if ^uint64(0)-total < value {
			return UsageStats{}, errors.New("invalid usage statistics: counter overflow")
		}
		total += value
	}
	if stats.Version != 1 || timeErr != nil || stats.Processed != total {
		return UsageStats{}, errors.New("invalid or unsupported usage statistics; totals unavailable")
	}
	return stats, nil
}

func recordStats(stateDir string, decision Decision, resultErr error) error {
	root, unlock, err := statsRoot(stateDir, true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer unlock()
	stats, err := readStats(root)
	if err != nil {
		return err
	}
	if stats.Processed == ^uint64(0) {
		return errors.New("usage statistics counter overflow")
	}
	switch {
	case resultErr != nil:
		stats.Errors++
	case decision.Decision == DecisionDeny:
		stats.Denied++
	case decision.Decision == DecisionAsk:
		stats.Ask++
	case decision.Decision == DecisionAllow && decision.Source == SourceAutoAllow:
		stats.Policy++
	case decision.Decision == DecisionAllow && decision.Source == SourceAssessor:
		stats.LLMFresh++
	case decision.Decision == DecisionAllow && decision.Source == SourceReviewedTrust:
		stats.LLMReused++
	case decision.Decision == DecisionAllow && decision.Source == SourceGrant:
		stats.Human++
	default:
		return errors.New("unknown Reviewer outcome; usage totals unavailable")
	}
	stats.Processed++
	if stats.StartedAt == "" {
		stats.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	payload, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	file, err := root.OpenFile("stats.json.tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer root.Remove("stats.json.tmp")
	_, writeErr := file.Write(payload)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename("stats.json.tmp", "stats.json")
}
