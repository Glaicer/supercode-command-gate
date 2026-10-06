package reviewer

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func historyLock(stateDir string, exclusive bool) (func(), error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("history state directory must not be a symlink")
	}
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.OpenFile("history.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open history lock: %w", err)
	}
	operation := unix.LOCK_SH
	if exclusive {
		operation = unix.LOCK_EX
	}
	if err := unix.Flock(int(file.Fd()), operation|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("review history is busy: %w", err)
	}
	return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
}

func Cleanup(options Options) (int, error) {
	request := Request{CWD: currentWorkingDirectory(), WorkspaceRoot: workspaceRootFromEnvironment()}
	config, err := resolveReviewerConfig(request, options)
	if err != nil {
		return 0, err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return 0, err
	}
	if _, err := os.Lstat(stateDir); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	unlock, err := historyLock(stateDir, true)
	if err != nil {
		return 0, err
	}
	defer unlock()
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	for _, name := range []string{"audit", "logs", "logs/reviews.sqlite", "logs/reviews.sqlite-wal", "logs/reviews.sqlite-shm"} {
		if err := rejectHistorySymlink(root, name); err != nil {
			return 0, err
		}
	}
	auditFiles := []string{}
	audit, err := root.Open("audit")
	if err == nil {
		entries, readErr := audit.ReadDir(-1)
		audit.Close()
		if readErr != nil {
			return 0, readErr
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			name := filepath.Join("audit", entry.Name())
			if err := rejectHistorySymlink(root, name); err != nil {
				return 0, err
			}
			auditFiles = append(auditFiles, name)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if _, err := root.Stat("logs/reviews.sqlite"); err == nil {
		if err := cleanupReviewDatabase(filepath.Join(stateDir, "logs", "reviews.sqlite")); err != nil {
			return 0, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	removed := 0
	for _, name := range auditFiles {
		if err := root.Remove(name); err != nil {
			return removed, fmt.Errorf("remove audit: %w", err)
		}
		removed++
	}
	return removed, nil
}

func rejectHistorySymlink(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("history path %s must not be a symlink", name)
	}
	return nil
}

func cleanupReviewDatabase(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dsn := url.URL{Scheme: "file", Path: path}
	dsn.RawQuery = url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(1000)"}}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA secure_delete=ON; DELETE FROM review_events"); err != nil {
		return fmt.Errorf("cleanup review trace (busy or unavailable): %w", err)
	}
	var busy, frames, checkpointed int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &checkpointed); err != nil {
		return fmt.Errorf("checkpoint review trace: %w", err)
	}
	if busy != 0 {
		return errors.New("review trace is busy; WAL cleanup could not finish")
	}
	return nil
}
