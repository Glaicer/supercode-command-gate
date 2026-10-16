package reviewer

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStateFileLocks(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	open := func() *os.File {
		t.Helper()
		file, err := openStateFile(root, "state.lock", os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		return file
	}
	first, second := open(), open()
	if err := lockStateFile(first, false, true); err != nil {
		t.Fatal(err)
	}
	defer unlockStateFile(first)
	if err := lockStateFile(second, false, true); err != nil {
		t.Fatalf("shared locks must coexist: %v", err)
	}
	unlockStateFile(second)
	if err := lockStateFile(second, true, true); err == nil {
		unlockStateFile(second)
		t.Fatal("exclusive lock acquired while shared lock held")
	}
	unlockStateFile(first)
	if err := lockStateFile(second, true, true); err != nil {
		t.Fatalf("exclusive lock after shared unlock: %v", err)
	}
	defer unlockStateFile(second)
	if err := lockStateFile(first, false, true); err == nil {
		unlockStateFile(first)
		t.Fatal("shared lock acquired while exclusive lock held")
	}
	if err := lockStateFile(first, true, true); err == nil {
		unlockStateFile(first)
		t.Fatal("second exclusive lock acquired")
	}
	unlockStateFile(second)
	if err := lockStateFile(first, true, false); err != nil {
		t.Fatalf("blocking lock after exclusive unlock: %v", err)
	}
}

func TestStateFileReadCreateAndTruncate(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if file, err := openStateFile(root, "missing.json", os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("missing state file: %v", err)
	}
	file, err := openStateFile(root, "stats.json", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("original"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	file, err = openStateFile(root, "stats.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("new"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	payload, err := root.ReadFile("stats.json")
	if err != nil || string(payload) != "new" {
		t.Fatalf("truncated state file = %q, %v", payload, err)
	}
}

func TestStateFileCannotFollowExternalSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "stats.json")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, flag := range []int{os.O_RDONLY, os.O_CREATE | os.O_RDWR, os.O_CREATE | os.O_WRONLY | os.O_TRUNC} {
		file, err := openStateFile(root, "stats.json", flag, 0600)
		if err == nil {
			file.Close()
			t.Fatalf("followed external symlink with flags %d", flag)
		}
	}
	payload, err := os.ReadFile(target)
	if err != nil || string(payload) != "keep" {
		t.Fatalf("external target modified: %q, %v", payload, err)
	}
}

func TestReviewDatabaseURI(t *testing.T) {
	windowsURI := reviewDatabaseURI(filepath.FromSlash("C:/Users/Tester/state #100%/reviews.sqlite"))
	if got, want := windowsURI.String(), "file:///C:/Users/Tester/state%20%23100%25/reviews.sqlite"; got != want {
		t.Fatalf("Windows database URI = %s, want %s", got, want)
	}
	filename := "reviews #100%.sqlite"
	if runtime.GOOS != "windows" {
		filename += "?"
	}
	stateDir := filepath.Join(t.TempDir(), "state #100%")
	path := filepath.Join(stateDir, filename)
	uri := reviewDatabaseURI(path)
	parsed, err := url.Parse(uri.String())
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.ToSlash(path)
	if !strings.HasPrefix(want, "/") {
		want = "/" + want
	}
	if parsed.Scheme != "file" || parsed.Host != "" || parsed.Path != want || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatalf("database URI = %s, want path %s", uri.String(), want)
	}
	log, err := newReviewLog(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	log.db.Close()
	if err := cleanupReviewDatabase(filepath.Join(stateDir, "logs", "reviews.sqlite")); err != nil {
		t.Fatal(err)
	}
}
