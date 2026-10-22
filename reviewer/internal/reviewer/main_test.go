package reviewer_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the suite from the developer's real AAR configuration:
// without it, tests that consult default config discovery pick up a live
// model configuration and make network calls.
func TestMain(main *testing.M) {
	home, err := os.MkdirTemp("", "aar-test-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create isolated home: %v\n", err)
		os.Exit(1)
	}
	for _, key := range []string{"AAR_CONFIG", "XDG_CONFIG_HOME", "HOME", "USERPROFILE", "AppData"} {
		if err := os.Unsetenv(key); err != nil {
			fmt.Fprintf(os.Stderr, "unset %s: %v\n", key, err)
			os.Exit(1)
		}
	}
	isolated := map[string]string{
		"HOME":            home,
		"USERPROFILE":     home,
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
	}
	for key, value := range isolated {
		if err := os.Setenv(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "set %s: %v\n", key, err)
			os.Exit(1)
		}
	}
	code := main.Run()
	if err := os.RemoveAll(home); err != nil {
		fmt.Fprintf(os.Stderr, "remove isolated home: %v\n", err)
	}
	os.Exit(code)
}
