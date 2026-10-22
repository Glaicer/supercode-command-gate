package reviewer_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func TestHardDenyBlocksWholeTreeDestruction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		command string
		env     map[string]string
	}{
		{name: "root operand", command: "rm -rf /"},
		{name: "cataloged non-root operand", command: "rm -rf --preserve-root /etc"},
		{name: "effective working directory", command: "cd / && rm -rf ."},
		{name: "trusted PWD anchor", command: `cd / && rm -rf "$PWD"`},
		{name: "find delete", command: "find / -delete"},
		{name: "trusted home anchor", command: `sudo rm -rf "$HOME"`, env: map[string]string{"HOME": "/root"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := testRequest(t, tc.command)
			for key, value := range tc.env {
				request.Env[key] = value
			}
			decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision != reviewer.DecisionDeny || decision.Source != reviewer.SourceHardDeny {
				t.Fatalf("decision = %#v, want hard-deny", decision)
			}
			if decision.Rule == nil || *decision.Rule != "HD001" {
				t.Fatalf("rule = %v, want HD001", decision.Rule)
			}
		})
	}
}

func TestHardDenyWholeTreeNearMissesRouteToAssessment(t *testing.T) {
	t.Parallel()

	commands := []string{
		"rm -rf dist",
		"rm -rf /tmp/build-output",
		"rm -rf /etc/passwd",
		"rm -rf /dev/loop0",
		"rm -rf --preserve-root /",
		`rm -rf "$TARGET"`,
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Source == reviewer.SourceHardDeny {
				t.Fatalf("near miss hard-denied: %#v", decision)
			}
		})
	}
}

func TestHardDenyDecisionIsEffectBasedAndCannotUseAnAddition(t *testing.T) {
	t.Parallel()

	request := testRequest(t, "rm -rf /")
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir: t.TempDir(),
		AutoAllowAdditions: []reviewer.AutoAllowAddition{{
			Argv: []string{"rm", "-rf", "/"},
		}},
		ProtectedPaths: []string{filepath.Join(request.CWD, "ordinary-protected")},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionDeny || decision.Source != reviewer.SourceHardDeny {
		t.Fatalf("decision = %#v, want non-overridable hard deny", decision)
	}
	if decision.Rule == nil || *decision.Rule != "HD001" {
		t.Fatalf("rule = %v, want HD001", decision.Rule)
	}
	if strings.Contains(strings.ToLower(decision.Reason), "exit") || strings.Contains(decision.Reason, "code") {
		t.Fatalf("reason = %q, must describe the effect without an exit code", decision.Reason)
	}
}

func TestHardDenyBlocksImmutableRootMutation(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"cat source > /etc",
		"cat source >&/etc",
		"> /etc",
		"truncate -s 0 /var",
		"mv /etc /tmp/etc-backup",
		"mv -T source /etc",
		"dd if=input of=/etc",
		"cp -T source /etc",
	} {
		assertHardDenyRule(t, command, "HD002")
	}
}

func TestHardDenyBlocksRawDeviceWrites(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"cat source > /dev/sda",
		"cat source >&/dev/sda",
		"> /dev/sda",
		"dd if=input of=/dev/nvme0n1",
		"tee /dev/md0",
		"tar -cf /dev/sda .",
		"curl -o /dev/sda https://example.invalid/data",
		"git archive -o /dev/sda HEAD",
		"cat source > /proc/sysrq-trigger",
	} {
		assertHardDenyRule(t, command, "HD003")
	}
}

func TestHardDenyBlocksStorageFormatAndDiscard(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"mkfs.ext4 /dev/sda",
		"mkswap /dev/nvme0n1",
		"wipefs -a /dev/sda",
		"blkdiscard /dev/sda",
		"badblocks -w /dev/sda",
		"sgdisk --zap-all /dev/sda",
		"hdparm --security-erase /dev/sda",
		"sfdisk --delete /dev/sda",
	} {
		assertHardDenyRule(t, command, "HD004")
	}
}

func TestHardDenyBlocksRecursiveMetadataDamage(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"chown -R root:root /etc",
		"chmod -R 000 /usr",
		"chgrp -R root /var",
		"setfacl -R -m u::--- /home",
		"chmod -R --reference=/etc /usr",
		"find / -exec chmod 000 {} +",
	} {
		assertHardDenyRule(t, command, "HD005")
	}
}

func TestHardDenyBlocksImmediateHostCrashPrimitives(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"echo b > /proc/sysrq-trigger",
		"kill -9 1",
		"kill -9 -1",
		"kill -1",
		"reboot",
		"shutdown -h now",
		"systemctl reboot",
		`:(){ :|:& };:`,
	} {
		assertHardDenyRule(t, command, "HD006")
	}
}

func TestHardDenyExcludesDryRunsAndNonCatalogTargets(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"mkfs.ext4 image.img",
		"mkfs.ext4 -L /dev/sda image.img",
		"mkfs.ext4 -d /dev/sda image.img",
		"mkfs.ext4 /dev/loop0",
		"wipefs -n /dev/sda",
		"parted /dev/sda print",
		"curl -f /dev/sda",
		"chmod 000 /etc",
		"chmod -R 000 /etc/passwd",
		"chmod -R --preserve-root 000 /",
		"kill -0 1",
		"kill -0 -1",
		"kill -9 2",
		"reboot --help",
		"shutdown -k now",
		"systemctl status reboot",
		"systemctl -h reboot",
		"cp -f source /etc",
		"systemctl status",
		"rm -rf /tmp/build-output",
	} {
		assertHardDenyMiss(t, command)
	}
}

func TestConfiguredProtectedPathsDoNotExpandTheClosedCatalog(t *testing.T) {
	t.Parallel()

	request := testRequest(t, "rm -rf ordinary-build-output")
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir:       t.TempDir(),
		ProtectedPaths: []string{"ordinary-build-output"},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Source == reviewer.SourceHardDeny {
		t.Fatalf("configured protected path expanded hard-deny catalog: %#v", decision)
	}
}

func TestHardDenyResolvesSymlinkAndNearestExistingParent(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	link := filepath.Join(cwd, "devices")
	if err := os.Symlink("/dev", link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	request := testRequest(t, "cat source > devices/sda")
	request.CWD = cwd
	request.Env["PWD"] = cwd
	assertHardDenyRuleWithRequest(t, request, "HD003")

	rootLink := filepath.Join(cwd, "root")
	if err := os.Symlink("/", rootLink); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	request.Command = "cat source > root/../etc"
	assertHardDenyRuleWithRequest(t, request, "HD002")
}

func assertHardDenyRule(t *testing.T, command, wantRule string) {
	t.Helper()
	assertHardDenyRuleWithRequest(t, testRequest(t, command), wantRule)
}

func assertHardDenyRuleWithRequest(t *testing.T, request reviewer.Request, wantRule string) {
	t.Helper()
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check(%q) error = %v", request.Command, err)
	}
	if decision.Decision != reviewer.DecisionDeny || decision.Source != reviewer.SourceHardDeny {
		t.Fatalf("Check(%q) = %#v, want hard-deny", request.Command, decision)
	}
	if decision.Rule == nil || *decision.Rule != wantRule {
		t.Fatalf("Check(%q) rule = %v, want %s", request.Command, decision.Rule, wantRule)
	}
}

func assertHardDenyMiss(t *testing.T, command string) {
	t.Helper()
	decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check(%q) error = %v", command, err)
	}
	if decision.Source == reviewer.SourceHardDeny {
		t.Fatalf("Check(%q) = %#v, must proceed past the hard-deny catalog", command, decision)
	}
}
