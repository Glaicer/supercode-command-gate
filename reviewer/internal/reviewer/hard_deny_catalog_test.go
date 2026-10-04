package reviewer

import (
	"path/filepath"
	"testing"
)

func TestHardDenyLinuxCatalogsAreClosed(t *testing.T) {
	t.Parallel()

	for _, root := range linuxWholeTreeRoots {
		if !isWholeTreeCatalogPath(root, platformLinux, Request{}) {
			t.Fatalf("Linux whole-tree root %q was not cataloged", root)
		}
	}
	for _, target := range []string{
		"/dev/sda", "/dev/hda", "/dev/vda", "/dev/xvda", "/dev/nvme0n1", "/dev/mmcblk0", "/dev/md0", "/dev/dm-0", "/dev/mapper/crypt-root", "/dev/mem", "/dev/kmem", "/proc/sysrq-trigger",
	} {
		if !isRawDeviceCatalogPath(target, platformLinux) {
			t.Fatalf("Linux raw target %q was not cataloged", target)
		}
	}
	for _, target := range []string{"/dev/loop0", "/dev/loop-control", "/dev/sda.img", "/tmp/sda.img", "/mnt/dataset", "/dev/mapper/nested/name"} {
		if isRawDeviceCatalogPath(target, platformLinux) {
			t.Fatalf("Linux near-miss raw target %q was cataloged", target)
		}
	}
	if isWholeTreeCatalogPath("/etc/passwd", platformLinux, Request{}) {
		t.Fatal("Linux descendant was treated as a whole-tree root")
	}
}

func TestHardDenyDarwinCatalogsAreClosed(t *testing.T) {
	t.Parallel()

	for _, root := range darwinWholeTreeRoots {
		if !isWholeTreeCatalogPath(root, platformDarwin, Request{}) {
			t.Fatalf("macOS whole-tree root %q was not cataloged", root)
		}
	}
	for _, target := range []string{"/dev/disk0", "/dev/disk2s1", "/dev/disk3s1s1", "/dev/rdisk0"} {
		if !isRawDeviceCatalogPath(target, platformDarwin) {
			t.Fatalf("macOS raw target %q was not cataloged", target)
		}
	}
	for _, target := range []string{"/dev/loop0", "/tmp/disk.img", "/dev/disk"} {
		if isRawDeviceCatalogPath(target, platformDarwin) {
			t.Fatalf("macOS near-miss raw target %q was cataloged", target)
		}
	}
	if resolved, ok := resolveExistingPrefix("/var"); ok && resolved != "/var" && !isWholeTreeCatalogPath(resolved, platformDarwin, Request{}) {
		t.Fatalf("macOS symlinked catalog root %q was not cataloged", resolved)
	}
}

func TestHardDenyReservedWindowsFactsNormalizeCaseInsensitively(t *testing.T) {
	t.Parallel()

	request := Request{Env: map[string]string{
		"SystemRoot":  `C:\Windows`,
		"USERPROFILE": `C:\Users\Ada`,
	}}
	for _, root := range []string{`c:\`, `D:\`, `c:\Program Files`, `C:\PROGRAM FILES (X86)`, `d:\ProgramData`, `C:\Users`, `c:\Recovery`, `C:\System Volume Information`, `c:\Windows`, `c:\users\ada`} {
		if !isWholeTreeCatalogPath(root, platformWindows, request) {
			t.Fatalf("Windows reserved root %q was not cataloged", root)
		}
	}
	for _, target := range []string{`\\.\PhysicalDrive0`, `\\.\HarddiskVolume2`, `\\?\Volume{ABC}`} {
		if !isRawDeviceCatalogPath(target, platformWindows) {
			t.Fatalf("Windows reserved raw target %q was not cataloged", target)
		}
	}
	if isWholeTreeCatalogPath(`c:\Users\Ada\Documents`, platformWindows, request) {
		t.Fatal("Windows descendant was treated as a whole-tree root")
	}
}

func TestHardDenyDecisionUsesTheSelectedUnixCatalog(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	request := Request{
		SchemaVersion: RequestSchemaVersion,
		Command:       "rm -rf /Applications",
		CWD:           cwd,
		WorkspaceRoot: stringPointerForTest(filepath.Clean(cwd)),
		Env:           map[string]string{"PWD": cwd},
		Session:       Session{ID: "session-1", Host: "test"},
	}
	rule, reason, ok := evaluateHardDenyForPlatform(request, ParseShell(request.Command), platformDarwin)
	if !ok || rule != "HD001" {
		t.Fatalf("decision = %q, %q, %t; want HD001 hard deny", rule, reason, ok)
	}
}

func stringPointerForTest(value string) *string {
	return &value
}
