//go:build !windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRemoveOwnedResourceRejectsTerminalReplacement(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "owned")
			displaced := filepath.Join(root, "checked-object")
			replacement := filepath.Join(root, "replacement")

			if kind == "directory" {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(replacement, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(replacement, "must-remain"), []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(target, []byte("checked"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			replacementFile, err := os.Open(replacement)
			if err != nil {
				t.Fatal(err)
			}
			defer replacementFile.Close()

			hookCalls := 0
			_, err = removeOwnedResourceWithHook(root, "owned", func(stage purgeStage) error {
				if stage != purgeBeforeTerminalMove {
					return nil
				}
				hookCalls++
				if err := os.Rename(target, displaced); err != nil {
					return err
				}
				return os.Rename(replacement, target)
			})
			if err == nil || !strings.Contains(err.Error(), "changed during purge") {
				t.Fatalf("terminal replacement error = %v", err)
			}
			if hookCalls != 1 {
				t.Fatalf("replacement hook calls = %d, want 1", hookCalls)
			}
			if _, err := os.Stat(displaced); err != nil {
				t.Fatalf("checked object was lost: %v", err)
			}

			var stat unix.Stat_t
			if err := unix.Fstat(int(replacementFile.Fd()), &stat); err != nil {
				t.Fatal(err)
			}
			if stat.Nlink == 0 {
				t.Fatal("replacement object was deleted")
			}

			foundReplacement := false
			replacementInfo, err := replacementFile.Stat()
			if err != nil {
				t.Fatal(err)
			}
			err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if os.SameFile(info, replacementInfo) {
					foundReplacement = true
					if info.IsDir() {
						return filepath.SkipDir
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !foundReplacement {
				t.Fatal("replacement object no longer has a name under the purge root")
			}
		})
	}
}

func TestRemoveOwnedResourceCleansQuarantine(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state", "nested", "owned"), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := removeOwnedResource(root, "state")
	if err != nil {
		t.Fatalf("remove owned directory: %v", err)
	}
	if !removed {
		t.Fatal("remove owned directory reported no removal")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("purge root entries = %v, want none", entries)
	}
}
