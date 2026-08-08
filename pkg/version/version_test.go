package version_test

import (
	"strings"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/version"
)

func TestVersionInfo(t *testing.T) {
	info := version.Info()
	if info == "" {
		t.Fatal("expected non-empty version info string")
	}

	if !strings.Contains(info, version.Version) {
		t.Errorf("version info string %q does not contain version %q", info, version.Version)
	}

	if !strings.Contains(info, version.GitCommit) {
		t.Errorf("version info string %q does not contain git commit %q", info, version.GitCommit)
	}
}
