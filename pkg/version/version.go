package version

import (
	"fmt"
	"runtime"
)

var (
	// Version holds the current release version of ZeroFeed (injected at build time).
	Version = "v1.3.0"
	// GitCommit holds the git commit SHA (injected at build time).
	GitCommit = "dev"
	// BuildDate holds the build timestamp (injected at build time).
	BuildDate = "unknown"
)

// Info returns a formatted string containing full version and build metadata.
func Info() string {
	return fmt.Sprintf("ZeroFeed %s (commit %s, built %s, %s/%s, %s)",
		Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
