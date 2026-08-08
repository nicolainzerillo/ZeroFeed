package feed

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ProgressBar renders a real-time progress bar with throughput (MB/s) and ETA to os.Stderr.
type ProgressBar struct {
	totalBytes int64
	currBytes  int64
	startTime  time.Time
	lastRender time.Time
	w          io.Writer
	quiet      bool
	mu         sync.Mutex
}

// NewProgressBar initializes a new progress bar for totalBytes.
func NewProgressBar(totalBytes int64, quiet bool) *ProgressBar {
	return &ProgressBar{
		totalBytes: totalBytes,
		startTime:  time.Now(),
		w:          os.Stderr,
		quiet:      quiet,
	}
}

// Add updates the progress counter by n bytes and renders the progress bar if needed.
func (p *ProgressBar) Add(n int) {
	if p == nil || p.quiet || p.totalBytes <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.currBytes += int64(n)
	now := time.Now()
	if now.Sub(p.lastRender) < 100*time.Millisecond && p.currBytes < p.totalBytes {
		return
	}
	p.lastRender = now
	p.render()
}

func (p *ProgressBar) render() {
	pct := float64(p.currBytes) / float64(p.totalBytes) * 100.0
	if pct > 100.0 {
		pct = 100.0
	}

	const barWidth = 25
	filled := int(float64(barWidth) * (pct / 100.0))
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}
	empty := barWidth - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	elapsed := time.Since(p.startTime).Seconds()
	var speedMBs float64
	if elapsed > 0 {
		speedMBs = (float64(p.currBytes) / (1024 * 1024)) / elapsed
	}

	var etaStr string
	if speedMBs > 0 && p.currBytes < p.totalBytes {
		remainingBytes := p.totalBytes - p.currBytes
		etaSec := int((float64(remainingBytes) / (1024 * 1024)) / speedMBs)
		etaStr = fmt.Sprintf("%02d:%02d", etaSec/60, etaSec%60)
	} else {
		etaStr = "00:00"
	}

	currMB := float64(p.currBytes) / (1024 * 1024)
	totMB := float64(p.totalBytes) / (1024 * 1024)

	fmt.Fprintf(p.w, "\r [%s] %5.1f%% | %.2f MB / %.2f MB | %.2f MB/s | ETA %s",
		bar, pct, currMB, totMB, speedMBs, etaStr)

	if p.currBytes >= p.totalBytes {
		fmt.Fprintln(p.w)
	}
}

// Finish completes the progress bar display.
func (p *ProgressBar) Finish() {
	if p == nil || p.quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.currBytes = p.totalBytes
	p.render()
}
