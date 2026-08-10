package feed

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// FormatBytes formats a byte count into a human-readable string (B, KB, MB, GB, etc.).
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ProgressBar renders a real-time progress bar with throughput and ETA to os.Stderr.
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
	if now.Sub(p.lastRender) >= 100*time.Millisecond || p.currBytes >= p.totalBytes {
		p.render()
		p.lastRender = now
	}
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
	var speedBytesSec float64
	if elapsed > 0 {
		speedBytesSec = float64(p.currBytes) / elapsed
	}

	var etaStr string
	if speedBytesSec > 0 && p.currBytes < p.totalBytes {
		remainingBytes := p.totalBytes - p.currBytes
		etaSec := int(float64(remainingBytes) / speedBytesSec)
		etaStr = fmt.Sprintf("%02d:%02d", etaSec/60, etaSec%60)
	} else {
		etaStr = "00:00"
	}

	currStr := FormatBytes(p.currBytes)
	totStr := FormatBytes(p.totalBytes)
	speedStr := FormatBytes(int64(speedBytesSec)) + "/s"

	fmt.Fprintf(p.w, "\r [%s] %5.1f%% | %s / %s | %s | ETA %s",
		bar, pct, currStr, totStr, speedStr, etaStr)

	if p.currBytes >= p.totalBytes {
		fmt.Fprintln(p.w)
	}
}

// Finish flushes and completes the progress bar.
func (p *ProgressBar) Finish() {
	if p == nil || p.quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.currBytes = p.totalBytes
	p.render()
}
