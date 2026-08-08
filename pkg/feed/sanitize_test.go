package feed

import (
	"bytes"
	"testing"
)

func TestSanitizeTextOutput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{
			name:  "plain text passthrough",
			input: []byte("hello world"),
			want:  []byte("hello world"),
		},
		{
			name:  "newline and tab preserved",
			input: []byte("line1\nline2\ttabbed"),
			want:  []byte("line1\nline2\ttabbed"),
		},
		{
			name:  "CSI color reset stripped",
			input: []byte("\x1b[0mhello\x1b[0m"),
			want:  []byte("hello"),
		},
		{
			name:  "CSI cursor move stripped",
			input: []byte("\x1b[2J\x1b[H"),
			want:  []byte(""),
		},
		{
			name:  "OSC title injection stripped",
			input: []byte("\x1b]0;EVIL TITLE\x07visible"),
			want:  []byte("visible"),
		},
		{
			name:  "OSC with ST terminator stripped",
			input: []byte("\x1b]2;EVIL\x1b\\visible"),
			want:  []byte("visible"),
		},
		{
			name:  "bare ESC + char stripped",
			input: []byte("a\x1bcb"),
			want:  []byte("ab"),
		},
		{
			name:  "C0 null byte stripped",
			input: []byte("a\x00b"),
			want:  []byte("ab"),
		},
		{
			name:  "C0 BEL stripped",
			input: []byte("a\x07b"),
			want:  []byte("ab"),
		},
		{
			name:  "DEL (0x7F) stripped",
			input: []byte("a\x7fb"),
			want:  []byte("ab"),
		},
		{
			name:  "carriage return preserved",
			input: []byte("line\r\n"),
			want:  []byte("line\r\n"),
		},
		{
			name:  "mixed attack payload",
			input: []byte("\x1b[31mRED\x1b[0m\x1b]0;pwned\x07clean"),
			want:  []byte("REDclean"),
		},
		{
			name:  "empty input",
			input: []byte{},
			want:  []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTextOutput(tt.input)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("sanitizeTextOutput(%q)\n got:  %q\n want: %q", tt.input, got, tt.want)
			}
		})
	}
}
