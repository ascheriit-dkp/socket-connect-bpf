package main

import (
	"flag"
	"strings"
	"testing"
)

func TestArgumentRedactorRedactsConfiguredPatterns(t *testing.T) {
	redactor, err := newArgumentRedactor([]string{
		`(?i)token=[^ ]+`,
		`password=[^ ]+`,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := redactor.Redact(
		"--token=secret TOKEN=other password=hunter2 --safe=value",
	)
	want := "--[REDACTED] [REDACTED] [REDACTED] --safe=value"

	if got != want {
		t.Fatalf("Redact() = %q, want %q", got, want)
	}
}

func TestArgumentRedactorWithoutPatternsPreservesInput(t *testing.T) {
	redactor, err := newArgumentRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}

	const input = "--token=visible --safe=value"
	if got := redactor.Redact(input); got != input {
		t.Fatalf("Redact() = %q, want %q", got, input)
	}
}

func TestArgumentRedactorRejectsInvalidPatterns(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		contains string
	}{
		{
			name:     "empty",
			patterns: []string{""},
			contains: "must not be empty",
		},
		{
			name:     "invalid regex",
			patterns: []string{"("},
			contains: "compile --redact-arg pattern",
		},
		{
			name:     "matches empty",
			patterns: []string{"a*"},
			contains: "matches empty text",
		},
		{
			name: "too long",
			patterns: []string{
				strings.Repeat("a", maxArgumentRedactionPatternLength+1),
			},
			contains: "exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newArgumentRedactor(test.patterns)
			if err == nil {
				t.Fatal("newArgumentRedactor() error = nil")
			}
			if !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %q, want %q", err, test.contains)
			}
		})
	}
}

func TestArgumentRedactorRejectsTooManyPatterns(t *testing.T) {
	patterns := make([]string, maxArgumentRedactionPatterns+1)
	for index := range patterns {
		patterns[index] = "secret"
	}

	_, err := newArgumentRedactor(patterns)
	if err == nil {
		t.Fatal("newArgumentRedactor() error = nil")
	}
	if !strings.Contains(err.Error(), "too many --redact-arg patterns") {
		t.Fatalf("error = %q", err)
	}
}

func TestArgumentRedactionFlagMayBeRepeated(t *testing.T) {
	flagSet := flag.NewFlagSet("redaction", flag.ContinueOnError)
	values := registerArgumentRedactionFlags(flagSet)

	if err := flagSet.Parse([]string{
		"--redact-arg",
		"token=[^ ]+",
		"--redact-arg",
		"password=[^ ]+",
	}); err != nil {
		t.Fatal(err)
	}

	if len(*values) != 2 {
		t.Fatalf("len(patterns) = %d, want 2", len(*values))
	}
	if (*values)[0] != "token=[^ ]+" || (*values)[1] != "password=[^ ]+" {
		t.Fatalf("patterns = %#v", *values)
	}
}
