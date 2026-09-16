package main

import (
	"strings"
	"testing"
)

func TestFormatBuildVersion(t *testing.T) {
	originalVersion := buildVersion
	originalCommit := buildCommit
	originalDate := buildDate
	t.Cleanup(func() {
		buildVersion = originalVersion
		buildCommit = originalCommit
		buildDate = originalDate
	})

	buildVersion = "v2.0.0"
	buildCommit = "0123456789abcdef"
	buildDate = "2026-09-16T13:25:19Z"

	got := formatBuildVersion()
	want := "socket-connect-bpf v2.0.0 commit=0123456789abcdef built=2026-09-16T13:25:19Z"
	if got != want {
		t.Fatalf("formatBuildVersion() = %q, want %q", got, want)
	}
}

func TestVersionFlagFalseDoesNotExit(t *testing.T) {
	if err := (versionFlagValue{}).Set("false"); err != nil {
		t.Fatalf("Set(false) error = %v", err)
	}
}

func TestVersionFlagRejectsInvalidBoolean(t *testing.T) {
	err := (versionFlagValue{}).Set("not-a-bool")
	if err == nil {
		t.Fatal("Set(invalid) error = nil")
	}
	if !strings.Contains(err.Error(), "parse --version value") {
		t.Fatalf("Set(invalid) error = %q", err)
	}
}
