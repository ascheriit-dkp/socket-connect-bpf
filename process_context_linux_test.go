// Copyright 2026 Ascheriit-Dkp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseProcessStat(t *testing.T) {
	fields := []string{
		"S", "42", "0", "0", "0", "0", "0", "0", "0", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "987654",
	}

	stat, err := parseProcessStat(
		"1234 (command with ) characters) " + strings.Join(fields, " "),
	)
	if err != nil {
		t.Fatalf("parse process stat: %v", err)
	}
	if stat.ParentPID != 42 {
		t.Fatalf("parent PID = %d; want 42", stat.ParentPID)
	}
	if stat.StartTimeTicks != 987654 {
		t.Fatalf("start time = %d; want 987654", stat.StartTimeTicks)
	}
}

func TestParseProcessStatRejectsMalformedData(t *testing.T) {
	if _, err := parseProcessStat("1234 no-parentheses"); err == nil {
		t.Fatal("malformed stat was accepted")
	}

	if _, err := parseProcessStat("1234 (test) S 1"); err == nil {
		t.Fatal("short stat was accepted")
	}
}

func TestParseProcessCgroupPath(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "cgroup v2",
			value: "0::/user.slice/user-1000.slice/session-2.scope\n",
			want:  "/user.slice/user-1000.slice/session-2.scope",
		},
		{
			name: "prefer unified hierarchy",
			value: "2:cpu:/legacy\n0::/unified\n",
			want: "/unified",
		},
		{
			name:  "cgroup v1 fallback",
			value: "5:memory:/docker/example\n4:cpu:/other\n",
			want:  "/docker/example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseProcessCgroupPath(test.value); got != test.want {
				t.Fatalf("cgroup path = %q; want %q", got, test.want)
			}
		})
	}
}

func TestParseProcessNamespaceID(t *testing.T) {
	if got := parseProcessNamespaceID("net:[4026531993]"); got != 4026531993 {
		t.Fatalf("namespace ID = %d; want 4026531993", got)
	}
	if got := parseProcessNamespaceID("broken"); got != 0 {
		t.Fatalf("malformed namespace ID = %d; want 0", got)
	}
}

func TestDetectProcessContainer(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name    string
		path    string
		runtime string
	}{
		{
			name:    "docker cgroupfs",
			path:    "/docker/" + id,
			runtime: "docker",
		},
		{
			name:    "docker systemd",
			path:    "/system.slice/docker-" + id + ".scope",
			runtime: "docker",
		},
		{
			name:    "containerd",
			path:    "/kubepods.slice/cri-containerd-" + id + ".scope",
			runtime: "containerd",
		},
		{
			name:    "cri-o",
			path:    "/kubepods.slice/crio-" + id + ".scope",
			runtime: "cri-o",
		},
		{
			name:    "podman",
			path:    "/user.slice/libpod-" + id + ".scope",
			runtime: "podman",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := detectProcessContainer(test.path)
			if got == nil {
				t.Fatal("container was not detected")
			}
			if got.Runtime != test.runtime || got.ID != id {
				t.Fatalf("container = %#v; want runtime=%q id=%q", got, test.runtime, id)
			}
		})
	}

	if got := detectProcessContainer("/user.slice/session.scope"); got != nil {
		t.Fatalf("host process detected as container: %#v", got)
	}
}

func TestLookupProcessContextForCurrentProcess(t *testing.T) {
	context := lookupProcessContext(os.Getpid())
	if context.StartTimeTicks == 0 {
		t.Fatal("current process start time was not resolved")
	}
	if context.Namespaces.PID == 0 || context.Namespaces.Net == 0 {
		t.Fatalf("namespace context incomplete: %#v", context.Namespaces)
	}
}
