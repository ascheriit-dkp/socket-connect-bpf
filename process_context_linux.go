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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type processNamespaceSnapshot struct {
	Cgroup uint64
	IPC    uint64
	Mount  uint64
	Net    uint64
	PID    uint64
	User   uint64
	UTS    uint64
}

type processContainerSnapshot struct {
	Runtime string
	ID      string
}

type processContextSnapshot struct {
	GID                  *uint32
	StartTimeTicks       uint64
	ParentPID            uint32
	ParentStartTimeTicks uint64
	CgroupPath           string
	Namespaces           processNamespaceSnapshot
	Container            *processContainerSnapshot
}

type parsedProcessStat struct {
	ParentPID      uint32
	StartTimeTicks uint64
}

var containerCgroupPatterns = []struct {
	runtime string
	pattern *regexp.Regexp
}{
	{
		runtime: "containerd",
		pattern: regexp.MustCompile(
			`(?:^|/)cri-containerd-([0-9a-fA-F]{12,64})\.scope(?:/|$)`,
		),
	},
	{
		runtime: "cri-o",
		pattern: regexp.MustCompile(
			`(?:^|/)crio-([0-9a-fA-F]{12,64})\.scope(?:/|$)`,
		),
	},
	{
		runtime: "podman",
		pattern: regexp.MustCompile(
			`(?:^|/)libpod-([0-9a-fA-F]{12,64})\.scope(?:/|$)`,
		),
	},
	{
		runtime: "docker",
		pattern: regexp.MustCompile(
			`(?:^|/)docker-([0-9a-fA-F]{12,64})\.scope(?:/|$)`,
		),
	},
	{
		runtime: "docker",
		pattern: regexp.MustCompile(
			`(?:^|/)docker/([0-9a-fA-F]{12,64})(?:/|$)`,
		),
	},
}

func lookupProcessContext(pid int) processContextSnapshot {
	context := processContextSnapshot{}

	if stat, err := readProcessStat(pid); err == nil {
		context.StartTimeTicks = stat.StartTimeTicks
		context.ParentPID = stat.ParentPID

		if stat.ParentPID != 0 {
			if parentStat, parentErr := readProcessStat(int(stat.ParentPID)); parentErr == nil {
				context.ParentStartTimeTicks = parentStat.StartTimeTicks
			}
		}
	}

	context.GID = readProcessGID(pid)
	context.CgroupPath = readProcessCgroupPath(pid)
	context.Namespaces = readProcessNamespaces(pid)
	context.Container = detectProcessContainer(context.CgroupPath)

	return context
}

func readProcessStat(pid int) (parsedProcessStat, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return parsedProcessStat{}, err
	}

	return parseProcessStat(string(data))
}

func parseProcessStat(value string) (parsedProcessStat, error) {
	closing := strings.LastIndex(value, ") ")
	if closing < 0 {
		return parsedProcessStat{}, fmt.Errorf("malformed /proc stat: missing command terminator")
	}

	fields := strings.Fields(value[closing+2:])
	if len(fields) <= 19 {
		return parsedProcessStat{}, fmt.Errorf(
			"malformed /proc stat: got %d fields after command; want at least 20",
			len(fields),
		)
	}

	parent, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return parsedProcessStat{}, fmt.Errorf("parse parent PID: %w", err)
	}

	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return parsedProcessStat{}, fmt.Errorf("parse process start time: %w", err)
	}

	return parsedProcessStat{
		ParentPID:      uint32(parent),
		StartTimeTicks: startTime,
	}, nil
}

func readProcessGID(pid int) *uint32 {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Gid:") {
			continue
		}

		fields := strings.Fields(strings.TrimPrefix(line, "Gid:"))
		if len(fields) == 0 {
			return nil
		}

		value, parseErr := strconv.ParseUint(fields[0], 10, 32)
		if parseErr != nil {
			return nil
		}

		gid := uint32(value)
		return &gid
	}

	return nil
}

func readProcessCgroupPath(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}

	return parseProcessCgroupPath(string(data))
}

func parseProcessCgroupPath(value string) string {
	fallback := ""

	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}

		path := filepath.Clean(parts[2])
		if !strings.HasPrefix(path, "/") {
			continue
		}

		if parts[1] == "" {
			return path
		}
		if fallback == "" {
			fallback = path
		}
	}

	return fallback
}

func readProcessNamespaces(pid int) processNamespaceSnapshot {
	return processNamespaceSnapshot{
		Cgroup: readProcessNamespaceID(pid, "cgroup"),
		IPC:    readProcessNamespaceID(pid, "ipc"),
		Mount:  readProcessNamespaceID(pid, "mnt"),
		Net:    readProcessNamespaceID(pid, "net"),
		PID:    readProcessNamespaceID(pid, "pid"),
		User:   readProcessNamespaceID(pid, "user"),
		UTS:    readProcessNamespaceID(pid, "uts"),
	}
}

func readProcessNamespaceID(pid int, namespace string) uint64 {
	target, err := os.Readlink(
		filepath.Join("/proc", strconv.Itoa(pid), "ns", namespace),
	)
	if err != nil {
		return 0
	}

	return parseProcessNamespaceID(target)
}

func parseProcessNamespaceID(value string) uint64 {
	opening := strings.LastIndex(value, "[")
	closing := strings.LastIndex(value, "]")
	if opening < 0 || closing <= opening+1 {
		return 0
	}

	id, err := strconv.ParseUint(value[opening+1:closing], 10, 64)
	if err != nil {
		return 0
	}

	return id
}

func detectProcessContainer(cgroupPath string) *processContainerSnapshot {
	for _, candidate := range containerCgroupPatterns {
		matches := candidate.pattern.FindStringSubmatch(cgroupPath)
		if len(matches) != 2 {
			continue
		}

		return &processContainerSnapshot{
			Runtime: candidate.runtime,
			ID:      strings.ToLower(matches[1]),
		}
	}

	return nil
}

func processNamespacesEmpty(namespaces processNamespaceSnapshot) bool {
	return namespaces == (processNamespaceSnapshot{})
}
