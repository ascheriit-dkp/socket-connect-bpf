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

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

var (
	buildVersion = "devel"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

type versionFlagValue struct{}

func (versionFlagValue) String() string {
	return "false"
}

func (versionFlagValue) Set(value string) error {
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("parse --version value: %w", err)
	}
	if !enabled {
		return nil
	}

	fmt.Fprintln(os.Stdout, formatBuildVersion())
	os.Exit(0)
	return nil
}

func (versionFlagValue) IsBoolFlag() bool {
	return true
}

func init() {
	flag.CommandLine.Var(
		versionFlagValue{},
		"version",
		"print version, commit and build date, then exit",
	)
}

func formatBuildVersion() string {
	return fmt.Sprintf(
		"socket-connect-bpf %s commit=%s built=%s",
		buildVersion,
		buildCommit,
		buildDate,
	)
}
