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
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ascheriit-dkp/socket-connect-bpf/as"
)

func TestResolveASNDirectoryUsesConfiguredRelativePath(t *testing.T) {
	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(originalWorkingDirectory); err != nil {
			t.Errorf(
				"os.Chdir(%q) during cleanup error = %v",
				originalWorkingDirectory,
				err,
			)
		}
	})

	workingDirectory := t.TempDir()

	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatalf("os.Chdir(%q) error = %v", workingDirectory, err)
	}

	got, err := resolveASNDirectory(
		filepath.Join("custom", "..", "datasets"),
	)
	if err != nil {
		t.Fatalf("resolveASNDirectory() error = %v", err)
	}

	want := filepath.Join(workingDirectory, "datasets")

	if got != want {
		t.Fatalf(
			"resolveASNDirectory() = %q, want %q",
			got,
			want,
		)
	}
}

func TestLoadASNDataLoadsBothDatasets(t *testing.T) {
	asnDirectory := t.TempDir()

	ipv4Start := ipv4AddressUint(t, "203.0.113.0")
	ipv4End := ipv4AddressUint(t, "203.0.113.255")

	writeMainASNFixture(
		t,
		filepath.Join(asnDirectory, "ip2asn-v4-u32.tsv"),
		fmt.Sprintf(
			"%d\t%d\t64520\tZZ\tTEST IPV4 NETWORK\n",
			ipv4Start,
			ipv4End,
		),
	)

	writeMainASNFixture(
		t,
		filepath.Join(asnDirectory, "ip2asn-v6.tsv"),
		"2001:db8:1::\t2001:db8:1::ffff\t64521\tZZ\tTEST IPV6 NETWORK\n",
	)

	if err := loadASNData(asnDirectory); err != nil {
		t.Fatalf("loadASNData() error = %v", err)
	}

	ipv4Info := as.GetASInfoIPv4(
		net.ParseIP("203.0.113.42").To4(),
	)

	if ipv4Info.AsNumber != 64520 {
		t.Fatalf(
			"IPv4 lookup returned AS%d, want AS64520",
			ipv4Info.AsNumber,
		)
	}

	if ipv4Info.Name != "TEST" {
		t.Fatalf(
			"IPv4 lookup returned name %q, want %q",
			ipv4Info.Name,
			"TEST",
		)
	}

	ipv6Info := as.GetASInfoIPv6(
		net.ParseIP("2001:db8:1::42"),
	)

	if ipv6Info.AsNumber != 64521 {
		t.Fatalf(
			"IPv6 lookup returned AS%d, want AS64521",
			ipv6Info.AsNumber,
		)
	}

	if ipv6Info.Name != "TEST" {
		t.Fatalf(
			"IPv6 lookup returned name %q, want %q",
			ipv6Info.Name,
			"TEST",
		)
	}
}

func TestLoadASNDataReportsMissingIPv6Dataset(t *testing.T) {
	asnDirectory := t.TempDir()

	ipv4Start := ipv4AddressUint(t, "198.51.100.0")
	ipv4End := ipv4AddressUint(t, "198.51.100.255")

	writeMainASNFixture(
		t,
		filepath.Join(asnDirectory, "ip2asn-v4-u32.tsv"),
		fmt.Sprintf(
			"%d\t%d\t64530\tZZ\tTEST NETWORK\n",
			ipv4Start,
			ipv4End,
		),
	)

	err := loadASNData(asnDirectory)
	if err == nil {
		t.Fatal("loadASNData() error = nil, want an error")
	}

	if !strings.Contains(err.Error(), "load IPv6 ASN dataset") {
		t.Fatalf(
			"loadASNData() error = %q, want IPv6 dataset context",
			err,
		)
	}

	if !strings.Contains(err.Error(), "ip2asn-v6.tsv") {
		t.Fatalf(
			"loadASNData() error = %q, want missing filename",
			err,
		)
	}
}

func ipv4AddressUint(t *testing.T, value string) uint32 {
	t.Helper()

	ip := net.ParseIP(value).To4()
	if ip == nil {
		t.Fatalf("net.ParseIP(%q).To4() returned nil", value)
	}

	return binary.BigEndian.Uint32(ip)
}

func writeMainASNFixture(
	t *testing.T,
	path string,
	content string,
) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}
