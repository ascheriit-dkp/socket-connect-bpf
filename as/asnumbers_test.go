package as

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseASNumbersIPv4LoadsCrossBucketRange(t *testing.T) {
	originalMap := asMap
	t.Cleanup(func() {
		asMap = originalMap
	})

	asMap = make(map[uint8][]ASInfo)

	startAddress := ipv4Uint(t, "10.255.255.250")
	endAddress := ipv4Uint(t, "11.0.0.5")

	validPath := writeASNFixture(
		t,
		"ipv4-valid.tsv",
		fmt.Sprintf(
			"%d\t%d\t64501\tZZ\tEXAMPLE NETWORK\n",
			startAddress,
			endAddress,
		),
	)

	if err := ParseASNumbersIPv4(validPath); err != nil {
		t.Fatalf("ParseASNumbersIPv4() error = %v", err)
	}

	got := GetASInfoIPv4(toBigIP4(ipv4Uint(t, "11.0.0.1")))

	if got.AsNumber != 64501 {
		t.Fatalf("GetASInfoIPv4().AsNumber = %d, want 64501", got.AsNumber)
	}

	if got.Name != "EXAMPLE" {
		t.Fatalf("GetASInfoIPv4().Name = %q, want %q", got.Name, "EXAMPLE")
	}

	invalidPath := writeASNFixture(
		t,
		"ipv4-invalid.tsv",
		"not-a-number\t184549381\t64502\tZZ\tBROKEN NETWORK\n",
	)

	err := ParseASNumbersIPv4(invalidPath)
	if err == nil {
		t.Fatal("ParseASNumbersIPv4() error = nil, want an error")
	}

	if !strings.Contains(err.Error(), "invalid start address") {
		t.Fatalf(
			"ParseASNumbersIPv4() error = %q, want invalid start address context",
			err,
		)
	}

	gotAfterFailure := GetASInfoIPv4(
		toBigIP4(ipv4Uint(t, "11.0.0.1")),
	)

	if gotAfterFailure.AsNumber != 64501 {
		t.Fatalf(
			"lookup after failed parse returned AS%d, want AS64501",
			gotAfterFailure.AsNumber,
		)
	}
}

func TestParseASNumbersIPv6LoadsDataAndPreservesItOnError(t *testing.T) {
	originalList := asList
	t.Cleanup(func() {
		asList = originalList
	})

	asList = nil

	validPath := writeASNFixture(
		t,
		"ipv6-valid.tsv",
		"2001:db8::\t2001:db8::ffff\t64510\tZZ\tEXAMPLE NETWORK NAME\n",
	)

	if err := ParseASNumbersIPv6(validPath); err != nil {
		t.Fatalf("ParseASNumbersIPv6() error = %v", err)
	}

	got := GetASInfoIPv6(net.ParseIP("2001:db8::42"))

	if got.AsNumber != 64510 {
		t.Fatalf("GetASInfoIPv6().AsNumber = %d, want 64510", got.AsNumber)
	}

	if got.Name != "EXAMPLE" {
		t.Fatalf("GetASInfoIPv6().Name = %q, want %q", got.Name, "EXAMPLE")
	}

	invalidPath := writeASNFixture(
		t,
		"ipv6-invalid.tsv",
		"not-an-ip\t2001:db8::ffff\t64511\tZZ\tBROKEN NETWORK\n",
	)

	err := ParseASNumbersIPv6(invalidPath)
	if err == nil {
		t.Fatal("ParseASNumbersIPv6() error = nil, want an error")
	}

	if !strings.Contains(err.Error(), "invalid start address") {
		t.Fatalf(
			"ParseASNumbersIPv6() error = %q, want invalid start address context",
			err,
		)
	}

	gotAfterFailure := GetASInfoIPv6(net.ParseIP("2001:db8::42"))

	if gotAfterFailure.AsNumber != 64510 {
		t.Fatalf(
			"lookup after failed parse returned AS%d, want AS64510",
			gotAfterFailure.AsNumber,
		)
	}
}

func ipv4Uint(t *testing.T, value string) uint32 {
	t.Helper()

	ip := net.ParseIP(value).To4()
	if ip == nil {
		t.Fatalf("net.ParseIP(%q).To4() returned nil", value)
	}

	return binary.BigEndian.Uint32(ip)
}

func writeASNFixture(
	t *testing.T,
	filename string,
	content string,
) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), filename)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}

	return path
}
