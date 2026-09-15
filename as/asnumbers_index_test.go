package as

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestIndexedIPv4LookupHandlesUnsortedInput(t *testing.T) {
	originalMap := asMap
	t.Cleanup(func() {
		asMap = originalMap
	})

	firstStart := ipv4Uint(t, "10.0.1.0")
	firstEnd := ipv4Uint(t, "10.0.1.255")
	secondStart := ipv4Uint(t, "10.0.0.0")
	secondEnd := ipv4Uint(t, "10.0.0.255")

	path := writeASNFixture(
		t,
		"ipv4-unsorted.tsv",
		fmt.Sprintf(
			"%d\t%d\t64502\tZZ\tSECOND NETWORK\n%d\t%d\t64501\tZZ\tFIRST NETWORK\n",
			firstStart,
			firstEnd,
			secondStart,
			secondEnd,
		),
	)

	if err := ParseASNumbersIPv4(path); err != nil {
		t.Fatal(err)
	}

	if got := GetASInfoIPv4(net.ParseIP("10.0.0.42")); got.AsNumber != 64501 {
		t.Fatalf("10.0.0.42 = AS%d, want AS64501", got.AsNumber)
	}
	if got := GetASInfoIPv4(net.ParseIP("10.0.1.42")); got.AsNumber != 64502 {
		t.Fatalf("10.0.1.42 = AS%d, want AS64502", got.AsNumber)
	}
	if got := GetASInfoIPv4(net.ParseIP("10.0.2.42")); got.AsNumber != 0 {
		t.Fatalf("10.0.2.42 = AS%d, want no match", got.AsNumber)
	}
}

func TestIndexedIPv6LookupHandlesUnsortedInput(t *testing.T) {
	originalList := asList
	t.Cleanup(func() {
		asList = originalList
	})

	path := writeASNFixture(
		t,
		"ipv6-unsorted.tsv",
		"2001:db8:1::\t2001:db8:1::ffff\t64512\tZZ\tSECOND NETWORK\n"+
			"2001:db8::\t2001:db8::ffff\t64511\tZZ\tFIRST NETWORK\n",
	)

	if err := ParseASNumbersIPv6(path); err != nil {
		t.Fatal(err)
	}

	if got := GetASInfoIPv6(net.ParseIP("2001:db8::42")); got.AsNumber != 64511 {
		t.Fatalf("2001:db8::42 = AS%d, want AS64511", got.AsNumber)
	}
	if got := GetASInfoIPv6(net.ParseIP("2001:db8:1::42")); got.AsNumber != 64512 {
		t.Fatalf("2001:db8:1::42 = AS%d, want AS64512", got.AsNumber)
	}
	if got := GetASInfoIPv6(net.ParseIP("2001:db8:2::42")); got.AsNumber != 0 {
		t.Fatalf("2001:db8:2::42 = AS%d, want no match", got.AsNumber)
	}
}

func BenchmarkGetASInfoIPv4Indexed(b *testing.B) {
	originalMap := asMap
	b.Cleanup(func() {
		asMap = originalMap
	})

	const entryCount = 32768
	entries := make([]ASInfo, entryCount)
	base := uint32(10) << 24
	for index := range entries {
		address := base + uint32(index*2)
		entries[index] = ASInfo{
			StartIP:  address,
			EndIP:    address,
			AsNumber: uint32(64512 + index%1024),
			Name:     "BENCH",
		}
	}
	asMap = map[uint8][]ASInfo{10: entries}

	targetValue := entries[len(entries)-1].StartIP
	target := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(target, targetValue)

	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result := GetASInfoIPv4(target)
		if result.AsNumber == 0 {
			b.Fatal("lookup returned no ASN")
		}
	}
}

func BenchmarkGetASInfoIPv6Indexed(b *testing.B) {
	originalList := asList
	b.Cleanup(func() {
		asList = originalList
	})

	const entryCount = 65536
	entries := make([]ASInfoIPv6, entryCount)
	for index := range entries {
		start := make(net.IP, net.IPv6len)
		binary.BigEndian.PutUint32(start[0:4], 0x20010db8)
		binary.BigEndian.PutUint32(start[12:16], uint32(index*2))
		end := append(net.IP(nil), start...)
		entries[index] = ASInfoIPv6{
			StartIP:  start,
			EndIP:    end,
			AsNumber: uint32(64512 + index%1024),
			Name:     "BENCH",
		}
	}
	asList = entries
	target := append(net.IP(nil), entries[len(entries)-1].StartIP...)

	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result := GetASInfoIPv6(target)
		if result.AsNumber == 0 {
			b.Fatal("lookup returned no ASN")
		}
	}
}
