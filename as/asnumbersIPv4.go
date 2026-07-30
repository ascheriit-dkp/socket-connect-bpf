// Modified in 2026 by Ascheriit-Dkp.

package as

import (
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ascheriit-dkp/socket-connect-bpf/conv"
)

var asMap = make(map[uint8][]ASInfo)

// ParseASNumbersIPv4 loads IPv4 autonomous-system ranges from a TSV file.
//
// The existing lookup data is replaced only after the complete file has been
// parsed successfully.
func ParseASNumbersIPv4(asTsvFile string) error {
	csvFile, err := os.Open(asTsvFile)
	if err != nil {
		return fmt.Errorf("open IPv4 ASN data %q: %w", asTsvFile, err)
	}
	defer csvFile.Close()

	reader := csv.NewReader(csvFile)
	reader.Comma = '\t'
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	parsedMap := make(map[uint8][]ASInfo)

	for recordNumber := 1; ; recordNumber++ {
		record, readErr := reader.Read()

		if errors.Is(readErr, io.EOF) {
			break
		}

		if readErr != nil {
			return fmt.Errorf(
				"read IPv4 ASN data %q at record %d: %w",
				asTsvFile,
				recordNumber,
				readErr,
			)
		}

		if len(record) < 5 {
			return fmt.Errorf(
				"parse IPv4 ASN data %q at record %d: expected at least 5 fields, got %d",
				asTsvFile,
				recordNumber,
				len(record),
			)
		}

		startAddr, parseErr := parseIPv4UintField(
			record[0],
			"start address",
			asTsvFile,
			recordNumber,
		)
		if parseErr != nil {
			return parseErr
		}

		endAddr, parseErr := parseIPv4UintField(
			record[1],
			"end address",
			asTsvFile,
			recordNumber,
		)
		if parseErr != nil {
			return parseErr
		}

		asNumber, parseErr := parseIPv4UintField(
			record[2],
			"AS number",
			asTsvFile,
			recordNumber,
		)
		if parseErr != nil {
			return parseErr
		}

		if endAddr < startAddr {
			return fmt.Errorf(
				"parse IPv4 ASN data %q at record %d: end address %d is before start address %d",
				asTsvFile,
				recordNumber,
				endAddr,
				startAddr,
			)
		}

		if asNumber == 0 {
			continue
		}

		entry := ASInfo{
			StartIP:  startAddr,
			EndIP:    endAddr,
			AsNumber: asNumber,
			Name:     getNameOnly(record[4]),
		}

		startBucket := uint16(startAddr >> 24)
		endBucket := uint16(endAddr >> 24)

		for bucket := startBucket; bucket <= endBucket; bucket++ {
			bucketID := uint8(bucket)
			parsedMap[bucketID] = append(parsedMap[bucketID], entry)
		}
	}

	asMap = parsedMap

	return nil
}

func parseIPv4UintField(
	value string,
	fieldName string,
	asTsvFile string,
	recordNumber int,
) (uint32, error) {
	parsedValue, err := strconv.ParseUint(
		strings.TrimSpace(value),
		10,
		32,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"parse IPv4 ASN data %q at record %d: invalid %s %q: %w",
			asTsvFile,
			recordNumber,
			fieldName,
			value,
			err,
		)
	}

	return uint32(parsedValue), nil
}

func toBigIP4(addr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, addr)

	return ip
}

func getNameOnly(description string) string {
	fields := strings.Fields(description)
	if len(fields) == 0 {
		return ""
	}

	return fields[0]
}

// GetASInfoIPv4 returns information about the autonomous system containing
// the supplied IPv4 address.
func GetASInfoIPv4(ip net.IP) ASInfo {
	ipAddr := conv.ToUint(ip)

	bs := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(bs, ipAddr)

	bucket := bs[0]
	values := asMap[bucket]

	for _, asInfo := range values {
		if checkRange(&asInfo, ipAddr) {
			return asInfo
		}
	}

	return ASInfo{}
}

func checkRange(asInfo *ASInfo, ipAddr uint32) bool {
	return ipAddr >= asInfo.StartIP && ipAddr <= asInfo.EndIP
}

// ASInfo contains information about an autonomous system.
type ASInfo struct {
	StartIP  uint32
	EndIP    uint32
	AsNumber uint32
	Name     string
}
