// Modified in 2026 by Ascheriit-Dkp.

package as

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

var asList []ASInfoIPv6

// ParseASNumbersIPv6 loads IPv6 autonomous-system ranges from a TSV file.
//
// The existing lookup data is replaced only after the complete file has been
// parsed successfully.
func ParseASNumbersIPv6(asTsvFile string) error {
	csvFile, err := os.Open(asTsvFile)
	if err != nil {
		return fmt.Errorf("open IPv6 ASN data %q: %w", asTsvFile, err)
	}
	defer csvFile.Close()

	reader := csv.NewReader(csvFile)
	reader.Comma = '\t'
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	parsedList := make([]ASInfoIPv6, 0)

	for recordNumber := 1; ; recordNumber++ {
		record, readErr := reader.Read()

		if errors.Is(readErr, io.EOF) {
			break
		}

		if readErr != nil {
			return fmt.Errorf(
				"read IPv6 ASN data %q at record %d: %w",
				asTsvFile,
				recordNumber,
				readErr,
			)
		}

		if len(record) < 5 {
			return fmt.Errorf(
				"parse IPv6 ASN data %q at record %d: expected at least 5 fields, got %d",
				asTsvFile,
				recordNumber,
				len(record),
			)
		}

		startIP, parseErr := parseIPv6Address(
			record[0],
			"start address",
			asTsvFile,
			recordNumber,
		)
		if parseErr != nil {
			return parseErr
		}

		endIP, parseErr := parseIPv6Address(
			record[1],
			"end address",
			asTsvFile,
			recordNumber,
		)
		if parseErr != nil {
			return parseErr
		}

		if bytes.Compare(endIP, startIP) < 0 {
			return fmt.Errorf(
				"parse IPv6 ASN data %q at record %d: end address %q is before start address %q",
				asTsvFile,
				recordNumber,
				record[1],
				record[0],
			)
		}

		asNumber, parseErr := parseIPv6ASNumber(
			record[2],
			asTsvFile,
			recordNumber,
		)
		if parseErr != nil {
			return parseErr
		}

		if asNumber == 0 {
			continue
		}

		description := strings.Join(record[4:], " ")

		parsedList = append(parsedList, ASInfoIPv6{
			StartIP:  startIP,
			EndIP:    endIP,
			AsNumber: asNumber,
			Name:     getNameOnly(description),
		})
	}

	asList = parsedList

	return nil
}

func parseIPv6Address(
	value string,
	fieldName string,
	asTsvFile string,
	recordNumber int,
) (net.IP, error) {
	parsedIP := net.ParseIP(strings.TrimSpace(value))
	if parsedIP == nil || parsedIP.To4() != nil {
		return nil, fmt.Errorf(
			"parse IPv6 ASN data %q at record %d: invalid %s %q",
			asTsvFile,
			recordNumber,
			fieldName,
			value,
		)
	}

	normalizedIP := parsedIP.To16()
	if normalizedIP == nil {
		return nil, fmt.Errorf(
			"parse IPv6 ASN data %q at record %d: invalid %s %q",
			asTsvFile,
			recordNumber,
			fieldName,
			value,
		)
	}

	ipCopy := make(net.IP, net.IPv6len)
	copy(ipCopy, normalizedIP)

	return ipCopy, nil
}

func parseIPv6ASNumber(
	value string,
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
			"parse IPv6 ASN data %q at record %d: invalid AS number %q: %w",
			asTsvFile,
			recordNumber,
			value,
			err,
		)
	}

	return uint32(parsedValue), nil
}

// GetASInfoIPv6 returns information about the autonomous system containing
// the supplied IPv6 address.
func GetASInfoIPv6(ip net.IP) ASInfoIPv6 {
	if ip == nil || ip.To4() != nil {
		return ASInfoIPv6{}
	}

	normalizedIP := ip.To16()
	if normalizedIP == nil {
		return ASInfoIPv6{}
	}

	for _, asInfo := range asList {
		if bytes.Compare(normalizedIP, asInfo.StartIP) >= 0 &&
			bytes.Compare(normalizedIP, asInfo.EndIP) <= 0 {
			return asInfo
		}
	}

	return ASInfoIPv6{}
}

// ASInfoIPv6 contains information about an autonomous system.
type ASInfoIPv6 struct {
	StartIP  net.IP
	EndIP    net.IP
	AsNumber uint32
	Name     string
}
