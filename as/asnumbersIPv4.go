package as

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ascheriit-dkp/socket-connect-bpf/conv"
)

var asMap = make(map[uint8][]ASInfo)

// ParseASNumbersIPv4 parses the autonomous system (AS) Numbers and IPv4 ranges from a .tsv file
func ParseASNumbersIPv4(asTsvFile string) {
	csvFile, err := os.Open(asTsvFile)

	if err != nil {
		fmt.Println("Could not read AS Number file")
		fmt.Println(err)
		return
	}

	defer csvFile.Close()

	reader := csv.NewReader(csvFile)

	reader.Comma = '\t'
	reader.LazyQuotes = true

	reader.FieldsPerRecord = -1

	csvData, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Could not read AS Number file")
		fmt.Println(err)
		return
	}

	for _, each := range csvData {
		startAddr, _ := strconv.ParseUint(each[0], 10, 32)

		bs := make([]byte, 4)
		binary.BigEndian.PutUint32(bs, uint32(startAddr))

		endAddr, _ := strconv.ParseUint(each[1], 10, 32)
		asNumber, _ := strconv.ParseUint(each[2], 10, 32)

		if asNumber != 0 {
			asName := getNameOnly(each[4])
			bucket := bs[0]

			entry := ASInfo{
				StartIP:  uint32(startAddr),
				EndIP:    uint32(endAddr),
				AsNumber: uint32(asNumber),
				Name:     asName,
			}

			values, ok := asMap[bucket]
			if !ok {
				asMap[bucket] = []ASInfo{entry}
			} else {
				asMap[bucket] = append(values, entry)
			}
		}
	}
}

func toBigIP4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)

	return ip
}

func getNameOnly(description string) string {
	return strings.Fields(description)[0]
}

// GetASInfoIPv4 returns information about the autonomous system containing
// the supplied IPv4 address.
func GetASInfoIPv4(ip net.IP) ASInfo {
	ipAddr := conv.ToUint(ip)

	bs := make([]byte, 4)
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
	if ipAddr < asInfo.StartIP {
		return false
	}

	if ipAddr > asInfo.EndIP {
		return false
	}

	return true
}

// ASInfo contains information about an autonomous system.
type ASInfo struct {
	StartIP  uint32
	EndIP    uint32
	AsNumber uint32
	Name     string
}
