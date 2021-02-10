package ip2cidr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
)

func IPRangeToCIDR(start, end string) ([]string, error) {
	cidrToMask := []uint32{
		0x00000000, 0x80000000, 0xC0000000,
		0xE0000000, 0xF0000000, 0xF8000000,
		0xFC000000, 0xFE000000, 0xFF000000,
		0xFF800000, 0xFFC00000, 0xFFE00000,
		0xFFF00000, 0xFFF80000, 0xFFFC0000,
		0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
		0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
		0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
		0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
		0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
		0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
	}

	startAddr, err := ipToLong(start)
	if err != nil {
		return []string{}, err
	}
	endAddr, err := ipToLong(end)
	if err != nil {
		return []string{}, err
	}

	if startAddr > endAddr {
		return []string{}, errors.New("start of IP range must be less than the end")
	}

	var cidrList []string

	for i := endAddr; i >= startAddr; i-- {
		maxSize := 32
		for j := maxSize; j > 0; j-- {
			mask := cidrToMask[maxSize-1]
			maskedBase := startAddr & mask

			if maskedBase != startAddr {
				break
			}

			maxSize--
		}

		x := math.Log(float64(endAddr-startAddr+1)) / math.Log(2)
		maxDiff := int(32) - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}

		cidrList = append(cidrList, fmt.Sprintf("%s/%s", longToIP(startAddr), strconv.Itoa(maxSize)))
		startAddr += uint32(math.Pow(2, float64(32-maxSize)))
	}
	return cidrList, nil
}

func ipToLong(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, errors.New("wrong IP address format")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

func longToIP(ipl uint32) string {
	ipb := make([]byte, 4)
	binary.BigEndian.PutUint32(ipb, ipl)
	ip := net.IP(ipb)
	return ip.String()
}

func intToIP(ipi uint32) string {
	result := make(net.IP, 4)
	result[0] = byte(ipi)
	result[1] = byte(ipi >> 8)
	result[2] = byte(ipi >> 16)
	result[3] = byte(ipi >> 24)
	return result.String()
}
