package ip

import (
	"encoding/binary" // For binary.BigEndian.PutUint32
	"net"
)

// converts integer to ips
func IntToIP(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}
