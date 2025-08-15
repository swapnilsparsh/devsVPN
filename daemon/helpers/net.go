package helpers

import (
	"net"
	"regexp"
)

var (
	// Regular expression for IPv4 addresses of form x.x.x.x
	IPv4AddrRegex = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

	// privacy filtering - mask hostname and MAC addresses
	MacAddrRegex                       = regexp.MustCompile(`([0-9a-fA-F]{2}[:\s-]){5,7}[0-9a-fA-F]{2}`)
	HostnameFieldPrefixWinRegex        = regexp.MustCompile(`[\s]*Host Name`)
	HostnameFieldPrefixWinFullStrRegex = regexp.MustCompile(`[\s]*Host Name.*`)
)

const MacAddrReplacement = "XX:XX:XX:XX:XX:XX"

type HostnameAndIP struct {
	Hostname        string
	DefaultIP       net.IP
	DefaultIpString string
}
