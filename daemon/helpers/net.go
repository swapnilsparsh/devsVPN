package helpers

import "regexp"

// Regular expression for IPv4 addresses of form x.x.x.x
var IPv4AddrRegex = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
