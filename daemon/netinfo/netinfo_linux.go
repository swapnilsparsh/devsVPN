//
//  Daemon for IVPN Client Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the Daemon for IVPN Client Desktop.
//
//  The Daemon for IVPN Client Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for IVPN Client Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for IVPN Client Desktop. If not, see <https://www.gnu.org/licenses/>.
//

package netinfo

import (
	"fmt"
	"net"
	"regexp"

	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

var outRegexp = regexp.MustCompile("default[ a-z]*([0-9.]*)(?:.*metric ([0-9]*))?")

// doDefaultGatewayIPs - returns: all default gateways
func doDefaultGatewayIPs() (defGatewayIPs []net.IP, err error) {

	// Expected output of "/sbin/ip route" command:
	//
	// default via 192.168.1.1 dev enp0s3 proto dhcp src 192.168.1.100 metric 100
	// default via 192.168.1.1 dev wlx1234 proto dhcp src 192.168.1.101 metric 600
	// 192.168.1.0/24 dev enp0s3 proto kernel scope link src 192.168.1.57 metric 100
	// 192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1 linkdown
	//
	// Note that metric value is optional, e.g.:	default via 192.168.1.1 dev eth0 onlink

	outParse := func(text string, isError bool) {
		if !isError {
			columns := outRegexp.FindStringSubmatch(text)
			if len(columns) <= 2 {
				return
			}
			gw := net.ParseIP(columns[1])
			if gw == nil {
				return
			}
			defGatewayIPs = append(defGatewayIPs, gw)
		}
	}

	retErr := shell.ExecAndProcessOutput(log, outParse, "", "/sbin/ip", "route")

	if retErr != nil {
		return nil, fmt.Errorf("Failed to obtain local gateways: %w", retErr)
	} else if len(defGatewayIPs) <= 0 {
		return nil, fmt.Errorf("No default gateways found")
	}

	return defGatewayIPs, nil
}
