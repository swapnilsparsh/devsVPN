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
	"bytes"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// doDefaultGatewayIPs - returns: all default gateway IPs
func doDefaultGatewayIPs() (defGatewayIPs []net.IP, err error) {
	routes, err := getWindowsIPv4Routes()
	if err != nil {
		return nil, fmt.Errorf("failed to get routes: %w", err)
	}

	for _, route := range routes {
		// Eample:
		// Network 		Destination  	Netmask   		Gateway    		Interface  Metric
		// 0.0.0.0   	0.0.0.0      	192.168.1.1 	192.168.1.248	35
		// 0.0.0.0 		128.0.0.0      	10.59.44.1   	10.59.44.2  	15 <- route to virtual VPN interface !!!
		zeroBytes := []byte{0, 0, 0, 0}
		if bytes.Equal(route.DwForwardDest[:], zeroBytes) && bytes.Equal(route.DwForwardMask[:], zeroBytes) { // Network == 0.0.0.0 && Netmask == 0.0.0.0
			defGatewayIPs = append(defGatewayIPs, net.IPv4(route.DwForwardNextHop[0],
				route.DwForwardNextHop[1],
				route.DwForwardNextHop[2],
				route.DwForwardNextHop[3]))
		}
	}

	if len(defGatewayIPs) > 0 {
		return defGatewayIPs, nil
	} else {
		return nil, fmt.Errorf("failed to determine default route")
	}
}

// DefaultGatewayEx returns one of the interfaces that has the default route for the given address family.
// If there are multiple such interfaces, metric is not taken into account.
func DefaultGatewayEx(isIpv6 bool) (defGatewayIP net.IP, inf *net.Interface, err error) {
	defGatewaysAndIfaces, err := DefaultRoutesEx(isIpv6)
	if err != nil {
		return nil, nil, err
	} else if len(defGatewaysAndIfaces) > 0 {
		return defGatewaysAndIfaces[0].route.NextHop.Addr().AsSlice(), defGatewaysAndIfaces[0].iface, nil
	} else {
		return nil, nil, fmt.Errorf("DefaultGatewaysEx() failed")
	}
}

type gatewayAndInterface struct {
	//	defGatewayIP net.IP
	route winipcfg.MibIPforwardRow2
	iface *net.Interface
}

// DefaultRoutesEx returns all routes (with interfaces) that have the default route for the given address family.
func DefaultRoutesEx(isIpv6 bool) (defRoutesAndInterfaces []gatewayAndInterface, err error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if isIpv6 {
		family = winipcfg.AddressFamily(windows.AF_INET6)
	}

	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue // skip non-default routes
		}
		for _, iface := range ifaces {
			if uint32(iface.Index) != route.InterfaceIndex || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback == 1 {
				continue // skip down and loopback interfaces
			}

			// gatewayIP := route.NextHop.Addr().AsSlice()
			entry := gatewayAndInterface{route, &iface}
			defRoutesAndInterfaces = append(defRoutesAndInterfaces, entry)
		}
	}

	if len(defRoutesAndInterfaces) > 0 {
		return defRoutesAndInterfaces, nil
	} else {
		return nil, fmt.Errorf("no default routes found for family %v", family)
	}
}
