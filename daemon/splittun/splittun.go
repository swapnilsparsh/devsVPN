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

package splittun

import (
	"fmt"
	"net"
	"sync"

	"github.com/swapnilsparsh/devsVPN/daemon/logger"
)

var log *logger.Logger

func init() {
	log = logger.NewLogger("spltun")
}

const (
	// constants copied from Windows definitions
	AF_INET  uint16 = 2  // IPv4
	AF_INET6 uint16 = 23 // IPv6

	// 'blackhole' IP addresses. Used for forwarding all traffic of split-tunnel apps to 'nowhere' (in fact, to block traffic)
	BlackHoleIPv4 = "192.0.2.255" // RFC 5737 - IPv4 Address Blocks Reserved for Documentation
	BlackHoleIPv6 = "0100::1"     // RFC 6666 - A Discard Prefix for IPv6
)

var (
	mutex sync.Mutex

	// last known Wireguard VPN endpoints - we'll need them to reset the changed routes back to default routes (dest 0.0.0.0/0)
	// these are protected by the above mutex
	lastConfiguredEndpoints = map[uint16]*net.IP{
		AF_INET:  nil,
		AF_INET6: nil,
	}

	// and address sizes by IP family in bits: 32 for IPv4 and 128 for IPv6
	addrSizesByIpFamily = map[uint16]uint8{
		AF_INET:  32,
		AF_INET6: 128,
	}

	// all-zeroes for default routes
	defaultRouteIPv4 = "0.0.0.0/0"
	defaultRouteIPv6 = "::/0"
)

type ConfigAddresses struct {
	IPv4Public net.IP // OutboundIPv4
	IPv4Tunnel net.IP // VpnLocalIPv4
	IPv6Public net.IP // OutboundIPv6
	IPv6Tunnel net.IP // VpnLocalIPv6

	// PrivateLine Wireguard VPN endpoint
	IPv4Endpoint net.IP
	IPv6Endpoint net.IP
}

func (c ConfigAddresses) IsEmpty() bool {
	return len(c.IPv4Public) == 0 && len(c.IPv4Tunnel) == 0 && len(c.IPv6Public) == 0 && len(c.IPv6Tunnel) == 0
}

// Information about running application
// https://man7.org/linux/man-pages/man5/proc.5.html
type RunningApp struct {
	Pid                int
	Ppid               int // The PID of the parent of this process.
	Cmdline            string
	Exe                string // The actual pathname of the executed command
	ExtIvpnRootPid     int    // PID of the known parent process registered by AddPid() function
	ExtModifiedCmdLine string
}

// Initialize must be called first (before accessing any ST functionality)
// Normally, it should check if the ST functionality available
// Returns non-nil error object if Split-Tunneling functionality not available
func Initialize() error {
	mutex.Lock()
	defer mutex.Unlock()

	log.Info("Initializing Split-Tunnelling")
	err := implInitialize()
	if err != nil {
		return fmt.Errorf("error in implInitialize(): %w", err)
	}

	return nil
}

// IsFuncNotAvailableError returns non-nil error object if Split-Tunneling functionality not available
// The return value is the same as Initialize()
func GetFuncNotAvailableError() (generalStError, inversedStError error) {
	return implFuncNotAvailableError()
}

func Reset() error {
	mutex.Lock()
	defer mutex.Unlock()

	return implReset()
}

// ApplyConfig control split-tunnel functionality
func ApplyConfig(isStEnabled, isStInverse, enclaveAllowAllApps, isStInverseAllowWhenNoVpn, isVpnEnabled bool, addrConfig ConfigAddresses, splitTunnelApps []string) error {
	mutex.Lock()
	defer func() {
		log.Debug("ApplyConfig() completed")
		mutex.Unlock()
	}()
	log.Debug(fmt.Sprintf("ApplyConfig() started: isStEnabled=%t, isVpnEnabled=%t", isStEnabled, isVpnEnabled))
	// don't leave PrintStack calls enabled in production builds beyond the MVP
	// logger.PrintStackToStderr()

	if !isVpnEnabled {
		addrConfig.IPv4Tunnel = nil
		addrConfig.IPv6Tunnel = nil
	}

	if retErr := implApplyConfig(isStEnabled, isStInverse, enclaveAllowAllApps, isStInverseAllowWhenNoVpn, isVpnEnabled, addrConfig, splitTunnelApps); retErr != nil {
		return log.ErrorE(fmt.Errorf("error in implApplyConfig(): %w", retErr), 0)
	}
	return nil
}

// AddPid add process to Split-Tunnel environment
// (applicable for Linux)
func AddPid(pid int, commandToExecute string) error {
	return implAddPid(pid, commandToExecute)
}

// RemovePid remove process to Split-Tunnel environment
// (applicable for Linux)
func RemovePid(pid int) error {
	return implRemovePid(pid)
}

// Get information about active applications running in Split-Tunnel environment
// (applicable for Linux)
func GetRunningApps() (allProcesses []RunningApp, err error) {
	return implGetRunningApps()
}
