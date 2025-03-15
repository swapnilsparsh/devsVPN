//
//  Daemon for privateLINE Connect Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the Daemon for privateLINE Connect Desktop.
//
//  The Daemon for privateLINE Connect Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for privateLINE Connect Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for privateLINE Connect Desktop. If not, see <https://www.gnu.org/licenses/>.
//

//go:build linux
// +build linux

// Here we have Linux firewall logic for iptables-legacy firewall interface

package firewall

import (
	"os/exec"
	"sync"

	"github.com/singchia/go-xtables/iptables"
)

const (
	IPTABLES_LEGACY = "iptables-legacy"

	VPN_COEXISTENCE_CHAIN_LEGACY_IN  = VPN_COEXISTENCE_CHAIN_PREFIX + "-legacy-in"
	VPN_COEXISTENCE_CHAIN_LEGACY_OUT = VPN_COEXISTENCE_CHAIN_PREFIX + "-legacy-out"
)

var (
	fwLinuxLegacyMutex                       sync.Mutex           // global lock for firewall_linux_legacy read and write operations
	stopMonitoringFirewallChangesLegacy      = make(chan bool, 2) // used to send a stop signal to implFirewallBackgroundMonitorLegacy() thread
	implFirewallBackgroundMonitorLegacyMutex sync.Mutex           // to ensure there's only one instance of implFirewallBackgroundMonitorLegacy function

	iptablesLegacyPath string                   // empty if iptables-legacy not found in path
	ipt                *iptables.IPTables = nil // nil if iptables-legacy not found
)

func implInitializeLegacy() (err error) {
	if iptablesLegacyPath, err = exec.LookPath(IPTABLES_LEGACY); err != nil {
		return log.ErrorFE("error looking up %s in PATH: %w", IPTABLES_LEGACY, err)
	}

	ipt = iptables.NewIPTables(iptables.OptionIPTablesCmdPath(iptablesLegacyPath), iptables.OptionIPTablesLogger(log))

	return nil
}

func iptablesLegacyPresent() bool {
	return ipt != nil
}

func implHaveTopFirewallPriorityLegacy() (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	weHaveTopFirewallPriority, retErr = implGetEnabledLegacy()
	return weHaveTopFirewallPriority, "", "", "", retErr
}

func implGetEnabledLegacy() (exists bool, retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return false, nil
	}

	// TODO FIXME: Vlad - flesh out
	return false, nil
}

func implReregisterFirewallAtTopPriorityLegacy() (firewallReconfigured bool, retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return false, nil
	}

	// TODO FIXME: Vlad - flesh out

	// to ensure there's only one instance of this function, and that no other read or write operations are taking place in parallel
	fwLinuxLegacyMutex.Lock()
	defer fwLinuxLegacyMutex.Unlock()
	// ...

	return false, nil
}

// implFirewallBackgroundMonitorLegacy runs as a background thread, monitors (polls) iptables-legacy tables for changes
// It checks whether we have top firewall priority. If don't have top pri - it recreates our firewall objects.
func implFirewallBackgroundMonitorLegacy() {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	// TODO FIXME: Vlad - flesh out

	implFirewallBackgroundMonitorLegacyMutex.Lock() // to ensure there's only one instance of implFirewallBackgroundMonitorLegacy
	defer implFirewallBackgroundMonitorLegacyMutex.Unlock()

	log.Debug("implFirewallBackgroundMonitorLegacy entered")
	defer log.Debug("implFirewallBackgroundMonitorLegacy exited")
	// ...
}

func implReEnableLegacy(fwLinuxLegacyMutexGrabbed bool) (retErr error) {
	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("implReEnableLegacy")

	if err := doDisableLegacy(true); err != nil {
		return log.ErrorFE("failed to disable iptables-legacy firewall: %w", err)
	}

	if err := doEnableLegacy(true); err != nil {
		return log.ErrorFE("failed to enable iptables-legacy firewall: %w", err)
	}

	//return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
	return nil
}

func doEnableLegacy(fwLinuxLegacyMutexGrabbed bool) (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	// TODO FIXME: Vlad - flesh out

	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("doEnableLegacy entered")
	defer log.Debug("doEnableLegacy exited")
	// ...

	return nil
}

func implDeployPostConnectionRulesLegacy(fwLinuxLegacyMutexGrabbed bool) (retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	// TODO FIXME: Vlad - flesh out

	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}
	// ...

	return nil
}

func doDisableLegacy(fwLinuxLegacyMutexGrabbed bool) (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	// TODO FIXME: Vlad - flesh out
	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("doDisableLegacy entered")
	defer log.Debug("doDisableLegacy exited")
	// ...

	return nil
}

func implOnChangeDnsLegacy() (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	// TODO FIXME: Vlad - flesh out
	fwLinuxLegacyMutex.Lock()
	defer fwLinuxLegacyMutex.Unlock()
	// ...

	return nil
}

func implTotalShieldApplyLegacy(_totalShieldEnabled bool) (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	// TODO FIXME: Vlad - flesh out
	fwLinuxLegacyMutex.Lock()
	defer fwLinuxLegacyMutex.Unlock()

	// by now we know the firewall is up - gotta add or remove DROP rules to reflect new Total Shield setting
	// ...

	return nil
}
