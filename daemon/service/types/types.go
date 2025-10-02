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

package types

type KillSwitchStatus struct {
	IsEnabled         bool   // FW state
	IsPersistent      bool   // configuration: true - when persistent
	IsAllowLAN        bool   // configuration: 'Allow LAN'
	IsAllowMulticast  bool   // configuration: 'Allow multicast'
	IsAllowApiServers bool   // configuration: 'Allow API servers'
	UserExceptions    string // configuration: Firewall exceptions: comma separated list of IP addresses (masks) in format: x.x.x.x[/xx]

	StateLanAllowed           bool // real state of 'Allow LAN'
	WeHaveTopFirewallPriority bool // whether PL Firewall sublayer is registered at top weight (0xFFFF) in WFP
	// if PL Firewall sublayer is not registered at top weight, then this is the information about the other guy

	// ID, name, description of other VPN that has top firewall priority
	OtherVpnID          string
	OtherVpnName        string
	OtherVpnDescription string

	// whether other VPNs detected, that are reconfigurable
	ReconfigurableOtherVpnsDetected bool
	ReconfigurableOtherVpnsNames    []string
	NordVpnUpOnWindows              bool // whether UI needs to show the user manual instructions to configure NordVPN on Windows
}

// Type - VPN type
type HealthchecksTypeEnum int

// Supported VPN protocols
const (
	HealthchecksType_Ping        HealthchecksTypeEnum = iota
	HealthchecksType_RestApiCall HealthchecksTypeEnum = iota
	HealthchecksType_Disabled    HealthchecksTypeEnum = iota

	HealthchecksTypeDefault = HealthchecksType_Ping
)

var (
	HealthcheckTypeNames = []string{"Ping", "RestApiCall", "Disabled"}

	HealthcheckTypesByName = map[string]HealthchecksTypeEnum{
		HealthcheckTypeNames[HealthchecksType_Ping]:        HealthchecksType_Ping,
		HealthcheckTypeNames[HealthchecksType_RestApiCall]: HealthchecksType_RestApiCall,
		HealthcheckTypeNames[HealthchecksType_Disabled]:    HealthchecksType_Disabled,
	}
)

type SetHealthchecksTypeCallback func(_healthchecksType HealthchecksTypeEnum)
