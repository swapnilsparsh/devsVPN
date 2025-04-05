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

package platform

import (
	"path"

	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
)

var (
	firewallScript string
	dnsScript      string
)

// initialize all constant values (e.g. servicePortFile) which can be used in external projects (privateLINE-Connect CLI)
func doInitConstants() {
	servicePortFile = "/Library/Application Support/privateLINE-Connect/port.txt"
	openvpnUserParamsFile = "/Library/Application Support/privateLINE-Connect/OpenVPN/ovpn_extra_params.txt"
	paranoidModeSecretFile = "/Library/Application Support/privateLINE-Connect/eaa"

	logDir := "/Library/Logs/"
	logFile = path.Join(logDir, helpers.ServiceName)
}

func doOsInit() (warnings []string, errors []error, logInfo []string) {
	routeCommand = "/sbin/route"

	warnings, errors = doOsInitForBuild()

	if errors == nil {
		errors = make([]error, 0)
	}

	if err := checkFileAccessRightsExecutable("firewallScript", firewallScript); err != nil {
		errors = append(errors, err)
	}
	if err := checkFileAccessRightsExecutable("dnsScript", dnsScript); err != nil {
		errors = append(errors, err)
	}

	return warnings, errors, logInfo
}

// FirewallScript returns path to firewal script
func FirewallScript() string {
	return firewallScript
}

// DNSScript returns path to DNS script
func DNSScript() string {
	return dnsScript
}

func implPLOtherAppsToAcceptIncomingConnections() (otherPlApps []string, err error) {
	return []string{}, nil // TODO FIXME: Vlad - implement on Linux also
}
