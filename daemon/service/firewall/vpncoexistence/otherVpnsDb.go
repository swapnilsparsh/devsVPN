// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

//go:build windows
// +build windows

package vpncoexistence

import (
	"syscall"
)

type otherVpnCliCmds struct {
	cmdStatus            string
	statusConnectedRE    string
	statusDisconnectedRE string

	cmdEnableSplitTun                  []string
	cmdAddOurBinaryToSplitTunWhitelist []string
	cmdConnect                         string
	cmdDisconnect                      string
}

// Contains all the information about another VPN that we need to configure interoperability
type OtherVpnInfo struct {
	name        string // brief name of another VPN
	serviceName string // name of Windows service, used to restart it
	cliPath     string // full path to CLI of that VPN, used to start connection and add our binaries to their split-tunnel whitelist
	cliCmds     otherVpnCliCmds
}

var (
	// sublayer GUIDS of other VPNs known to us
	mullvadSublayerKey = syscall.GUID{Data1: 0xC78056FF, Data2: 0x2BC1, Data3: 0x4211, Data4: [8]byte{0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D}}

	// map from WFP sublayer GUID to the information about the other VPN that created and owns that sublayer
	OtherVpnsBySublayerGUID = map[syscall.GUID]OtherVpnInfo{
		mullvadSublayerKey: {
			name:        "Mullvad VPN",
			serviceName: "MullvadVPN",
			cliPath:     "ProgramFiles/Mullvad VPN/resources/mullvad.exe",
			cliCmds: otherVpnCliCmds{
				cmdStatus:                          "status",
				statusConnectedRE:                  "^Connected([^a-zA-Z0-9]|$)", // must be 1st line
				statusDisconnectedRE:               "^Disconnected([^a-zA-Z0-9]|$)",
				cmdEnableSplitTun:                  []string{"split-tunnel", "set", "on"},
				cmdAddOurBinaryToSplitTunWhitelist: []string{"split-tunnel", "app", "add"},
				cmdConnect:                         "connect",
				cmdDisconnect:                      "disconnect",
			},
		},
	}
)
