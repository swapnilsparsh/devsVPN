// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

//go:build windows
// +build windows

// TODO FIXME: NordVPN CLI

package vpncoexistence

import (
	"regexp"
	"syscall"

	mapset "github.com/deckarep/golang-set/v2"
)

var ZeroGUID = syscall.GUID{}

const (
	MIN_BRAND_FIRST_WORD_LEN = 4 // first word must be at least 4 characters long to be a candidate for brand name
	// MAX_WINDOWS_SERVICE_CANDIDATES = 10
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
	name       string // display name of another VPN
	namePrefix string // name prefix used to match sublayer, provider names, and Windows service names
	cliPath    string // full path to CLI of that VPN, used to start connection and add our binaries to their split-tunnel whitelist
	cliCmds    otherVpnCliCmds
}

var (
	// blacklist of words that can't be brand name candidates
	// Vlad - don't stop services whose name starts with "Wireguard", because we don't want to kill our own connection, lol
	invalidServiceNamePrefixes mapset.Set[string] = mapset.NewSet[string]("microsoft", "windefend", "edge", "intel", "wireguard")

	// Windows service names to try always:

	// SurfShark uses random GUIDs for its sublayer 0xFFFF (named "WireGuard filters") and provider "WireGuard provider", so try its named services always
	// "Surfshark Service", "Surfshark WireGuard"

	// Must keep both lists in sync. otherVpnDefaultServiceNamePrefixesToTry must contain literal words, not regular expressions.
	otherVpnDefaultServiceNamePrefixesToTry mapset.Set[string] = mapset.NewSet[string]("mullvad", "expressvpn", "surfshark", "nord", "proton", "ivpn", "hideme",
		"mozillavpn", "windscribe", "ipvcallout", "ipvan", "cyberghost", "proton", "tunnelbear", "vypervpn", "vyprvpn", "turbovpn", "cloudflarewarp",
		"urbanvpn", "eddieelevation", "hshld", "hotspotshield", "privateinternetaccess", "hola", "avg", "securevpn")
	// (?i) for case-insensitive matching, regex matching group not closed in this string - must be closed where used
	otherVpnDefaultServiceNameBrandsRegexStart = "(?i)^(mullvad|expressvpn|surfshark|nord|proton|ivpn|hideme|mozillavpn|windscribe|ipv(callout|an)|" +
		"cyberghost|proton|tunnelbear|vype?rvpn|turbovpn|cloudflarewarp|urbanvpn|eddie.?elevation|hshld|hotspotshield|privateinternetaccess|" +
		"hola(.?vpn|[^a-z0-9]|$)|.*updater_.*_hola|avg|securevpn"
	otherVpnDefaultServiceNamePrefixesRE = regexp.MustCompile(otherVpnDefaultServiceNameBrandsRegexStart + ")")

	// other VPNs known to us

	// Mullvad
	mullvadSublayerKey = syscall.GUID{Data1: 0xC78056FF, Data2: 0x2BC1, Data3: 0x4211, Data4: [8]byte{0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D}}
	mullvadProfile     = OtherVpnInfo{
		name:       "Mullvad VPN",
		namePrefix: "mullvad",
		cliPath:    "ProgramFiles/Mullvad VPN/resources/mullvad.exe",
		cliCmds: otherVpnCliCmds{
			cmdStatus:                          "status",
			statusConnectedRE:                  "^Connected([^a-zA-Z0-9]|$)", // must be 1st line
			statusDisconnectedRE:               "^Disconnected([^a-zA-Z0-9]|$)",
			cmdEnableSplitTun:                  []string{"split-tunnel", "set", "on"},
			cmdAddOurBinaryToSplitTunWhitelist: []string{"split-tunnel", "app", "add"},
			cmdConnect:                         "connect",
			cmdDisconnect:                      "disconnect",
		},
	}

	// TODO: NordVPN CLI
	// NordVPN
	nordVpnSublayerKey = syscall.GUID{Data1: 0x92C759E5, Data2: 0x03BA, Data3: 0x41AD, Data4: [8]byte{0xA5, 0x99, 0x68, 0xAF, 0x2C, 0x1A, 0x17, 0xE5}}
	nordVpnProfile     = OtherVpnInfo{
		name:       "NordVPN",
		namePrefix: "nord",
		cliPath:    "",
		//cliPath:    "ProgramFiles/NordVPN/NordVPN.exe", // disabled for now, since we didn't find yet a programmatic way to check whether VPN is connected
		cliCmds: otherVpnCliCmds{
			cmdStatus:                          "",
			statusConnectedRE:                  "",
			statusDisconnectedRE:               "",
			cmdEnableSplitTun:                  []string{},
			cmdAddOurBinaryToSplitTunWhitelist: []string{},
			cmdConnect:                         "--connect",
			cmdDisconnect:                      "--disconnect",
		},
	}

	// index (DB) of other VPNs by sublayer key
	otherVpnsBySublayerGUID = map[syscall.GUID]*OtherVpnInfo{
		mullvadSublayerKey: &mullvadProfile,
		nordVpnSublayerKey: &nordVpnProfile,
	}
)
