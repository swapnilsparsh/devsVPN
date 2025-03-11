// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package vpncoexistence

var (
	// NordVPN
	nordVpnInterfaceName = "nordlynx"
	nordVpnProfile       = OtherVpnInfo{
		name:       "NordVPN",
		namePrefix: "nord",
		cliPath:    "nordvpn", // hopefully it's in path
		cliCmds: otherVpnCliCmds{
			cmdAddAllowlistOption: []string{"allowlist", "add"},
		},
	}

	// index (DB) of other VPNs by their network interface names
	otherVpnsByInterfaceName = map[string]*OtherVpnInfo{
		nordVpnInterfaceName: &nordVpnProfile,
	}
)

func OtherVpnByInterfaceName(otherVpnInterfaceName string) (otherVpn *OtherVpnInfo) {
	_otherVpn, ok := otherVpnsByInterfaceName[otherVpnInterfaceName]
	if ok {
		return _otherVpn
	} else {
		return nil
	}
}
