// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package vpncoexistence

import (
	"os/exec"
	"strings"
	"sync"

	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"github.com/vishvananda/netlink"
)

var (
	vpnCoexistenceLinuxMutex sync.Mutex // lock for Linux VPN coexistence functions called from firewall_linux

	// NordVPN
	nordVpnInterfaceName = "nordlynx"
	nordVpnProfile       = OtherVpnInfo{
		name:       "NordVPN",
		namePrefix: "nord",
		cliPath:    "nordvpn", // hopefully it's in path
		cliCmds: otherVpnCliCmds{
			cmdAddAllowlistOption: []string{"allowlist", "add", "subnet"},
		},
	}

	// index (DB) of other VPNs by their network interface names
	OtherVpnsByInterfaceName = map[string]*OtherVpnInfo{
		nordVpnInterfaceName: &nordVpnProfile,
	}
)

func OtherVpnByInterfaceName(otherVpnInterfaceName string) (otherVpn *OtherVpnInfo) {
	_otherVpn, ok := OtherVpnsByInterfaceName[otherVpnInterfaceName]
	if ok {
		return _otherVpn
	} else {
		return nil
	}
}

func tryCmdLogOnError(binPath string, args ...string) {
	outText, outErrText, exitCode, isBufferTooSmall, err := shell.ExecAndGetOutput(nil, 1024*5, "", binPath, args...)
	if err != nil || exitCode != 0 {
		if strings.Contains(outText, "is already allowlisted") { // ignore some errors
			return
		}

		// trim trailing newlines
		outText = strings.TrimSuffix(outText, "\n")
		outErrText = strings.TrimSuffix(outErrText, "\n")

		log.ErrorFE("error executing command \"%s\" \"%s\". err=\"%w\", exitCode=%d, outText=\"%s\", outErrText=\"%s\", isBufferTooSmall=%t",
			binPath, args, err, exitCode, outText, outErrText, isBufferTooSmall)
	}
}

// Look for other VPNs by the network interface names we know for them, process steps for found ones
func EnableCoexistenceWithOtherVpns(prefs preferences.Preferences) (retErr error) {
	if !vpnCoexistenceLinuxMutex.TryLock() { // Best-effort attempt to launch. If another instance is already running - don't enqueue another one.
		return nil
	}
	defer vpnCoexistenceLinuxMutex.Unlock()

	log.Debug("EnableCoexistenceWithOtherVpns entered")
	defer log.Debug("EnableCoexistenceWithOtherVpns exited")

	for otherVpnInterface, otherVpn := range OtherVpnsByInterfaceName {
		_, err := netlink.LinkByName(otherVpnInterface)
		if err == nil { // if the network interface that is known to belong to another VPN
			// Check other VPN CLI is in PATH
			otherVpnResolvedCliPath, err := exec.LookPath(otherVpn.cliPath)
			if err != nil || otherVpnResolvedCliPath == "" {
				log.ErrorFE("network interface '%s' found for other VPN '%s', but its CLI '%s' not found in PATH, ignoring. err=%w", otherVpnInterface, otherVpn.name, otherVpn.cliPath, err)
				continue
			}

			log.Debug("Other VPN '" + otherVpn.name + "' found, configuring coexistence")

			for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
				// So far we only know NordVPN, so add our Wireguard gateways to the other VPN's allowlist
				plWgEntryHostIpCIDR := vpnEntryHost.EndpointIP + "/32"
				cmdAddOurWgEndpointToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, plWgEntryHostIpCIDR)
				tryCmdLogOnError(otherVpnResolvedCliPath, cmdAddOurWgEndpointToOtherVpnAllowlist...)

				// also add privateLINE private IP ranges to the other VPN's allowlist
				for _, allowedIpRangeCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // CIDR format like "10.0.0.3/24"
					allowedIpRangeCIDR = strings.TrimSpace(allowedIpRangeCIDR)
					cmdAddPLAllowedIPsToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, allowedIpRangeCIDR)
					tryCmdLogOnError(otherVpnResolvedCliPath, cmdAddPLAllowedIPsToOtherVpnAllowlist...)
				}
			}
		}
	}

	return retErr
}
