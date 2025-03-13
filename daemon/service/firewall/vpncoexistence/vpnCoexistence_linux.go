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

type otherVpnUndoCompatCommand struct { // used by DisableCoexistenceWithOtherVpns to run command like: "cliPath" < ... intermediate args ...> <finalArg>
	cliPath  string
	fullArgs *[]string // it includes the final arg, specific one like "155.130.218.74/32", at the end
}

// map from finalArg to the command prefix
type otherVpnCommandsToUndoMap map[string]*otherVpnUndoCompatCommand

var (
	vpnCoexistenceLinuxMutex sync.Mutex // lock for Linux VPN coexistence functions called from firewall_linux

	// NordVPN
	nordVpnInterfaceName = "nordlynx"
	nordVpnProfile       = OtherVpnInfo{
		name:       "NordVPN",
		namePrefix: "nord",
		cliPath:    "nordvpn", // hopefully it's in path
		cliCmds: otherVpnCliCmds{
			cmdAddAllowlistOption:    []string{"allowlist", "add", "subnet"},
			cmdRemoveAllowlistOption: []string{"allowlist", "remove", "subnet"},
		},
	}

	// Index (DB) of other VPNs by their network interface names.
	otherVpnsByInterfaceName = map[string]*OtherVpnInfo{
		nordVpnInterfaceName: &nordVpnProfile,
	}

	// Index (DB) of other VPNs for which we enabled VPN-specific coexistence steps.
	// We'll need to disable these steps in DisableCoexistenceWithOtherVpns.
	// Maps from other VPN name to the list of commands to run on wrap-up
	otherVpnsToUndo = map[string]*otherVpnCommandsToUndoMap{}
)

func OtherVpnByInterfaceName(otherVpnInterfaceName string) (otherVpn *OtherVpnInfo) {
	_otherVpn, ok := otherVpnsByInterfaceName[otherVpnInterfaceName]
	if ok {
		return _otherVpn
	} else {
		return nil
	}
}

func tryCmdLogOnError(binPath string, args ...string) (retErr error) {
	logtext := strings.Join(append([]string{binPath}, args...), " ")
	log.Info("Shell exec: ", logtext)

	outText, outErrText, exitCode, isBufferTooSmall, err := shell.ExecAndGetOutput(nil, 1024*5, "", binPath, args...)
	if err != nil || exitCode != 0 {
		// ignore some errors
		if len(args) >= 2 &&
			args[0] == nordVpnProfile.cliCmds.cmdAddAllowlistOption[0] &&
			args[1] == nordVpnProfile.cliCmds.cmdAddAllowlistOption[1] &&
			strings.Contains(outText, "is already allowlisted") {
			return nil
		}

		// trim trailing newlines
		outText = strings.TrimSuffix(outText, "\n")
		outErrText = strings.TrimSuffix(outErrText, "\n")

		return log.ErrorFE("error executing command \"%s\" \"%s\". err=\"%w\", exitCode=%d, isBufferTooSmall=%t\n%s\n%s",
			binPath, args, err, exitCode, isBufferTooSmall, outErrText, outText)
	}

	return nil
}

// Look for other VPNs by the network interface names we know for them, process steps for found ones
func EnableCoexistenceWithOtherVpns(prefs preferences.Preferences) (retErr error) {
	vpnCoexistenceLinuxMutex.Lock()
	defer vpnCoexistenceLinuxMutex.Unlock()

	log.Debug("EnableCoexistenceWithOtherVpns entered")
	defer log.Debug("EnableCoexistenceWithOtherVpns exited")

	for otherVpnInterface, otherVpn := range otherVpnsByInterfaceName {
		if _, err := netlink.LinkByName(otherVpnInterface); err == nil { // if the network interface that is known to belong to another VPN
			// Check other VPN CLI is in PATH
			otherVpnCliPath, err := exec.LookPath(otherVpn.cliPath)
			if err != nil || otherVpnCliPath == "" {
				retErr = log.ErrorFE("network interface '%s' found for other VPN '%s', but its CLI '%s' not found in PATH, ignoring. err=%w", otherVpnInterface, otherVpn.name, otherVpn.cliPath, err)
				continue
			}

			log.Debug("Other VPN '" + otherVpn.name + "' found, configuring coexistence")
			otherVpnCommandsToUndo := otherVpnCommandsToUndoMap{}

			for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
				// so far we only know NordVPN, so add our Wireguard gateways to the other VPN's allowlist

				plWgEntryHostIpCIDR := vpnEntryHost.EndpointIP + "/32" // add endpoint IP to allowlist
				cmdAddOurWgEndpointToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, plWgEntryHostIpCIDR)
				if err = tryCmdLogOnError(otherVpnCliPath, cmdAddOurWgEndpointToOtherVpnAllowlist...); err != nil {
					retErr = err
				}

				otherVpnFullArgs := append(otherVpn.cliCmds.cmdRemoveAllowlistOption, plWgEntryHostIpCIDR) // ... and add a removal command to the undo list
				otherVpnCommandsToUndo[plWgEntryHostIpCIDR] = &otherVpnUndoCompatCommand{cliPath: otherVpnCliPath, fullArgs: &otherVpnFullArgs}

				// also add privateLINE private IP ranges to the other VPN's allowlist
				for _, allowedIpRangeCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // CIDR format like "10.0.0.3/24"
					allowedIpRangeCIDR = strings.TrimSpace(allowedIpRangeCIDR)
					cmdAddPLAllowedIPsToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, allowedIpRangeCIDR)
					if err = tryCmdLogOnError(otherVpnCliPath, cmdAddPLAllowedIPsToOtherVpnAllowlist...); err != nil {
						retErr = err
					}

					otherVpnFullArgs := append(otherVpn.cliCmds.cmdRemoveAllowlistOption, allowedIpRangeCIDR) // ... and add a removal command to the undo list
					otherVpnCommandsToUndo[allowedIpRangeCIDR] = &otherVpnUndoCompatCommand{cliPath: otherVpnCliPath, fullArgs: &otherVpnFullArgs}

				}

				otherVpnsToUndo[otherVpn.name] = &otherVpnCommandsToUndo // add this VPN to undo list
			}
		}
	}

	return retErr
}

// Undo VPN compatibility steps per VPN.
// TODO: if customers will have multiple other VPNs up, consider processing them in parallel?
func DisableCoexistenceWithOtherVpns() (retErr error) {
	vpnCoexistenceLinuxMutex.Lock()
	defer vpnCoexistenceLinuxMutex.Unlock()

	log.Debug("DisableCoexistenceWithOtherVpns entered")
	defer log.Debug("DisableCoexistenceWithOtherVpns exited")

	for _, otherVpnCommands := range otherVpnsToUndo {
		for _, cmdInfo := range *otherVpnCommands {
			if err := tryCmdLogOnError(cmdInfo.cliPath, *cmdInfo.fullArgs...); err != nil {
				retErr = err
			}
		}
	}

	clear(otherVpnsToUndo)

	return retErr
}
