// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package vpncoexistence

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"github.com/vishvananda/netlink"
)

// We can detect these things about the other VPN(s):
//   - Its CLI is in PATH, that means it's present on the system
//		- We should add ourselves to the other VPN allowlist, exceptions list, etc.
//   - Its firewall object (i.e., a chain in iptables-legacy) exists, that means its killswitch may be active
//		- We should deploy our anti-killswitch measures
//   - Its tunnel network interface is up, that means the other VPN is likely connected/connecting
//		- We should deploy logic like low MTU and so
//
// TODO FIXME: Vlad - allow all DNS traffic from the point we start connecting till CONNECTED
//		- or maybe even for the whole time we're connecting/connected?

type otherVpnUndoCompatCommand struct { // used by DisableCoexistenceWithOtherVpns to run command like: "cliPath" < ... intermediate args ...> <finalArg>
	cliPath  string
	fullArgs *[]string // it includes the final arg, specific one like "155.130.218.74/32", at the end
}

// map from finalArg to the command prefix
type otherVpnCommandsToUndoMap map[string]*otherVpnUndoCompatCommand

var (
	vpnCoexistenceLinuxMutex sync.Mutex // lock for Linux VPN coexistence functions called from firewall_linux.
	// An additional mutex for disable tasks - it's exported, because launcher will wait for it on daemon shutdown, to ensure that disable steps finished before daemon exits.
	DisableCoexistenceWithOtherVpnsMutex sync.Mutex

	// NordVPN
	nordVpnInterfaceName = "nordlynx"
	nordVpnProfile       = OtherVpnInfo{
		name:       "NordVPN",
		namePrefix: "nord",
		hasCLI:     true,
		cliPath:    "nordvpn", // hopefully it's in path
		ourMTU:     1340,
		cliCmds: otherVpnCliCmds{
			cmdAddAllowlistOption:    []string{"allowlist", "add", "subnet"},
			cmdRemoveAllowlistOption: []string{"allowlist", "remove", "subnet"},
		},
	}

	// SurfShark
	surfsharkInterfaceNameWg  = "surfshark_wg"  // when it uses Wireguard
	surfsharkInterfaceNameTun = "surfshark_tun" // when it uses OpenVPN, TCP or UDP
	surfsharkProfile          = OtherVpnInfo{
		name:                     "Surfshark",
		namePrefix:               "surfshark",
		hasCLI:                   false,
		ourMTU:                   1290,
		needsResolvectlDnsConfig: true,
	}

	// Index (DB) of other VPNs by their network interface names.
	otherVpnsByInterfaceName = map[string]*OtherVpnInfo{
		nordVpnInterfaceName:      &nordVpnProfile,
		surfsharkInterfaceNameWg:  &surfsharkProfile,
		surfsharkInterfaceNameTun: &surfsharkProfile,
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

func implBestWireguardMtuForConditions() int { // check for running other VPNs, and adjust the MTU accordingly
	lowestMtu := platform.WGDefaultMTU()
	for otherVpnInterfaceName, otherVpn := range otherVpnsByInterfaceName {
		if _, err := netlink.LinkByName(otherVpnInterfaceName); err == nil { // if the network interface, that's known to belong to another VPN, is up
			if otherVpn.ourMTU < lowestMtu {
				lowestMtu = otherVpn.ourMTU
			}
		}
	}
	return lowestMtu
}

// func postConnectionResolvectlDnsConfig(prefs preferences.Preferences) (retErr error) {
// 	if !platform.ResolvectlDetected() {
// 		return nil
// 	}

// 	// Per comment #9: https://bugs.launchpad.net/ubuntu/+source/wireguard/+bug/1992491/comments/9

// 	// resolvectl dns %i <ip1> <ip2> ...
// 	resolvectlDnsCmdArgs := []string{"dns", "wgprivateline"}
// 	for _, vpnEntryHost := range prefs.VpnEntryHostsParsed {
// 		for _, dnsSrv := range vpnEntryHost.DnsServersIPv4 {
// 			resolvectlDnsCmdArgs = append(resolvectlDnsCmdArgs, dnsSrv.String())
// 		}
// 	}
// 	if err := tryCmdLogOnError(platform.ResolvectlBinPath(), resolvectlDnsCmdArgs...); err != nil {
// 		retErr = err
// 	}

// 	// resolvectl domain %i \~domain1 \~domain2 ...
// 	if err := tryCmdLogOnError(platform.ResolvectlBinPath(), helpers.ResolvectlDomainCmdArgs...); err != nil {
// 		retErr = err
// 	}

// 	return retErr
// }

// Look for other VPNs by the network interface names we know for them, process steps for found ones
func implEnableCoexistenceWithOtherVpns(prefs preferences.Preferences, vpnConnectedOrConnectingCallback types.VpnConnectedCallback) (retErr error) {
	vpnCoexistenceLinuxMutex.Lock()
	defer vpnCoexistenceLinuxMutex.Unlock()

	log.Debug("EnableCoexistenceWithOtherVpns entered")
	defer log.Debug("EnableCoexistenceWithOtherVpns exited")

	var err error
	ourWgInterfacePresent := false
	var ourWgInterface netlink.Link
	currMtu := 0
	newMtu := platform.WGDefaultMTU()
	if vpnConnectedOrConnectingCallback() {
		if ourWgInterface, err = netlink.LinkByName(platform.WGInterfaceName()); err != nil {
			log.Debug(fmt.Errorf("error getting our Wireguard interface - perhaps it's not up yet. Skipping MTU logic. err=%w", err))
		} else {
			ourWgInterfacePresent = true
			currMtu = ourWgInterface.Attrs().MTU
		}
	}

	for otherVpnInterfaceName, otherVpn := range otherVpnsByInterfaceName {
		if _, err := netlink.LinkByName(otherVpnInterfaceName); err == nil { // if the network interface, that is known to belong to another VPN, is up
			// If another VPN has CLI - check that it's in PATH
			otherVpnCliPath := ""
			// needsResolvectlDnsConfig
			if otherVpn.hasCLI {
				otherVpnCliPath, err = exec.LookPath(otherVpn.cliPath)
				if err != nil || otherVpnCliPath == "" {
					retErr = log.ErrorFE("network interface '%s' found for other VPN '%s', but its CLI '%s' not found in PATH, ignoring. err=%w", otherVpnInterfaceName, otherVpn.name, otherVpn.cliPath, err)
				}
			}

			log.Debug("Other VPN '" + otherVpn.name + "' found, configuring coexistence")

			if ourWgInterfacePresent && otherVpn.ourMTU < newMtu { // determine the lowest MTU we have to apply
				newMtu = otherVpn.ourMTU
			}

			otherVpnCommandsToUndo := otherVpnCommandsToUndoMap{}

			if otherVpnCliPath != "" && len(otherVpn.cliCmds.cmdAddAllowlistOption) > 0 { // if we have an allowlist command for that VPN
				for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
					// so far we only know NordVPN, so add our Wireguard gateways to the other VPN's allowlist

					plWgEntryHostIpCIDR := vpnEntryHost.EndpointIP + "/32" // add Wireguard endpoint IP to allowlist
					cmdAddOurWgEndpointToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, plWgEntryHostIpCIDR)
					if err = tryCmdLogOnError(otherVpnCliPath, cmdAddOurWgEndpointToOtherVpnAllowlist...); err != nil {
						retErr = err
					}

					otherVpnFullArgs := append(otherVpn.cliCmds.cmdRemoveAllowlistOption, plWgEntryHostIpCIDR) // ... and add a removal command to the undo list
					otherVpnCommandsToUndo[plWgEntryHostIpCIDR] = &otherVpnUndoCompatCommand{cliPath: otherVpnCliPath, fullArgs: &otherVpnFullArgs}

					// TODO: Vlad - apparently private IP ranges not needed, only WG endpoint needed
					// // also add privateLINE private IP ranges to the other VPN's allowlist
					// for _, allowedIpRangeCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // CIDR format like "10.0.0.3/24"
					// 	allowedIpRangeCIDR = strings.TrimSpace(allowedIpRangeCIDR)
					// 	cmdAddPLAllowedIPsToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, allowedIpRangeCIDR)
					// 	if err = tryCmdLogOnError(otherVpnCliPath, cmdAddPLAllowedIPsToOtherVpnAllowlist...); err != nil {
					// 		retErr = err
					// 	}

					// 	otherVpnFullArgs := append(otherVpn.cliCmds.cmdRemoveAllowlistOption, allowedIpRangeCIDR) // ... and add a removal command to the undo list
					// 	otherVpnCommandsToUndo[allowedIpRangeCIDR] = &otherVpnUndoCompatCommand{cliPath: otherVpnCliPath, fullArgs: &otherVpnFullArgs}

					// }

					otherVpnsToUndo[otherVpn.name] = &otherVpnCommandsToUndo // add this VPN to undo list
				}
			}
		}
	}

	if ourWgInterfacePresent && newMtu != currMtu && vpnConnectedOrConnectingCallback() { // if we have to change our MTU and our VPN is still up
		if err = netlink.LinkSetMTU(ourWgInterface, newMtu); err != nil {
			return log.ErrorFE("erorr netlink.LinkSetMTU(%d): %w", newMtu, err)
		}
	}

	return retErr
}

// Undo VPN compatibility steps per VPN.
// TODO: if customers will have multiple other VPNs up, consider processing them in parallel?
func DisableCoexistenceWithOtherVpns() (retErr error) {
	vpnCoexistenceLinuxMutex.Lock()
	defer vpnCoexistenceLinuxMutex.Unlock()

	DisableCoexistenceWithOtherVpnsMutex.Lock() // launcher waits for this mutex on daemon shutdown, to ensure all disable tasks have been completed
	defer DisableCoexistenceWithOtherVpnsMutex.Unlock()

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
