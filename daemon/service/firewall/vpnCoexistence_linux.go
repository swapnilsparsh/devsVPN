// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kocmo/go-xtables/iptables"
	"github.com/kocmo/go-xtables/pkg/network"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
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
	// !!! don't grab other mutexes in vpnCoexistence*.go files, or at least be mindful of potential deadlocks !!!
	vpnCoexistenceLinuxMutex sync.Mutex // lock for Linux VPN coexistence functions called from firewall_linux.
	// An additional mutex for disable tasks - it's exported, because launcher will wait for it on daemon shutdown, to ensure that disable steps finished before daemon exits.
	DisableCoexistenceWithOtherVpnsMutex sync.Mutex

	// Index (DB) of other VPNs by name, must be initialized in init() to avoid initialization cycles.
	otherVpnsByName = map[string]*OtherVpnInfo{}

	// NordVPN
	nordVpnInterfaceName = "nordlynx"
	nordVpnProfile       = OtherVpnInfo{
		name:              "NordVPN",
		namePrefix:        "nord",
		recommendedOurMTU: 1340,

		changesNftables: true,

		cli: "nordvpn", // will be checked whether it's in PATH
		cliCmds: otherVpnCliCmds{
			cmdAddAllowlistOption:    []string{"allowlist", "add", "subnet"},
			cmdRemoveAllowlistOption: []string{"allowlist", "remove", "subnet"},
		},
	}

	// SurfShark
	surfsharkInterfaceNameWg  = "surfshark_wg"  // when it uses Wireguard
	surfsharkInterfaceNameTun = "surfshark_tun" // when it uses OpenVPN, TCP or UDP
	surfsharkProfile          = OtherVpnInfo{
		name:                  "Surfshark",
		namePrefix:            "surfshark",
		changesIptablesLegacy: true,
		iptablesLegacyChain:   "SSKS_OUTPUT", // iptables-legacy chain used by Surfshark killswitch
		iptablesLegacyHelper:  surfsharkLegacyHelper,
		recommendedOurMTU:     1290,
	}

	// ExpressVPN. It always has interface name "tun0", it's non-descriptive, so not indexing it by interface name.
	expressVpnProfile = OtherVpnInfo{
		name:       "ExpressVPN",
		namePrefix: "expressvpn",
		//recommendedOurMTU:     1380,

		changesNftables: true,
		nftablesChain:   "evpn.OUTPUT",
		nftablesHelper:  expressVpnNftablesHelper,

		cli: "expressvpnctl", // will be checked whether it's in PATH
		cliCmds: otherVpnCliCmds{
			cmdEnableSplitTun:                       []string{"set", "splittunnel", "true"},
			cmdAddOurBinaryToSplitTunWhitelist:      []string{"set", "split-app"},
			cmdSplitTunnelOurBinaryPathPrefixAdd:    "bypass:",
			cmdSplitTunnelOurBinaryPathPrefixRemove: "remove:", // TODO: unused for now

			// TODO: flesh out as needed
			// cmdStatus: "???",
			// statusConnectedRE: "",
			// statusDisconnectedRE: "",
		},
	}

	// Index (DB) of other VPNs by their network interface names
	otherVpnsByInterfaceName = map[string]*OtherVpnInfo{
		nordVpnInterfaceName:      &nordVpnProfile,
		surfsharkInterfaceNameWg:  &surfsharkProfile,
		surfsharkInterfaceNameTun: &surfsharkProfile,
	}

	// Index (DB) of other VPNs by their CLI command (for those that have a useful CLI)
	otherVpnsByCLI = map[string]*OtherVpnInfo{
		nordVpnProfile.cli:    &nordVpnProfile,
		expressVpnProfile.cli: &expressVpnProfile,
	}

	// Index (DB) of other VPNs by the name of their nftables chain in the table filter (for those that have one)
	otherVpnsByNftablesFilterChain = map[string]*OtherVpnInfo{
		expressVpnProfile.nftablesChain: &expressVpnProfile,
	}

	// Index (DB) of other VPNs by the name of their iptables-legacy chain (for those that have one)
	otherVpnsByLegacyChain = map[string]*OtherVpnInfo{
		surfsharkProfile.iptablesLegacyChain: &surfsharkProfile,
	}

	// Sets of names of other VPNs detected, and whether they change nftables and/or iptables-legacy
	OtherVpnsDetectedRelevantForNftables       mapset.Set[string] = mapset.NewSet[string]()
	OtherVpnsDetectedRelevantForIptablesLegacy mapset.Set[string] = mapset.NewSet[string]()

	// lowest recommended MTU for our Wireguard - adjusted every time other VPNs are detected
	lowestRecommendedMTU = platform.WGDefaultMTU()

	// Index (DB) of other VPNs for which we enabled VPN-specific coexistence steps.
	// We'll need to disable these steps in DisableCoexistenceWithOtherVpns.
	// Maps from other VPN name to the list of commands to run on wrap-up
	otherVpnsToUndo = map[string]*otherVpnCommandsToUndoMap{}
)

func init() {
	// Index (DB) of other VPNs by name, must be initialized in init() to avoid initialization cycles.
	otherVpnsByName[nordVpnProfile.name] = &nordVpnProfile
	otherVpnsByName[surfsharkProfile.name] = &surfsharkProfile
	otherVpnsByName[expressVpnProfile.name] = &expressVpnProfile
}

// func OtherVpnByInterfaceName(otherVpnInterfaceName string) (otherVpn *OtherVpnInfo) {
// 	_otherVpn, ok := otherVpnsByInterfaceName[otherVpnInterfaceName]
// 	if ok {
// 		return _otherVpn
// 	} else {
// 		return nil
// 	}
// }

// ---------------- per-VPN helpers for iptables-legacy ----------------

func surfsharkLegacyHelper() (err error) {
	log.Debug("surfsharkLegacyHelper entered")
	defer log.Debug("surfsharkLegacyHelper exited")

	prefs := getPrefsCallback()

	// we know our chains already exist, create their objects
	vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	vpnCoexLegacyOut := filterLegacy.Chain(vpnCoexLegacyOutDef)

	// allow all DNS
	// TODO FIXME: allow only until login (SessionNew) is done
	if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error add all DNS dst UDP port 53: %w", err)
	}
	if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolTCP).MatchTCP(iptables.WithMatchTCPDstPort(false, 53)).TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error add all DNS dst TCP port 53: %w", err)
	}
	if err = vpnCoexLegacyIn.MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPSrcPort(false, 53)).TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error add all DNS src UDP port 53: %w", err)
	}

	// try marking our outbound packets w/ mark 0x493e0, as SSKS_ALLOW_WG (used only for outbound) allows them
	surfsharkMark := 0x493e0

	// - allow outbound packets by our binaries (to allow login to deskapi)
	matchOurCgroup := iptables.WithMatchCGroupClassID(false, PL_CGROUP_ID)
	if err = vpnCoexLegacyOut.MatchCGroup(matchOurCgroup).TargetMark(iptables.WithTargetMarkSet(surfsharkMark)).Insert(); err != nil {
		return log.ErrorFE("error matching our cgroup out - set mark 0x%x: %w", surfsharkMark, err)
	}

	//	- allow all outbound DNS packets
	if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetMark(iptables.WithTargetMarkSet(surfsharkMark)).Insert(); err != nil {
		return log.ErrorFE("error add all DNS dst UDP port 53 set mark 0x%x: %w", surfsharkMark, err)
	}
	if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolTCP).MatchTCP(iptables.WithMatchTCPDstPort(false, 53)).TargetMark(iptables.WithTargetMarkSet(surfsharkMark)).Insert(); err != nil {
		return log.ErrorFE("error add all DNS dst TCP port 53 set mark 0x%x: %w", surfsharkMark, err)
	}

	for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
		wgEndpointIP := strings.TrimSpace(vpnEntryHost.EndpointIP) // outbound packets to our Wireguard endpoints
		if err = vpnCoexLegacyOut.MatchDestination(false, wgEndpointIP).TargetMark(iptables.WithTargetMarkSet(surfsharkMark)).Insert(); err != nil {
			return log.ErrorFE("error out wgEndpointIP set mark 0x%x: %w", surfsharkMark, err)
		}

		for _, allowedIpCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // outbound packets to our allowedIPs (internal PL IPs)
			allowedIpCIDR = strings.TrimSpace(allowedIpCIDR) // allowedIPs, internal PL IP ranges ; CIDR format like "10.0.0.3/24"
			if err = vpnCoexLegacyOut.MatchDestination(false, allowedIpCIDR).TargetMark(iptables.WithTargetMarkSet(surfsharkMark)).Insert(); err != nil {
				return log.ErrorFE("error add out on allowed PL IP range %s - set mark 0x%x: %w", allowedIpCIDR, surfsharkMark, err)
			}
		}
	}

	return err
}

// ---------------- per-VPN helpers for nftables -----------------------

// Must call expressVpnNftablesHelper with &expressVpnProfile. This is to prevent initialization cycle.
func expressVpnNftablesHelper(otherVpnName string) (err error) {
	log.Debug("expressVpnNftablesHelper entered")
	defer log.Debug("expressVpnNftablesHelper exited")

	otherVpn, ok := otherVpnsByName[otherVpnName]
	if !ok {
		return log.ErrorFE("error looking up other VPN by it's name '%s'", otherVpnName)
	}

	// enable ExpressVPN split tunnel
	if retErr := shell.Exec(log, otherVpn.cliPathResolved, otherVpn.cliCmds.cmdEnableSplitTun...); retErr != nil {
		log.ErrorFE("error enabling Split Tunnel in other VPN '%s': %w", otherVpn.name, retErr) // and continue
	}

	// add our binaries to ExpressVPN split tunnel bypass list; TODO: implement removing them on uninstallation
	for _, svcExe := range platform.PLServiceBinariesForFirewallToUnblock() {
		cmdWhitelistOurSvcExe := append(otherVpn.cliCmds.cmdAddOurBinaryToSplitTunWhitelist, otherVpn.cliCmds.cmdSplitTunnelOurBinaryPathPrefixAdd+svcExe)
		if retErr := shell.Exec(log, otherVpn.cliPathResolved, cmdWhitelistOurSvcExe...); retErr != nil {
			log.ErrorFE("error adding '%s' to Split Tunnel in other VPN '%s': %w", svcExe, otherVpn.name, retErr) // and continue
		}
	}

	return nil
}

// ---------------------------------------------------------------------

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

// reDetectOtherVpnsLinux - re-detect the other VPNs present, and optionally adjust the current MTU accordingly
func reDetectOtherVpnsLinux(vpnCoexistenceLinuxMutexGrabbed, updateCurrentMTU bool) (err error) {
	if !vpnCoexistenceLinuxMutexGrabbed {
		vpnCoexistenceLinuxMutex.Lock()
		defer vpnCoexistenceLinuxMutex.Unlock()
	}

	log.Debug("reDetectOtherVpnsLinux entered")
	defer log.Debug("reDetectOtherVpnsLinux exited")

	OtherVpnsDetectedRelevantForNftables.Clear()
	OtherVpnsDetectedRelevantForIptablesLegacy.Clear()

	var (
		reDetectOtherVpnsWaiter          sync.WaitGroup
		defMtu                           = platform.WGDefaultMTU()
		newRecommendedMtuByNftablesChain = defMtu
		newRecommendedMtuByLegacyChain   = defMtu
		newRecommendedMtuByInterface     = defMtu
		newRecommendedMtuByCli           = defMtu
	)

	reDetectOtherVpnsWaiter.Add(4)

	go func() { // detect other VPNs by whether their nftables chain is present in table filter
		defer reDetectOtherVpnsWaiter.Done()

		if chains, err := nftConn.ListChainsOfTableFamily(TABLE_TYPE); err != nil {
			log.ErrorFE("error listing chains: %w", err)
			return
		} else {
			for _, chain := range chains {
				if otherVpn, ok := otherVpnsByNftablesFilterChain[chain.Name]; ok {
					log.Info("Other VPN '", otherVpn.name, "' detected by nftables chain: ", otherVpn.nftablesChain)
					if otherVpn.changesNftables {
						OtherVpnsDetectedRelevantForNftables.Add(otherVpn.name)
					}
					if otherVpn.changesIptablesLegacy {
						OtherVpnsDetectedRelevantForIptablesLegacy.Add(otherVpn.name)
					}
					if otherVpn.recommendedOurMTU != 0 && otherVpn.recommendedOurMTU < newRecommendedMtuByNftablesChain {
						newRecommendedMtuByNftablesChain = otherVpn.recommendedOurMTU
					}
				}
			}
		}
	}()

	go func() { // detect other VPNs by whether their iptables-legacy chain is present
		defer reDetectOtherVpnsWaiter.Done()
		if iptablesLegacyPresent() {
			for _, otherVpn := range otherVpnsByLegacyChain {
				userDefinedLegacyChain := iptables.ChainTypeUserDefined
				userDefinedLegacyChain.SetName(otherVpn.iptablesLegacyChain)
				if foundChains, err := filterLegacy.Chain(userDefinedLegacyChain).FindChains(); err == nil && len(foundChains) >= 1 {
					log.Info("Other VPN '", otherVpn.name, "' detected by iptables-legacy chain: ", otherVpn.iptablesLegacyChain)
					if otherVpn.changesNftables {
						OtherVpnsDetectedRelevantForNftables.Add(otherVpn.name)
					}
					if otherVpn.changesIptablesLegacy {
						OtherVpnsDetectedRelevantForIptablesLegacy.Add(otherVpn.name)
					}
					if otherVpn.recommendedOurMTU != 0 && otherVpn.recommendedOurMTU < newRecommendedMtuByLegacyChain {
						newRecommendedMtuByLegacyChain = otherVpn.recommendedOurMTU
					}
				}
			}
		}
	}()

	go func() { // detect other VPNs by network interface name
		defer reDetectOtherVpnsWaiter.Done()
		for otherVpnInterfaceName, otherVpn := range otherVpnsByInterfaceName {
			if _, err := netlink.LinkByName(otherVpnInterfaceName); err == nil {
				log.Info("Other VPN '", otherVpn.name, "' detected by interface name: ", otherVpnInterfaceName)
				if otherVpn.changesNftables {
					OtherVpnsDetectedRelevantForNftables.Add(otherVpn.name)
				}
				if otherVpn.changesIptablesLegacy {
					OtherVpnsDetectedRelevantForIptablesLegacy.Add(otherVpn.name)
				}
				if otherVpn.recommendedOurMTU != 0 && otherVpn.recommendedOurMTU < newRecommendedMtuByInterface {
					newRecommendedMtuByInterface = otherVpn.recommendedOurMTU
				}
			}
		}
	}()

	go func() { // detect other VPNs by whether their CLI is in PATH
		defer reDetectOtherVpnsWaiter.Done()
		for _, otherVpn := range otherVpnsByCLI {
			if otherVpnCliPath, err := exec.LookPath(otherVpn.cli); err != nil || otherVpnCliPath == "" {
				// log.Debug(fmt.Errorf("CLI '%s' expected to be in PATH for other VPN '%s', but not found in PATH, ignoring. err=%w", otherVpn.cli, otherVpn.name, err))
				otherVpn.cliPathResolved = ""
			} else {
				log.Info("Other VPN '", otherVpn.name, "' detected by CLI: ", otherVpnCliPath)
				otherVpn.cliPathResolved = otherVpnCliPath

				if otherVpn.changesNftables {
					OtherVpnsDetectedRelevantForNftables.Add(otherVpn.name)
				}
				if otherVpn.changesIptablesLegacy {
					OtherVpnsDetectedRelevantForIptablesLegacy.Add(otherVpn.name)
				}
				if otherVpn.recommendedOurMTU != 0 && otherVpn.recommendedOurMTU < newRecommendedMtuByCli {
					newRecommendedMtuByCli = otherVpn.recommendedOurMTU
				}
			}
		}
	}()

	var ourWgInterface netlink.Link
	var currMtu = 0
	if updateCurrentMTU && vpnConnectedOrConnectingCallback() { // if requested, update the current MTU on wgprivateline network interface
		if ourWgInterface, err = netlink.LinkByName(platform.WGInterfaceName()); err == nil {
			currMtu = ourWgInterface.Attrs().MTU
		} else {
			log.Debug(fmt.Errorf("error getting our Wireguard interface - perhaps it's not up at the moment. Not adjusting our current MTU. err=%w", err))
		}
	}

	reDetectOtherVpnsWaiter.Wait()
	lowestRecommendedMTU = min(newRecommendedMtuByCli, newRecommendedMtuByInterface, newRecommendedMtuByLegacyChain, newRecommendedMtuByNftablesChain)

	if updateCurrentMTU && currMtu != 0 { // if requested, update the current MTU on wgprivateline network interface
		if currMtu != lowestRecommendedMTU { // if we have to change our current MTU
			if err = netlink.LinkSetMTU(ourWgInterface, lowestRecommendedMTU); err != nil {
				return log.ErrorFE("error netlink.LinkSetMTU(%d): %w", lowestRecommendedMTU, err)
			}
		}
	}

	return nil
}

// implBestWireguardMtuForConditions - check for running other VPNs, detect the optimal MTU
func implBestWireguardMtuForConditions() (recommendedMTU int, retErr error) {
	vpnCoexistenceLinuxMutex.Lock()
	defer vpnCoexistenceLinuxMutex.Unlock()

	retErr = reDetectOtherVpnsLinux(true, false)
	return lowestRecommendedMTU, retErr
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
func enableVpnCoexistenceLinuxNft() (retErr error) {
	vpnCoexistenceLinuxMutex.Lock() // be mindful of possible deadlocks with other mutexes
	defer vpnCoexistenceLinuxMutex.Unlock()

	log.Debug("implEnableCoexistenceWithOtherVpns entered")
	defer log.Debug("implEnableCoexistenceWithOtherVpns exited")

	prefs := getPrefsCallback()

	retErr = reDetectOtherVpnsLinux(true, true) // re-detect other VPNs, and adjust our current MTU if needed

	// TODO: note that the detected VPNs that affect iptables-legacy are processed in doEnableLegacy()
	for otherVpnNftName := range OtherVpnsDetectedRelevantForNftables.Iterator().C {
		otherVpnNft, ok := otherVpnsByName[otherVpnNftName]
		if !ok {
			log.ErrorFE("error looking up detected other VPN '%s', skipping", otherVpnNftName)
			continue
		}

		if otherVpnNft.cliPathResolved != "" && len(otherVpnNft.cliCmds.cmdAddAllowlistOption) > 0 { // if we have an allowlist command for that VPN
			otherVpnCommandsToUndo := otherVpnCommandsToUndoMap{}
			for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
				// so far we only know NordVPN, so add our Wireguard gateways to the other VPN's allowlist

				plWgEntryHostIpCIDR := vpnEntryHost.EndpointIP + "/32" // add Wireguard endpoint IP to allowlist
				cmdAddOurWgEndpointToOtherVpnAllowlist := append(otherVpnNft.cliCmds.cmdAddAllowlistOption, plWgEntryHostIpCIDR)
				if err := tryCmdLogOnError(otherVpnNft.cliPathResolved, cmdAddOurWgEndpointToOtherVpnAllowlist...); err != nil {
					retErr = err
				}

				otherVpnFullArgs := append(otherVpnNft.cliCmds.cmdRemoveAllowlistOption, plWgEntryHostIpCIDR) // ... and add a removal command to the undo list
				otherVpnCommandsToUndo[plWgEntryHostIpCIDR] = &otherVpnUndoCompatCommand{cliPath: otherVpnNft.cliPathResolved, fullArgs: &otherVpnFullArgs}

				// TODO: Vlad - apparently private IP ranges not needed, only WG endpoint needed
				// // also add privateLINE private IP ranges to the other VPN's allowlist
				// for _, allowedIpRangeCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // CIDR format like "10.0.0.3/24"
				// 	allowedIpRangeCIDR = strings.TrimSpace(allowedIpRangeCIDR)
				// 	cmdAddPLAllowedIPsToOtherVpnAllowlist := append(otherVpn.cliCmds.cmdAddAllowlistOption, allowedIpRangeCIDR)
				// 	if err = tryCmdLogOnError(otherVpnNft.cliPathResolved, cmdAddPLAllowedIPsToOtherVpnAllowlist...); err != nil {
				// 		retErr = err
				// 	}

				// 	otherVpnFullArgs := append(otherVpn.cliCmds.cmdRemoveAllowlistOption, allowedIpRangeCIDR) // ... and add a removal command to the undo list
				// 	otherVpnCommandsToUndo[allowedIpRangeCIDR] = &otherVpnUndoCompatCommand{cliPath: otherVpnNft.cliPathResolved, fullArgs: &otherVpnFullArgs}

				// }

				otherVpnsToUndo[otherVpnNft.name] = &otherVpnCommandsToUndo // add this VPN to undo list
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
