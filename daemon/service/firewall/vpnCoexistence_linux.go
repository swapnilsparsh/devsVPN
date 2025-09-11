// TODO: FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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
// TODO: FIXME: Vlad - allow all DNS traffic from the point we start connecting till CONNECTED
//		- or maybe even for the whole time we're connecting/connected?

type otherVpnUndoCompatCommand struct { // used by DisableCoexistenceWithOtherVpns to run command like: "cliPath" < ... intermediate args ...> <finalArg>
	cliPath  string
	fullArgs *[]string // it includes the final arg, specific one like "155.130.218.74/32", at the end
}

// map from finalArg to the command prefix
type otherVpnCommandsToUndoMap map[string]*otherVpnUndoCompatCommand

var (
	// !!! don't grab other mutexes in vpnCoexistence*.go files, or at least be mindful of potential deadlocks !!!

	// Sets of names of other VPNs detected, and whether they change nftables and/or iptables-legacy

	// !!! to avoid deadlocks, always acquire the mutexes in the same order:
	//	otherVpnsNftMutex 1st
	//	otherVpnsLegacyMutex 2nd
	//	DisableCoexistenceWithOtherVpnsMutex 3rd
	OtherVpnsDetectedReconfigurableViaCli      mapset.Set[string] = mapset.NewSet[string]() // those other VPNs, which we need to reconfigure via their CLI
	otherVpnsCliMutex                          sync.Mutex                                   // used to protect OtherVpnsDetectedReconfigurableViaCli
	OtherVpnsDetectedRelevantForNftables       mapset.Set[string] = mapset.NewSet[string]()
	otherVpnsNftMutex                          sync.Mutex         // used to protect OtherVpnsDetectedRelevantForNftables
	OtherVpnsDetectedRelevantForIptablesLegacy mapset.Set[string] = mapset.NewSet[string]()
	otherVpnsLegacyMutex                       sync.Mutex         // used to protect OtherVpnsDetectedRelevantForIptablesLegacy

	// An additional mutex for disable tasks - it's exported, because launcher will wait for it on daemon shutdown, to ensure that disable steps finished before daemon exits.
	DisableCoexistenceWithOtherVpnsMutex sync.Mutex

	// lowest recommended MTU for our Wireguard - adjusted every time other VPNs are detected
	lowestRecommendedMTU = platform.WGDefaultMTU()

	// NordVPN. Apparently it doesn't create any custom firewall chains.
	nordVpnInterfaceName = "nordlynx"
	nordVpnProfile       = OtherVpnInfo{
		name:              "NordVPN",
		namePrefix:        "nord",
		recommendedOurMTU: 1340,

		networkInterfaceNames: []string{nordVpnInterfaceName},

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
		name:                                 "Surfshark",
		namePrefix:                           "surfshark",
		recommendedOurMTU:                    1290,
		incompatWithTotalShieldWhenConnected: true,

		networkInterfaceNames: []string{surfsharkInterfaceNameWg, surfsharkInterfaceNameTun},

		changesIptablesLegacy: true,
		iptablesLegacyChain:   "SSKS_OUTPUT", // iptables-legacy chain used by Surfshark killswitch
		iptablesLegacyHelper:  surfsharkLegacyHelper,

		cli: "surfshark", // will be checked whether it's in PATH
	}

	// ExpressVPN
	expressVpnName = "ExpressVPN"
	//expressVpnInterfaceNameTun = "tun0" // It always has interface name "tun0", it's too generic, so not indexing it by this interface name.
	expressVpnProfile = OtherVpnInfo{
		name:       expressVpnName,
		namePrefix: "expressvpn",
		//recommendedOurMTU:     1380,
		incompatWithTotalShieldWhenConnected: true, // but we're not including its interface name, tun0, so Total Shield won't get disabled automatically

		changesNftables:               true,
		nftablesChain:                 "evpn.OUTPUT",
		nftablesChainNamePrefix:       "evpn.", // nft monitor watches for new rules in chains with names starting with that prefix - that may signify ExpressVPN is connecting
		nftablesChainNameExclusionsRE: regexp.MustCompile(`evpn\..*\.allowLAN`),
		nftablesHelper:                expressVpnNftablesHelper,

		cli: "expressvpnctl", // will be checked whether it's in PATH
		cliCmds: otherVpnCliCmds{
			cmdStatus:               "status",
			checkCliConnectedStatus: true,
			statusConnectedRE:       commonStatusConnectedRE, // must be 1st line
			statusDisconnectedRE:    commonStatusDisconnectedRE,

			cmdEnableSplitTun:                       []string{"set", "splittunnel", "true"},
			cmdAddOurBinaryPathToSplitTunWhitelist:  []string{"set", "split-app"},
			cmdSplitTunnelOurBinaryPathPrefixAdd:    "bypass:",
			cmdSplitTunnelOurBinaryPathPrefixRemove: "remove:", // TODO: unused for now

			cmdAllowLan: []string{"set", "allowlan", "true"},
		},
	}

	// Mullvad
	mullvadName = "Mullvad"
	// TODO: merge Windows and Linux Mullvad profiles?
	mullvadInterfaceNameWg = "wg0-mullvad" // When it uses Wireguard
	//mullvadInterfaceNameTun = "tun0"        // When it uses OpenVPN, TCP or UDP. Interface name "tun0" is too generic, so not indexing it by this interface name.
	mullvadProfile = OtherVpnInfo{
		name:                                 mullvadName,
		namePrefix:                           "mullvad",
		recommendedOurMTU:                    1200, // = 1280 (safe Mullvad setting) - 80 (Wireguard IPv6 header overhead)
		incompatWithTotalShieldWhenConnected: true,

		networkInterfaceNames: []string{mullvadInterfaceNameWg},

		changesNftables: true,
		nftablesHelper:  mullvadNftablesHelper,

		cli: "mullvad", // will be checked whether it's in PATH
		cliCmds: otherVpnCliCmds{
			cmdStatus:               "status",
			checkCliConnectedStatus: true,
			statusConnectedRE:       commonStatusConnectedRE, // must be 1st line
			statusDisconnectedRE:    commonStatusDisconnectedRE,

			cmdAddOurBinaryPidToSplitTunWhitelist:      []string{"split-tunnel", "add"},
			cmdDeleteOurBinaryPidFromSplitTunWhitelist: []string{"split-tunnel", "delete"},

			cmdAllowLan: []string{"lan", "set", "allow"},
		},
	}

	// Index (DB) of other VPNs by their network interface names
	otherVpnsByInterfaceName = map[string]*OtherVpnInfo{
		nordVpnInterfaceName:      &nordVpnProfile,
		surfsharkInterfaceNameWg:  &surfsharkProfile,
		surfsharkInterfaceNameTun: &surfsharkProfile,
		mullvadInterfaceNameWg:    &mullvadProfile,
	}

	// Index (DB) of other VPNs by their CLI command (to detect them by CLI present in PATH)
	otherVpnsByCLI = map[string]*OtherVpnInfo{
		nordVpnProfile.cli:    &nordVpnProfile,
		expressVpnProfile.cli: &expressVpnProfile,
		surfsharkProfile.cli:  &surfsharkProfile,
		mullvadProfile.cli:    &mullvadProfile,
	}

	// Index (DB) of other VPNs by the name of their nftables chain in the table filter (for those that have one)
	otherVpnsByNftablesFilterChain = map[string]*OtherVpnInfo{
		expressVpnProfile.nftablesChain: &expressVpnProfile,
	}

	// Index (DB) of other VPNs by the name of their iptables-legacy chain (for those that have one)
	otherVpnsByLegacyChain = map[string]*OtherVpnInfo{
		surfsharkProfile.iptablesLegacyChain: &surfsharkProfile,
	}

	// Index (DB) of other VPNs for which we enabled VPN-specific coexistence steps.
	// We'll need to disable these steps in DisableCoexistenceWithOtherVpns.
	// Maps from other VPN name to the list of commands to run on wrap-up
	otherVpnsToUndo = map[string]*otherVpnCommandsToUndoMap{}
)

func init() {
	knownOtherVpnProfiles = []*OtherVpnInfo{&nordVpnProfile, &surfsharkProfile, &expressVpnProfile, &mullvadProfile}

	// Index (DB) of other VPNs by name, must be initialized in init() to avoid initialization cycles
	for _, otherVpn := range knownOtherVpnProfiles {
		otherVpnsByName[otherVpn.name] = otherVpn
	}
}

// ---------------- per-VPN helpers for iptables-legacy ----------------
// By the time the per-VPN helpers for iptables-legacy get called, our chains must already exist. So these helpers are called at the end of doEnableLegacy().

func surfsharkLegacyHelper(_ bool) (err error) {
	// if !iptablesLegacyWasInitialized.Load() {
	// 	return nil
	// }

	log.Debug("surfsharkLegacyHelper entered")
	defer log.Debug("surfsharkLegacyHelper exited")

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	prefs := getPrefsCallback()

	// we know our chains already exist, create their objects
	// vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	vpnCoexLegacyOut := filterLegacy.Chain(vpnCoexLegacyOutDef)

	// // allow all DNS - applying it generally in doEnableLegacy() for now
	// // TODO: allow only until login (SessionNew) is done
	// if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetAccept().Insert(); err != nil {
	// 	return log.ErrorFE("error add all DNS dst UDP port 53: %w", err)
	// }
	// if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolTCP).MatchTCP(iptables.WithMatchTCPDstPort(false, 53)).TargetAccept().Insert(); err != nil {
	// 	return log.ErrorFE("error add all DNS dst TCP port 53: %w", err)
	// }
	// if err = vpnCoexLegacyIn.MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPSrcPort(false, 53)).TargetAccept().Insert(); err != nil {
	// 	return log.ErrorFE("error add all DNS src UDP port 53: %w", err)
	// }

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

// commonNftablesHelper - logic common to all nftables helpers. Can be run in parallel with VPN-specific helpers.
func commonNftablesHelper(otherVpnName string, canReconfigureOtherVpn bool) (err error) { // logic common to all nftables helpers
	log.Debug("commonNftablesHelper entered for VPN: ", otherVpnName)
	defer log.Debug("commonNftablesHelper exited for VPN: ", otherVpnName)

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	otherVpn, ok := otherVpnsByName[otherVpnName]
	if !ok {
		return log.ErrorFE("error looking up other VPN by its name '%s'", otherVpnName)
	}

	canReconfigureOtherVpn = canReconfigureOtherVpn || getPrefsCallback().PermissionReconfigureOtherVPNs

	// if the VPN has allow-LAN command registered, run it
	if canReconfigureOtherVpn && len(otherVpn.cliCmds.cmdAllowLan) > 0 {
		if err = shell.Exec(log, otherVpn.cliPathResolved, otherVpn.cliCmds.cmdAllowLan...); err != nil {
			err = log.ErrorFE("error enabling LAN (local area network access) in other VPN '%s': %w", otherVpnName, err) // and continue
		}
	}

	// if Total Shield is enabled, and another VPN is connected/connecting that is incompatible with Total Shield - disable it
	if otherVpn.incompatWithTotalShieldWhenConnected && getPrefsCallback().IsTotalShieldOn {
		if otherVpnConnected, err := otherVpn.CheckVpnConnectedConnecting(); err != nil {
			return log.ErrorFE("error otherVpn.CheckVpnConnected(): %w", err)
		} else if otherVpnConnected {
			log.Warning("When other VPN '", otherVpn.name, "' is connected - Total Shield cannot be enabled in PL Connect. Disabling Total Shield.")
			go disableTotalShieldAsyncCallback() // need to fork into the background, so that firewall.TotalShieldApply() can wait for all the mutexes
		}
	}

	return err
}

// ExpressVPN has a dedicated helper, because it needs to append prefixes to our binary paths
func expressVpnNftablesHelper(canReconfigureOtherVpn bool) (err error) {
	if !(canReconfigureOtherVpn || getPrefsCallback().PermissionReconfigureOtherVPNs) {
		return nil
	}

	log.Debug("expressVpnNftablesHelper entered")
	defer log.Debug("expressVpnNftablesHelper exited")

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	expressVpn, ok := otherVpnsByName[expressVpnName]
	if !ok {
		return log.ErrorFE("error looking up other VPN by its name '%s'", expressVpnName)
	}

	var expressVpnCli string
	if expressVpn.cliPathResolved != "" {
		expressVpnCli = expressVpn.cliPathResolved
	} else {
		expressVpnCli = expressVpn.cli
	}

	// enable ExpressVPN split tunnel
	if retErr := shell.Exec(log, expressVpnCli, expressVpn.cliCmds.cmdEnableSplitTun...); retErr != nil {
		log.ErrorFE("error enabling Split Tunnel in other VPN '%s': %w", expressVpn.name, retErr) // and continue
	}

	// add our binaries to ExpressVPN split tunnel bypass list; TODO: implement removing them on uninstallation
	for _, svcExe := range platform.PLServiceBinariesForFirewallToUnblock() {
		cmdWhitelistOurSvcExe := append(expressVpn.cliCmds.cmdAddOurBinaryPathToSplitTunWhitelist, expressVpn.cliCmds.cmdSplitTunnelOurBinaryPathPrefixAdd+svcExe)
		if retErr := shell.Exec(log, expressVpnCli, cmdWhitelistOurSvcExe...); retErr != nil {
			log.ErrorFE("error adding '%s' to Split Tunnel in other VPN '%s': %w", svcExe, expressVpn.name, retErr) // and continue
		}
	}

	return nil
}

// mullvadNftablesHelper is a dedicated helper for Mullvad
func mullvadNftablesHelper(canReconfigureOtherVpn bool) (err error) {
	if !(canReconfigureOtherVpn || getPrefsCallback().PermissionReconfigureOtherVPNs) {
		return nil
	}

	log.Debug("mullvadVpnNftablesHelper entered")
	defer log.Debug("mullvadNftablesHelper exited")

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	mullvad, ok := otherVpnsByName[mullvadName]
	if !ok {
		return log.ErrorFE("error looking up other VPN by its name '%s'", mullvadName)
	}

	var mullvadCli string
	if mullvad.cliPathResolved != "" {
		mullvadCli = mullvad.cliPathResolved
	} else {
		mullvadCli = mullvad.cli
	}

	otherVpnCommandsToUndo := otherVpnCommandsToUndoMap{}

	// If PL is CONNECTED, then configure Mullvad to use our DNS servers. Run dns command early - so that DNS starts working sooner after VPN is CONNECTED.
	// mullvad dns set custom 10.0.19.2 10.0.20.2
	mullvadDnsSetDefault := []string{"dns", "set", "default"}
	if vpnConnectedCallback() {
		prefs := getPrefsCallback()
		mullvadDnsSetCustomCmd := []string{"dns", "set", "custom"}
		for plDnsSrv := range prefs.AllDnsServersIPv4Set.Iterator().C {
			mullvadDnsSetCustomCmd = append(mullvadDnsSetCustomCmd, plDnsSrv)
		}
		if retErr := shell.Exec(log, mullvadCli, mullvadDnsSetCustomCmd...); retErr != nil {
			log.ErrorFE("error adding privateLINE DNS servers as custom servers to other VPN '%s': %w", mullvad.name, retErr) // and continue
		} else { // and, if successful - queue to run on disabling VPN coex:	mullvad dns set default
			otherVpnCommandsToUndo["mullvadDnsSetDefault"] = &otherVpnUndoCompatCommand{cliPath: mullvadCli, fullArgs: &mullvadDnsSetDefault}
		}
	} else { // in case we had leftover custom DNS config at Mullvad - reset their DNS to defaults
		if retErr := shell.Exec(log, mullvadCli, mullvadDnsSetDefault...); retErr != nil {
			log.ErrorFE("error resetting the other VPN '%s' DNS settings to defaults: %w", mullvad.name, retErr) // and continue
		}
	}

	// mullvad lockdown-mode set off
	if retErr := shell.Exec(log, mullvadCli, []string{"lockdown-mode", "set", "off"}...); retErr != nil {
		log.ErrorFE("error disabling lockdown in other VPN '%s': %w", mullvad.name, retErr) // and continue
	}

	// add our daemon PID to Mullvad split tunnel PID whitelist:	mullvad split-tunnel add <pid>
	daemonPid := strconv.Itoa(os.Getpid())
	cmdWhitelistOurDaemonPid := append(mullvad.cliCmds.cmdAddOurBinaryPidToSplitTunWhitelist, daemonPid)
	if retErr := shell.Exec(log, mullvadCli, cmdWhitelistOurDaemonPid...); retErr != nil {
		log.ErrorFE("error adding privateline-connect-svc PID '%s' to Split Tunnel PID whitelist in other VPN '%s': %w", daemonPid, mullvad.name, retErr) // and continue
	} else { // if successful - queue inverse command, to remove our PID from the whitelist when disabling our VPN coexistence logic
		mullvadRemoveDaemonPid := append(mullvad.cliCmds.cmdDeleteOurBinaryPidFromSplitTunWhitelist, daemonPid)
		otherVpnCommandsToUndo[daemonPid] = &otherVpnUndoCompatCommand{cliPath: mullvadCli, fullArgs: &mullvadRemoveDaemonPid}
	}

	// TODO: FIXME: do we need?
	//		- to worry about explicitly whitelisting /opt/privateline-connect/wireguard-tools/wg* with Mullvad?
	//		- "mullvad export-settings", munge them, "mullvad import-settings"

	otherVpnsToUndo[mullvadName] = &otherVpnCommandsToUndo // add this VPN to undo list

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

// reDetectOtherVpnsImpl - re-detect the other VPNs present, and optionally adjust the current MTU accordingly.
// If no detection was run yet, or if forceRedetection=true - it will run re-detection unconditionally.
// Else it will run re-detection only if the previous detection data is older than 5 seconds.
func reDetectOtherVpnsImpl(forceRedetection, detectOnlyByInterfaceName, updateCurrentMTU, otherVpnsCliMutexAlreadyGrabbed, canReconfigureOtherVpns bool) (recommendedNewMTU int, err error) {
	if isDaemonStoppingCallback() {
		return lowestRecommendedMTU, log.ErrorFE("error - daemon is stopping")
	}

	// Before entering critical section - check whether the last detection timestamp is too old.
	// (If it's zero - it means detection wasn't run yet since the daemon start.
	if !forceRedetection && !otherVpnsLastDetectionTimestamp.IsZero() && time.Since(otherVpnsLastDetectionTimestamp) < VPN_REDETECT_PERIOD { // if the timestamp is fresh
		return lowestRecommendedMTU, nil
	} // else we have to re-detect

	if !otherVpnsCliMutexAlreadyGrabbed {
		otherVpnsCliMutex.Lock()
		defer otherVpnsCliMutex.Unlock()
	}
	otherVpnsNftMutex.Lock()
	otherVpnsLegacyMutex.Lock()
	defer otherVpnsNftMutex.Unlock()
	defer otherVpnsLegacyMutex.Unlock()

	// Now we acquired all mutexes, we're in critical section
	log.Debug("reDetectOtherVpnsLinux entered")
	defer log.Debug("reDetectOtherVpnsLinux exited - redetected")

	OtherVpnsDetectedRelevantForNftables.Clear()
	OtherVpnsDetectedRelevantForIptablesLegacy.Clear()
	OtherVpnsDetectedReconfigurableViaCli.Clear()

	var (
		reDetectOtherVpnsWaiter          sync.WaitGroup
		defMtu                           = platform.WGDefaultMTU()
		newRecommendedMtuByNftablesChain = defMtu
		newRecommendedMtuByLegacyChain   = defMtu
		newRecommendedMtuByInterface     = defMtu
		newRecommendedMtuByCli           = defMtu
	)

	// xtables locks up for up to 2-15 minutes, so disabling slow iptables-legacy operations.
	//
	// if iptablesLegacyInitialized() && !isDaemonStoppingCallback() {
	// 	reDetectOtherVpnsWaiter.Add(1)
	// 	go func() { // detect other VPNs by whether their iptables-legacy chain is present
	// 		defer reDetectOtherVpnsWaiter.Done() // This thread tends to freeze on VPN disconnect. Console "iptables-legacy -L -nv" freezes, too.
	// 		log.Debug("reDetectOtherVpnsLinux iptables-legacy worker - entered")
	// 		defer log.Debug("reDetectOtherVpnsLinux iptables-legacy worker - exited") // this one can hang for 2-3 minutes
	// 		for _, otherVpn := range otherVpnsByLegacyChain {
	// 			userDefinedLegacyChain := iptables.ChainTypeUserDefined
	// 			userDefinedLegacyChain.SetName(otherVpn.iptablesLegacyChain)
	// 			if foundChains, err := filterLegacy.Chain(userDefinedLegacyChain).FindChains(); err == nil && len(foundChains) >= 1 {
	// 				log.Info("Other VPN '", otherVpn.name, "' detected by iptables-legacy chain: ", otherVpn.iptablesLegacyChain)
	// 				if otherVpn.changesNftables {
	// 					OtherVpnsDetectedRelevantForNftables.Add(otherVpn.name)
	// 				}
	// 				if otherVpn.changesIptablesLegacy {
	// 					OtherVpnsDetectedRelevantForIptablesLegacy.Add(otherVpn.name)
	// 				}
	// 				if otherVpn.recommendedOurMTU != 0 && otherVpn.recommendedOurMTU < newRecommendedMtuByLegacyChain {
	// 					newRecommendedMtuByLegacyChain = otherVpn.recommendedOurMTU
	// 				}
	// 			}
	// 		}
	// 	}()
	// }

	reDetectOtherVpnsWaiter.Add(1)
	go func() { // detect other VPNs by active network interface name
		defer reDetectOtherVpnsWaiter.Done()
		// log.Debug("reDetectOtherVpnsLinux interface worker - entered")
		// defer log.Debug("reDetectOtherVpnsLinux interface worker - exited")

		disabledTotalShield := false
		for otherVpnInterfaceName, otherVpn := range otherVpnsByInterfaceName {
			if _, err := netlink.LinkByName(otherVpnInterfaceName); err == nil {
				log.Info("Other VPN '", otherVpn.name, "' detected by active interface name: ", otherVpnInterfaceName)
				otherVpn.isConnectedConnecting = true
				if !disabledTotalShield && otherVpn.incompatWithTotalShieldWhenConnected && getPrefsCallback().IsTotalShieldOn {
					log.Warning("When other VPN '", otherVpn.name, "' is connected - Total Shield cannot be enabled in PL Connect. Disabling Total Shield.")
					go disableTotalShieldAsyncCallback() // need to fork into the background, so that firewall.TotalShieldApply() can wait for all the mutexes
					disabledTotalShield = true
				}
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

	if !detectOnlyByInterfaceName {
		reDetectOtherVpnsWaiter.Add(2)

		go func() { // detect other VPNs by whether their nftables chain is present in table filter
			defer reDetectOtherVpnsWaiter.Done()
			// log.Debug("reDetectOtherVpnsLinux nftables worker - entered")
			// defer log.Debug("reDetectOtherVpnsLinux nftables worker - exited")

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

		go func() { // detect other VPNs by whether their CLI is in PATH
			defer reDetectOtherVpnsWaiter.Done()
			// log.Debug("reDetectOtherVpnsLinux CLI worker - entered")
			// defer log.Debug("reDetectOtherVpnsLinux CLI worker - exited")

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
					if !reflect.DeepEqual(otherVpn.cliCmds, otherVpnCliCmdsEmpty) { // if the other VPN has CLI commands that we use to reconfigure it
						OtherVpnsDetectedReconfigurableViaCli.Add(otherVpn.name)
					}
					if otherVpn.recommendedOurMTU != 0 && otherVpn.recommendedOurMTU < newRecommendedMtuByCli {
						newRecommendedMtuByCli = otherVpn.recommendedOurMTU
					}
				}
			}
		}()
	}

	reDetectOtherVpnsWaiter.Wait()
	// log.Debug("reDetectOtherVpnsLinux: reDetectOtherVpnsWaiter.Wait() ended")
	otherVpnsLastDetectionTimestamp = time.Now()

	if !iptablesLegacyInitialized() && !OtherVpnsDetectedRelevantForIptablesLegacy.IsEmpty() { // if iptables-legacy were not initialized yet,
		go implInitializeIptablesLegacyWhenNeeded() // and we detected VPNs that affect legacy tables - then initialize it async, it's single-instance
	}

	lowestRecommendedMTU = min(newRecommendedMtuByCli, newRecommendedMtuByInterface, newRecommendedMtuByLegacyChain, newRecommendedMtuByNftablesChain)

	if !vpnConnectedOrConnectingCallback() { // the below section may be prone to deadlocks during disconnection (unclear) - so skipping it on disconnect
		return lowestRecommendedMTU, nil
	}

	var ourWgInterface netlink.Link
	var currMtu = 0
	if updateCurrentMTU { // if requested, update the current MTU on wgprivateline network interface
		// log.Debug("reDetectOtherVpnsLinux about to netlink.LinkByName(", platform.WGInterfaceName(), ")")
		if ourWgInterface, err = netlink.LinkByName(platform.WGInterfaceName()); err == nil {
			currMtu = ourWgInterface.Attrs().MTU
			// log.Debug("currMtu = ", currMtu)
		} else {
			log.Debug(fmt.Errorf("error getting our Wireguard interface - perhaps it's not up at the moment. Not adjusting our current MTU. err=%w", err))
		}
	}

	if updateCurrentMTU && currMtu != 0 { // if requested, update the current MTU on wgprivateline network interface
		if currMtu != lowestRecommendedMTU && vpnConnectedOrConnectingCallback() { // if we have to change our current MTU
			log.Debug("reDetectOtherVpnsLinux about to netlink.LinkSetMTU(", lowestRecommendedMTU, ") - changing from ", currMtu)
			if err = netlink.LinkSetMTU(ourWgInterface, lowestRecommendedMTU); err != nil {
				return lowestRecommendedMTU, log.ErrorFE("error netlink.LinkSetMTU(%d): %w", lowestRecommendedMTU, err)
			}
		}
	}

	return lowestRecommendedMTU, nil
}

// implBestWireguardMtuForConditions - check for running other VPNs, detect the optimal MTU
func implBestWireguardMtuForConditions() (recommendedMTU int, retErr error) {
	// otherVpnsNftMutex.Lock()
	// defer otherVpnsNftMutex.Unlock()
	// otherVpnsLegacyMutex.Lock()
	// defer otherVpnsLegacyMutex.Unlock()

	return reDetectOtherVpnsImpl(false, false, false, false, getPrefsCallback().PermissionReconfigureOtherVPNs)
	// recommendedMTU = lowestRecommendedMTU
	// return recommendedMTU, retErr
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

// enableVpnCoexistenceLinuxNft enables VPN coexistence steps for those other VPNs that affect nftables
func enableVpnCoexistenceLinuxNft(canReconfigureOtherVpns bool) (retErr error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	otherVpnsNftMutex.Lock() // we need to make sure reDetectOtherVpnsLinux() is not running, and that we have exclusive access to OtherVpnsDetectedRelevantForNftables
	defer otherVpnsNftMutex.Unlock()

	log.Debug("enableVpnCoexistenceLinuxNft entered")
	defer log.Debug("enableVpnCoexistenceLinuxNft exited")
	// Debugging: dump nftables and optionally iptables-legacy to log
	// defer printNftToLog()
	// defer printIptablesLegacy() // will print anything only if another VPN affecting iptables-legacy is detected

	prefs := getPrefsCallback()
	canReconfigureOtherVpns = canReconfigureOtherVpns || prefs.PermissionReconfigureOtherVPNs

	var enableVpnCoexistenceLinuxNftTasks sync.WaitGroup

	// Here we process only the other VPNs that affect nftables.
	// Note that the detected VPNs that affect iptables-legacy are processed in doEnableLegacy().
	for otherVpnNftName := range OtherVpnsDetectedRelevantForNftables.Iterator().C {
		otherVpnNft, ok := otherVpnsByName[otherVpnNftName]
		if !ok {
			log.ErrorFE("error looking up detected other VPN '%s', skipping", otherVpnNftName)
			continue
		}

		if otherVpnNft.nftablesHelper != nil { // run specific helper for VPNs that have one registered
			enableVpnCoexistenceLinuxNftTasks.Add(1)
			go func() {
				defer enableVpnCoexistenceLinuxNftTasks.Done()
				if err := otherVpnNft.nftablesHelper(canReconfigureOtherVpns); err != nil {
					retErr = log.ErrorFE("error otherVpnNft.nftablesHelper() for VPN '%s': %w", otherVpnNftName, err)
				}
			}()
		}

		enableVpnCoexistenceLinuxNftTasks.Add(1) // run commonNftablesHelper for this other VPN - logic common to all nftables-affecting other VPNs
		go func() {
			defer enableVpnCoexistenceLinuxNftTasks.Done()
			if err := commonNftablesHelper(otherVpnNftName, canReconfigureOtherVpns); err != nil {
				retErr = log.ErrorFE("error commonNftablesHelper() for VPN '%s': %w", otherVpnNftName, err)
			}
		}()

		if canReconfigureOtherVpns && otherVpnNft.cliPathResolved != "" && len(otherVpnNft.cliCmds.cmdAddAllowlistOption) > 0 { // if we have an allowlist command for that VPN
			otherVpnCommandsToUndo := otherVpnCommandsToUndoMap{}
			for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
				enableVpnCoexistenceLinuxNftTasks.Add(1)
				go func() {
					defer enableVpnCoexistenceLinuxNftTasks.Done()

					// so far we only know NordVPN, so add our Wireguard gateways to the other VPN's allowlist

					plWgEntryHostIpCIDR := vpnEntryHost.EndpointIP + "/32" // add Wireguard endpoint IP to allowlist
					cmdAddOurWgEndpointToOtherVpnAllowlist := append(otherVpnNft.cliCmds.cmdAddAllowlistOption, plWgEntryHostIpCIDR)
					if err := tryCmdLogOnError(otherVpnNft.cliPathResolved, cmdAddOurWgEndpointToOtherVpnAllowlist...); err != nil {
						retErr = log.ErrorFE("error adding WG endpoint IP '%s' to allowlist: %w", plWgEntryHostIpCIDR, err)
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
				}()
			}
		}
	}

	enableVpnCoexistenceLinuxNftTasks.Wait()
	return retErr
}

// Undo VPN compatibility steps per VPN.
// TODO: if customers will have multiple other VPNs up, consider processing them in parallel?
func DisableCoexistenceWithOtherVpns() (retErr error) {
	// log.Debug("DisableCoexistenceWithOtherVpns waiting for mutexes")

	otherVpnsNftMutex.Lock()
	defer otherVpnsNftMutex.Unlock()
	otherVpnsLegacyMutex.Lock()
	defer otherVpnsLegacyMutex.Unlock()

	DisableCoexistenceWithOtherVpnsMutex.Lock() // launcher waits for this mutex on daemon shutdown, to ensure all disable tasks have been completed
	defer DisableCoexistenceWithOtherVpnsMutex.Unlock()

	log.Debug("DisableCoexistenceWithOtherVpns entered")
	defer log.Debug("DisableCoexistenceWithOtherVpns exited")

	if getPrefsCallback().PermissionReconfigureOtherVPNs {
		for _, otherVpnCommands := range otherVpnsToUndo {
			for _, cmdInfo := range *otherVpnCommands {
				if err := tryCmdLogOnError(cmdInfo.cliPath, *cmdInfo.fullArgs...); err != nil {
					retErr = err
				}
			}
		}
	}

	clear(otherVpnsToUndo)

	return retErr
}

func reconfigurableOtherVpnsDetectedImpl() (detected bool, otherVpnNames []string, err error) {
	otherVpnsCliMutex.Lock() // lock it here, because this func uses OtherVpnsDetectedReconfigurableViaCli after reDetectOtherVpnsImpl()
	defer otherVpnsCliMutex.Unlock()

	if _, err = reDetectOtherVpnsImpl(false, false, false, true, false); err != nil {
		return false, otherVpnNames, log.ErrorFE("error in reDetectOtherVpnsImpl: %w", err)
	}

	// otherVpnNames = OtherVpnsDetectedRelevantForNftables.Union(OtherVpnsDetectedRelevantForIptablesLegacy).ToSlice()
	// return !OtherVpnsDetectedRelevantForNftables.IsEmpty() || !OtherVpnsDetectedRelevantForIptablesLegacy.IsEmpty(), otherVpnNames, nil

	return !OtherVpnsDetectedReconfigurableViaCli.IsEmpty(), OtherVpnsDetectedReconfigurableViaCli.ToSlice(), nil
}
