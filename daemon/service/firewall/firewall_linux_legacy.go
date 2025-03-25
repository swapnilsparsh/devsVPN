//
//  Daemon for privateLINE Connect Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the Daemon for privateLINE Connect Desktop.
//
//  The Daemon for privateLINE Connect Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for privateLINE Connect Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for privateLINE Connect Desktop. If not, see <https://www.gnu.org/licenses/>.
//

//go:build linux
// +build linux

// Here we have Linux firewall logic for iptables-legacy firewall interface

package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

const (
	IPTABLES_LEGACY = "iptables-legacy"

	VPN_COEXISTENCE_CHAIN_LEGACY_IN  = VPN_COEXISTENCE_CHAIN_PREFIX + "-legacy-in"
	VPN_COEXISTENCE_CHAIN_LEGACY_OUT = VPN_COEXISTENCE_CHAIN_PREFIX + "-legacy-out"
)

var (
	fwLinuxLegacyMutex                       sync.Mutex           // global lock for firewall_linux_legacy read and write operations
	stopMonitoringFirewallChangesLegacy      = make(chan bool, 2) // used to send a stop signal to implFirewallBackgroundMonitorLegacy() thread
	implFirewallBackgroundMonitorLegacyMutex sync.Mutex           // to ensure there's only one instance of implFirewallBackgroundMonitorLegacy function

	iptablesLegacyPath  string                   // empty if iptables-legacy not found in path
	ipt                 *iptables.IPTables = nil // nil if iptables-legacy not found
	filterLegacy        *iptables.IPTables = nil // nil if iptables-legacy not found
	inputLegacy         *iptables.IPTables = nil
	outputLegacy        *iptables.IPTables = nil
	vpnCoexLegacyInDef                     = iptables.ChainTypeUserDefined
	vpnCoexLegacyOutDef                    = iptables.ChainTypeUserDefined
)

func implInitializeLegacy() (err error) {
	if iptablesLegacyPath, err = exec.LookPath(IPTABLES_LEGACY); err != nil {
		return log.ErrorFE("error looking up %s in PATH: %w", IPTABLES_LEGACY, err)
	}

	ipt = iptables.NewIPTables(iptables.OptionIPTablesCmdPath(iptablesLegacyPath), iptables.OptionIPTablesLogger(log))
	filterLegacy = ipt.Table(iptables.TableTypeFilter)

	inputLegacy = filterLegacy.Chain(iptables.ChainTypeINPUT)
	outputLegacy = filterLegacy.Chain(iptables.ChainTypeOUTPUT)

	vpnCoexLegacyInDef.SetName(VPN_COEXISTENCE_CHAIN_LEGACY_IN)
	vpnCoexLegacyOutDef.SetName(VPN_COEXISTENCE_CHAIN_LEGACY_OUT)

	return nil
}

func iptablesLegacyPresent() bool {
	return ipt != nil
}

func implHaveTopFirewallPriorityLegacy() (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	weHaveTopFirewallPriority, retErr = implGetEnabledLegacy()
	return weHaveTopFirewallPriority, "", "", "", retErr
}

// implGetEnabledLegacy checks whether 1st rules in INPUT, OUTPUT chains are jumps to our chains
func implGetEnabledLegacy() (exists bool, retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return true, nil
	}

	// log.Debug("implGetEnabledLegacy entered")
	// defer log.Debug("implGetEnabledLegacy exited")

	// TODO: ? implement check-reenable logic? if the 1st rule in INPUT, OUTPUT not a jump to our chains - just add

	if inputRules, err := inputLegacy.ListRules(); err != nil {
		return false, log.ErrorFE("error listing INPUT rules: %w", err)
	} else if len(inputRules) < 1 {
		//log.Debug("INPUT chain empty")
		return false, nil
	} else if inputRules[0].Target().Short() != ("-j " + VPN_COEXISTENCE_CHAIN_LEGACY_IN) {
		log.Debug("unexpected 1st rule in INPUT chain: " + inputRules[0].Target().Short())
		return false, nil
	}

	if outputRules, err := outputLegacy.ListRules(); err != nil {
		return false, log.ErrorFE("error listing OUTPUT rules: %w", err)
	} else if len(outputRules) < 1 {
		//log.Debug("OUTPUT chain empty")
		return false, nil
	} else if outputRules[0].Target().Short() != ("-j " + VPN_COEXISTENCE_CHAIN_LEGACY_OUT) {
		log.Debug("unexpected 1st rule in OUTPUT chain: " + outputRules[0].Target().Short())
		return false, nil
	}

	return true, nil
}

func implReregisterFirewallAtTopPriorityLegacy() (firewallReconfigured bool, retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return false, nil
	}

	// to ensure there's only one instance of this function, and that no other read or write operations are taking place in parallel
	fwLinuxLegacyMutex.Lock()
	defer fwLinuxLegacyMutex.Unlock()

	// log.Debug("implReregisterFirewallAtTopPriorityLegacy entered")
	// defer log.Debug("implReregisterFirewallAtTopPriorityLegacy exited")

	if weHaveTopFirewallPriority, err := implGetEnabledLegacy(); err != nil {
		return false, log.ErrorFE("error in implGetEnabledLegacy(): %w", err)
	} else if weHaveTopFirewallPriority {
		return false, nil
	}

	// signal loss of top firewall priority to UI
	go waitForTopFirewallPriAfterWeLostIt()

	log.Debug("implReregisterFirewallAtTopPriorityLegacy - don't have top pri, need to reenable firewall")

	if err := implReEnableLegacy(true); err != nil {
		return true, log.ErrorFE("error in implReEnableLegacy: %w", err)
	}

	go onKillSwitchStateChangedCallback()         // send notification out in case state went from FAIL to GOOD
	go implDeployPostConnectionRulesLegacy(false) // forking in the background, as otherwise DNS timeouts are up to ~15 sec, they freeze UI changes

	return true, nil
}

// implFirewallBackgroundMonitorLegacy runs asynchronously as a forked thread.
// It polls regularly whether we have top firewall priority. If don't have top pri - it recreates our firewall objects.
// To stop this thread - send to stopMonitoringFirewallChangesLegacy chan.
func implFirewallBackgroundMonitorLegacy() {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	implFirewallBackgroundMonitorLegacyMutex.Lock() // to ensure there's only one instance of implFirewallBackgroundMonitorLegacy
	defer implFirewallBackgroundMonitorLegacyMutex.Unlock()

	log.Debug("implFirewallBackgroundMonitorLegacy entered")
	defer log.Debug("implFirewallBackgroundMonitorLegacy exited")

	for {
		time.Sleep(time.Second * 5)
		select {
		case _ = <-stopMonitoringFirewallChangesLegacy:
			log.Debug("implFirewallBackgroundMonitorLegacy exiting on stop signal")
			return
		default: // no message received
			if _, err := implReregisterFirewallAtTopPriorityLegacy(); err != nil {
				log.ErrorFE("error in implReregisterFirewallAtTopPriorityLegacy(): %w", err) // and continue
			}
		}
	}
}

func implReEnableLegacy(fwLinuxLegacyMutexGrabbed bool) (retErr error) {
	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("implReEnableLegacy")

	if err := doDisableLegacy(true); err != nil {
		log.ErrorFE("failed to disable iptables-legacy firewall: %w", err) // and continue
	}

	if err := doEnableLegacy(true); err != nil {
		return log.ErrorFE("failed to enable iptables-legacy firewall: %w", err)
	}

	//return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
	return nil
}

func doEnableLegacy(fwLinuxLegacyMutexGrabbed bool) (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("doEnableLegacy entered")
	defer log.Debug("doEnableLegacy exited")

	prefs := getPrefsCallback()

	if enabled, err := implGetEnabledLegacy(); err != nil {
		return log.ErrorFE("error implGetEnabledLegacy(): %w", err)
	} else if enabled {
		log.Debug("iptables-legacy already enabled, not enabling again")
		return nil
	}

	// create PL chains, and insert jumps to them on top of INPUT, OUTPUT
	if err = filterLegacy.NewChain(VPN_COEXISTENCE_CHAIN_LEGACY_IN); err != nil {
		return log.ErrorFE("error filterLegacy.NewChain(%s): %w", VPN_COEXISTENCE_CHAIN_LEGACY_IN, err)
	}
	if err = filterLegacy.Chain(iptables.ChainTypeINPUT).TargetJumpChain(VPN_COEXISTENCE_CHAIN_LEGACY_IN).Insert(); err != nil {
		return log.ErrorFE("error filterLegacy.Chain(iptables.ChainTypeINPUT).TargetJumpChain(%s).Insert(): %w", VPN_COEXISTENCE_CHAIN_LEGACY_IN, err)
	}

	if err = filterLegacy.NewChain(VPN_COEXISTENCE_CHAIN_LEGACY_OUT); err != nil {
		return log.ErrorFE("error filterLegacy.NewChain(%s): %w", VPN_COEXISTENCE_CHAIN_LEGACY_OUT, err)
	}
	if err = filterLegacy.Chain(iptables.ChainTypeOUTPUT).TargetJumpChain(VPN_COEXISTENCE_CHAIN_LEGACY_OUT).Insert(); err != nil {
		return log.ErrorFE("error filterLegacy.Chain(iptables.ChainTypeINPUT).TargetJumpChain(%s).Insert(): %w", VPN_COEXISTENCE_CHAIN_LEGACY_OUT, err)
	}

	vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	vpnCoexLegacyOut := filterLegacy.Chain(vpnCoexLegacyOutDef)

	// create rules

	// TODO: Vlad - allow ICMP: allow echo request out, echo reply in, and bi-directional fragmentation messages
	//	- to/fro Wireguard endpoints
	//	- PL IP ranges
	//
	//	? Maybe not necessary to create allow rules explicitly? Connmark established,related allows pinging many (but not all) PL internal hosts.

	for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
		wgEndpointIP := strings.TrimSpace(vpnEntryHost.EndpointIP) // Allow our Wireguard gateways: in UDP and established+related, out TCP+UDP (any proto)
		if err = vpnCoexLegacyIn.MatchSource(false, wgEndpointIP).MatchProtocol(false, network.ProtocolUDP).TargetAccept().Append(); err != nil {
			return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyIn).MatchSource(false, wgEndpointIP).MatchProtocol(false, network.ProtocolUDP).TargetAccept().Append(): %w", err)
		}
		if err = vpnCoexLegacyIn.MatchSource(false, wgEndpointIP).MatchState(iptables.ESTABLISHED | iptables.RELATED).TargetAccept().Append(); err != nil {
			return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyIn).MatchSource(false, wgEndpointIP).MatchState(iptables.ESTABLISHED | iptables.RELATED).TargetAccept().Append(): %w", err)
		}

		if err = vpnCoexLegacyOut.MatchDestination(false, wgEndpointIP).TargetAccept().Append(); err != nil {
			return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyOut).MatchDestination(false, wgEndpointIP).TargetAccept().Append(): %w", err)
		}

		// Allow UDP src port 53 from our DNS servers and UDP dst port 53 to our DNS servers, incl. custom DNS
		dnsSrvList := vpnEntryHost.DnsServers
		if len(customDnsServers) >= 1 { // append custom DNS, if configured
			for _, customDnsSrv := range customDnsServers {
				if !prefs.AllDnsServersIPv4Set.Contains(customDnsSrv.String()) && !net.IPv4zero.Equal(customDnsSrv) {
					dnsSrvList += "," + customDnsSrv.To4().String()
				}
			}
		}
		for _, dnsSrv := range strings.Split(dnsSrvList, ",") {
			dnsSrv = strings.TrimSpace(dnsSrv)
			if err = vpnCoexLegacyIn.MatchSource(false, dnsSrv).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPSrcPort(false, 53)).TargetAccept().Append(); err != nil {
				return log.ErrorFE("error add DNS src UDP port 53: %w", err)
			}
			if err = vpnCoexLegacyOut.MatchDestination(false, dnsSrv).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetAccept().Append(); err != nil {
				return log.ErrorFE("error add DNS dst UDP port 53: %w", err)
			}
		}

		// TODO: Vlad - permit all PL apps in UDP, out TCP+UDP (any proto) with PL IP ranges by default, until we re-implement App Whitelist

		for _, allowedIpCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // allowedIPs, internal PL IP ranges ; CIDR format like "10.0.0.3/24"
			allowedIpCIDR = strings.TrimSpace(allowedIpCIDR)

			//	"related, established" will take care of TCP inbound packets
			// allow UDP in, any proto out
			if err = vpnCoexLegacyIn.MatchSource(false, allowedIpCIDR).MatchProtocol(false, network.ProtocolUDP).TargetAccept().Append(); err != nil {
				return log.ErrorFE("error add in UDP on allowed PL IP range %s: %w", allowedIpCIDR, err)
			}
			if err = vpnCoexLegacyOut.MatchDestination(false, allowedIpCIDR).TargetAccept().Append(); err != nil {
				return log.ErrorFE("error add in any out on allowed PL IP range %s: %w", allowedIpCIDR, err)
			}
		}
	}

	// Allow our hosts (meet.privateline.network, etc.) in: UDP
	// Since we may not be connected to our VPN yet, use default cached IPs here
	for _, plInternalHost := range *platform.PLInternalHostsToAcceptIncomingUdpFrom() {
		if err = vpnCoexLegacyIn.MatchSource(false, plInternalHost.DefaultIpString).MatchProtocol(false, network.ProtocolUDP).TargetAccept().Append(); err != nil {
			return log.ErrorFE("error add in UDP for internal host '%s' IP %s: %w", plInternalHost.Hostname, plInternalHost.DefaultIpString, err)
		}
	}

	// allow PL service binaries in-out. Then we don't need to explicitly create allow rules for REST API servers, etc.
	// also allow in-out for our other default allowed apps (PL Comms, etc.)
	// 	TODO: permit PL Comms etc. only inbound UDP
	matchOurCgroup := iptables.WithMatchCGroupClassID(false, 0x70561e1d)
	if err = vpnCoexLegacyIn.MatchCGroup(matchOurCgroup).TargetAccept().Append(); err != nil {
		return log.ErrorFE("error matching our cgroup in: %w", err)
	}
	if err = vpnCoexLegacyOut.MatchCGroup(matchOurCgroup).TargetAccept().Append(); err != nil {
		return log.ErrorFE("error matching our cgroup out: %w", err)
	}

	// create rules for wgprivateline interface - even if it doesn't exist yet

	// conntrack state established,related accept on input on interface wgprivateline
	if err = vpnCoexLegacyIn.MatchInInterface(false, platform.WGInterfaceName()).MatchState(iptables.ESTABLISHED | iptables.RELATED).TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error ...: %w", err)
	}
	// conttrack state invalid drop on input on interface wgprivateline
	if err = vpnCoexLegacyIn.MatchInInterface(false, platform.WGInterfaceName()).MatchState(iptables.INVALID).TargetDrop().Insert(); err != nil {
		return log.ErrorFE("error ...: %w", err)
	}
	// conntrack state established accept on output on interface wgprivateline
	if err = vpnCoexLegacyOut.MatchOutInterface(false, platform.WGInterfaceName()).MatchState(iptables.ESTABLISHED).TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error ...: %w", err)
	}

	// allow lo traffic
	if err = vpnCoexLegacyIn.MatchInInterface(false, "lo").TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyIn).MatchInInterface(false, \"lo\").TargetAccept().Insert(): %w", err)
	}
	if err = vpnCoexLegacyOut.MatchOutInterface(false, "lo").TargetAccept().Insert(); err != nil {
		return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyOut).MatchOutInterface(false, \"lo\").TargetAccept().Insert(): %w", err)
	}

	// TODO FIXME: Vlad ---------------- Surfshark testing START ----------------

	// allow all DNS before login (SessionNew)
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

	// - outbound packets by our binaries (to allow login to deskapi)
	if err = vpnCoexLegacyOut.MatchCGroup(matchOurCgroup).TargetMark(iptables.WithTargetMarkOr(surfsharkMark)).Insert(); err != nil {
		return log.ErrorFE("error matching our cgroup out - OR mark 0x493e0: %w", err)
	}

	//	- all outbound DNS packets
	if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetMark(iptables.WithTargetMarkOr(surfsharkMark)).Insert(); err != nil {
		return log.ErrorFE("error add all DNS dst UDP port 53 OR mark 0x493e0: %w", err)
	}
	if err = vpnCoexLegacyOut.MatchProtocol(false, network.ProtocolTCP).MatchTCP(iptables.WithMatchTCPDstPort(false, 53)).TargetMark(iptables.WithTargetMarkOr(surfsharkMark)).Insert(); err != nil {
		return log.ErrorFE("error add all DNS dst TCP port 53 OR mark 0x493e0: %w", err)
	}

	for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
		//	- outbound packets to our WG endpoints
		wgEndpointIP := strings.TrimSpace(vpnEntryHost.EndpointIP) // Allow our Wireguard gateways: in UDP and established+related, out TCP+UDP (any proto)
		if err = vpnCoexLegacyOut.MatchDestination(false, wgEndpointIP).TargetMark(iptables.WithTargetMarkOr(surfsharkMark)).Insert(); err != nil {
			return log.ErrorFE("error out wgEndpointIP OR mark 0x493e0: %w", err)
		}

		//	- outbound packets to our allowedIPs (internal PL IPs)
		for _, allowedIpCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // allowedIPs, internal PL IP ranges ; CIDR format like "10.0.0.3/24"
			allowedIpCIDR = strings.TrimSpace(allowedIpCIDR)
			if err = vpnCoexLegacyOut.MatchDestination(false, allowedIpCIDR).TargetMark(iptables.WithTargetMarkOr(surfsharkMark)).Insert(); err != nil {
				return log.ErrorFE("error add out on allowed PL IP range %s - OR mark 0x493e0: %w", allowedIpCIDR, err)
			}
		}
	}

	// TODO FIXME: Vlad ---------------- Surfshark testing END ----------------

	if totalShieldEnabled && vpnConnectedOrConnectingCallback() { // add DROP rules at the end of our chains; enable Total Shield blocks only if VPN is connected or connecting
		log.Debug("doEnableLegacy: enabling TotalShield")
		if err = vpnCoexLegacyOut.TargetDrop().Append(); err != nil {
			return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyOut).TargetDrop().Append(): %w", err)
		}
		if err = vpnCoexLegacyIn.TargetDrop().Append(); err != nil {
			return log.ErrorFE("error filterLegacy.Chain(vpnCoexLegacyIn).TargetDrop().Append(): %w", err)
		}
	}

	return nil
}

func implDeployPostConnectionRulesLegacy(fwLinuxLegacyMutexGrabbed bool) (retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("implDeployPostConnectionRulesLegacy entered")
	defer log.Debug("implDeployPostConnectionRulesLegacy exited")

	if firewallEnabled, err := implGetEnabledLegacy(); err != nil {
		return log.ErrorFE("status check error: %w", err)
	} else if !firewallEnabled || !vpnConnectedOrConnectingCallback() {
		return nil // our tables not up or VPN not connected/connecting, so skipping
	}

	// Allow our hosts (meet.privateline.network, etc.) in: UDP
	vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	for _, plInternalHost := range *platform.PLInternalHostsToAcceptIncomingUdpFrom() {
		var IPs []net.IP
		if IPs, retErr = net.LookupIP(plInternalHost.Hostname); retErr != nil {
			retErr = log.ErrorFE("could not lookup IPs for '%s': %w", plInternalHost, retErr)
			continue
		} else if len(IPs) == 0 {
			retErr = log.ErrorFE("no IPs returned for '%s'", plInternalHost)
			continue
		}

		for _, IP := range IPs { // add newly found IPs for this hostname to set, unless they match the default known IP
			if !plInternalHost.DefaultIP.Equal(IP) && IP.To4() != nil && !net.IPv4zero.Equal(IP) { // IPv4
				if retErr = vpnCoexLegacyIn.MatchSource(false, IP).MatchProtocol(false, network.ProtocolUDP).TargetAccept().Append(); retErr != nil {
					return log.ErrorFE("error add in UDP for internal host '%s' IP %s: %w", plInternalHost.Hostname, plInternalHost.DefaultIP, retErr)
				}

			}
		}
	}

	return retErr
}

// deleteOurJumpRuleHelper takes arg: true for INPUT, false for OUTPUT
func deleteOurJumpRuleHelper(input bool) (retErr error) {
	if input { // iptables-legacy -D INPUT -j privateline-vpn-coexistence-legacy-in
		return shell.Exec(log, iptablesLegacyPath, []string{"-D", "INPUT", "-j", VPN_COEXISTENCE_CHAIN_LEGACY_IN}...)
	} else { // iptables-legacy -D OUTPUT -j privateline-vpn-coexistence-legacy-out
		return shell.Exec(log, iptablesLegacyPath, []string{"-D", "OUTPUT", "-j", VPN_COEXISTENCE_CHAIN_LEGACY_OUT}...)
	}
}

// deleteOurJumpRule takes arg: true for INPUT, false for OUTPUT
func deleteOurJumpRules(input bool) (retErr error) {
	var (
		chain                                 *iptables.IPTables
		chainName, expectedJumpRuleToOurChain string
	)
	if input {
		chain = inputLegacy
		chainName = "INPUT"
		expectedJumpRuleToOurChain = "-j " + VPN_COEXISTENCE_CHAIN_LEGACY_IN
	} else {
		chain = outputLegacy
		chainName = "OUTPUT"
		expectedJumpRuleToOurChain = "-j " + VPN_COEXISTENCE_CHAIN_LEGACY_OUT
	}

	if rules, err := chain.ListRules(); err != nil {
		return log.ErrorFE("error listing %s rules: %w", chainName, err)
	} else if len(rules) >= 1 {
		for _, rule := range rules {
			if rule.Target().Short() == expectedJumpRuleToOurChain {
				if err := deleteOurJumpRuleHelper(input); err != nil {
					log.ErrorFE("error deleteOurJumpRuleHelper(%t): %w", input, err) // and continue
				}
			}
		}
	}

	return nil
}

// doDisableLegacy - actions in it are best-effort, unless we encounter a real error
func doDisableLegacy(fwLinuxLegacyMutexGrabbed bool) (retErr error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	if !fwLinuxLegacyMutexGrabbed {
		fwLinuxLegacyMutex.Lock()
		defer fwLinuxLegacyMutex.Unlock()
	}

	log.Debug("doDisableLegacy entered")
	defer log.Debug("doDisableLegacy exited")

	vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	vpnCoexLegacyOut := filterLegacy.Chain(vpnCoexLegacyOutDef)

	// flush our chains
	if err := vpnCoexLegacyIn.Flush(); err != nil {
		log.Debug(fmt.Errorf("error flushing %s chain: %w", VPN_COEXISTENCE_CHAIN_LEGACY_IN, err)) // and continue
	}
	if err := vpnCoexLegacyOut.Flush(); err != nil {
		log.Debug(fmt.Errorf("error flushing %s chain: %w", VPN_COEXISTENCE_CHAIN_LEGACY_OUT, err)) // and continue
	}

	// delete all rules in INPUT, OUTPUT that are jumps to our chains
	for _, builtinChain := range []bool{true, false} {
		if err := deleteOurJumpRules(builtinChain); err != nil {
			log.ErrorFE("error deleting our jump rules: INPUT=%t: %w", builtinChain, err) // and continue
		}
	}

	// delete our chains
	if err := vpnCoexLegacyIn.DeleteChain(); err != nil {
		log.Warn(fmt.Errorf("error deleting our chain %s: %w", VPN_COEXISTENCE_CHAIN_LEGACY_IN, err)) // and continue
	}
	if err := vpnCoexLegacyOut.DeleteChain(); err != nil {
		log.Warn(fmt.Errorf("error deleting our chain %s: %w", VPN_COEXISTENCE_CHAIN_LEGACY_OUT, err)) // and continue
	}

	return nil
}

func implOnChangeDnsLegacy(newDnsServers *[]net.IP) (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	fwLinuxLegacyMutex.Lock()
	defer fwLinuxLegacyMutex.Unlock()

	vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	vpnCoexLegacyOut := filterLegacy.Chain(vpnCoexLegacyOutDef)

	for _, newDnsSrv := range *newDnsServers {
		if err = vpnCoexLegacyIn.MatchSource(false, newDnsSrv.To4()).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPSrcPort(false, 53)).TargetAccept().Append(); err != nil {
			return log.ErrorFE("error add DNS src UDP port 53: %w", err)
		}
		if err = vpnCoexLegacyOut.MatchDestination(false, newDnsSrv.To4()).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetAccept().Append(); err != nil {
			return log.ErrorFE("error add DNS dst UDP port 53: %w", err)
		}
	}

	return nil
}

func implTotalShieldApplyLegacy(_totalShieldEnabled bool) (err error) {
	if ipt == nil { // if iptables-legacy not present
		return
	}

	fwLinuxLegacyMutex.Lock()
	defer fwLinuxLegacyMutex.Unlock()

	// by now we know the firewall is up - gotta add or remove DROP rules to reflect new Total Shield setting

	vpnCoexLegacyIn := filterLegacy.Chain(vpnCoexLegacyInDef)
	vpnCoexLegacyOut := filterLegacy.Chain(vpnCoexLegacyOutDef)

	var (
		vpnCoexistenceChainInRules, vpnCoexistenceChainOutRules []*iptables.Rule
		lastInRuleIsDrop, lastOutRuleIsDrop                     bool
	)

	if vpnCoexistenceChainInRules, err = vpnCoexLegacyIn.ListRules(); err != nil {
		return log.ErrorFE("error listing rules in chain %s: %w", VPN_COEXISTENCE_CHAIN_LEGACY_IN, err)
	}

	if vpnCoexistenceChainOutRules, err = vpnCoexLegacyOut.ListRules(); err != nil {
		return log.ErrorFE("error listing rules in chain %s: %w", VPN_COEXISTENCE_CHAIN_LEGACY_OUT, err)
	}

	if len(vpnCoexistenceChainInRules) >= 1 {
		if vpnCoexistenceChainInRules[len(vpnCoexistenceChainInRules)-1].Target().Type() == iptables.TargetTypeDrop {
			lastInRuleIsDrop = true
		}
	}
	if len(vpnCoexistenceChainOutRules) >= 1 {
		if vpnCoexistenceChainOutRules[len(vpnCoexistenceChainOutRules)-1].Target().Type() == iptables.TargetTypeDrop {
			lastOutRuleIsDrop = true
		}
	}

	toEnableTotalShield := _totalShieldEnabled && vpnConnectedOrConnectingCallback() // Enable Total Shield DROP rules only if VPN is connected or connecting
	log.Debug("implTotalShieldApplyLegacy: setting TotalShield=", toEnableTotalShield, " in firewall")
	if toEnableTotalShield {
		if !lastOutRuleIsDrop { // if last rules are not DROP rules already - append DROP rules to the end
			if err = vpnCoexLegacyOut.TargetDrop().Append(); err != nil {
				return log.ErrorFE("error vpnCoexLegacyOut.TargetDrop().Append(): %w", err)
			}
		}
		if !lastInRuleIsDrop {
			if err = vpnCoexLegacyIn.TargetDrop().Append(); err != nil {
				return log.ErrorFE("error vpnCoexLegacyIn.TargetDrop().Append(): %w", err)
			}
		}
	} else { // Disable Total Shield in the firewall. If the last rules are DROP rules - delete them. Rule numbering in iptables is 1-based.
		if lastInRuleIsDrop {
			if err = vpnCoexLegacyIn.Delete(iptables.WithCommandDeleteRuleNumber(len(vpnCoexistenceChainInRules))); err != nil {
				return log.ErrorFE("error vpnCoexLegacyIn.Delete(iptables.WithCommandDeleteRuleNumber(%d)): %w", len(vpnCoexistenceChainInRules), err)
			}
		}
		if lastOutRuleIsDrop {
			if err = vpnCoexLegacyOut.Delete(iptables.WithCommandDeleteRuleNumber(len(vpnCoexistenceChainOutRules))); err != nil {
				return log.ErrorFE("error vpnCoexLegacyOut.Delete(iptables.WithCommandDeleteRuleNumber(%d)): %w", len(vpnCoexistenceChainOutRules), err)
			}
		}
	}

	return nil
}
