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

package firewall

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/unix"
)

const (
	VPN_COEXISTENCE_CHAIN_IN  = "PRIVATELINE_VPN_COEXISTENCE_IN"
	VPN_COEXISTENCE_CHAIN_OUT = "PRIVATELINE_VPN_COEXISTENCE_OUT"
)

var (
	nftConn       = &nftables.Conn{}
	mutexInternal sync.Mutex

	// key: is a string representation of allowed IP
	// value: true - if exception rule is persistent (persistent, means will stay available even client is disconnected)
	allowedHosts   map[string]bool
	allowedForICMP map[string]struct{} // IP addresses allowed for ICMP

	curAllowedLanIPs          []string // IP addresses allowed for LAN
	curStateAllowLAN          bool     // Allow LAN is enabled
	curStateAllowLanMulticast bool     // Allow Multicast is enabled
	curStateEnabled           bool     // Firewall is enabled
	isPersistent              bool     // Firewall is persistent
)

func init() {
	allowedHosts = make(map[string]bool)
}

func implInitialize() error {
	return nil
}

func implGetEnabled() (bool, error) {
	// TODO FIXME: Vlad - rewrite, check for our chain existence
	exitCode, err := shell.ExecGetExitCode(nil, platform.FirewallScript(), "-status")
	return !(err != nil && exitCode != 0), nil
}

func doEnable() (err error) {
	prefs := getPrefsCallback()

	// Create filter table, if not present
	filter := nftConn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})

	// Create VPN coexistence chains
	vpnCoexistenceChainIn := nftConn.AddChain(&nftables.Chain{
		Name:     VPN_COEXISTENCE_CHAIN_IN,
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFirst, // our rules take top priority, are processed 1st
	})
	vpnCoexistenceChainOut := nftConn.AddChain(&nftables.Chain{
		Name:     VPN_COEXISTENCE_CHAIN_OUT,
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFirst, // our rules take top priority, are processed 1st
	})

	// create INPUT, OUTPUT chains
	inputChain := nftConn.AddChain(&nftables.Chain{
		Name:     "INPUT",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	outputChain := nftConn.AddChain(&nftables.Chain{
		Name:     "OUTPUT",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})
	// jump to our chains from the top of INPUT, OUTPUT
	nftConn.AddRule(&nftables.Rule{
		Position: 0,
		Table:    filter,
		Chain:    inputChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictKind(unix.NFT_JUMP),
				Chain: VPN_COEXISTENCE_CHAIN_IN,
			},
		},
	})
	nftConn.AddRule(&nftables.Rule{
		Position: 0,
		Table:    filter,
		Chain:    outputChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictKind(unix.NFT_JUMP),
				Chain: VPN_COEXISTENCE_CHAIN_OUT,
			},
		},
	})

	// create a set of Wireguard endpoint IPs, and a set of our DNS servers, incl. custom DNS
	wgEndpointAddrsIPv4 := &nftables.Set{
		Name:    "Wireguard endpoint IPv4 addresses",
		Table:   filter,
		KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses
	}
	privatelineDnsAddrsIPv4 := &nftables.Set{
		Name:    "privateLINE DNS",
		Table:   filter,
		KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses so far
	}
	if err := nftConn.AddSet(wgEndpointAddrsIPv4, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	if err := nftConn.AddSet(privatelineDnsAddrsIPv4, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
		nftConn.SetAddElements(wgEndpointAddrsIPv4, []nftables.SetElement{{Key: net.ParseIP(vpnEntryHost.EndpointIP)}})
		for _, dnsSrv := range strings.Split(vpnEntryHost.DnsServers, ",") {
			nftConn.SetAddElements(privatelineDnsAddrsIPv4, []nftables.SetElement{{Key: net.ParseIP(strings.TrimSpace(dnsSrv))}})
		}
	}
	if customDNS != nil && !net.IPv4zero.Equal(customDNS) {
		nftConn.SetAddElements(privatelineDnsAddrsIPv4, []nftables.SetElement{{Key: customDNS}})
	}

	// create a set of TCP & UDP protocols
	tcpAndUdp := &nftables.Set{
		Name:    "TCP & UDP inet protocol types",
		Table:   filter,
		KeyType: nftables.TypeInetProto, // protocol type is 1 byte
	}
	if err := nftConn.AddSet(tcpAndUdp, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	nftConn.SetAddElements(tcpAndUdp, []nftables.SetElement{{Key: []byte{unix.IPPROTO_TCP}}, {Key: []byte{unix.IPPROTO_UDP}}})

	// Create rules

	// TODO FIXME: Vlad - allow ICMP: allow echo request out, echo reply in, and bi-directional fragmentation messages
	//	- to/fro Wireguard endpoints
	//	- PL IP ranges

	// allow lo traffic
	lo := []byte("lo\x00")
	nftConn.AddRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	nftConn.AddRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept}},
	})

	// TODO FIXME: Vlad - apply on our interface wgprivateline, when it's up:
	//	ct state invalid drop
	//	ct state established,related accept
	//	allow meet.privateline.network, same as in firewall_windows.go
	//
	// wgprivateline := []byte("wgprivateline\x00")

	// Allow our Wireguard gateways: in UDP, out TCP+UDP (any proto)
	nftConn.AddRule(&nftables.Rule{ // in UDP
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			// [ lookup reg 1, set Wireguard endpoints whitelist ]
			&expr.Lookup{SourceRegister: 1, SetName: wgEndpointAddrsIPv4.Name, SetID: wgEndpointAddrsIPv4.ID},
			// [ meta load l4proto => reg 2 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
			// [ cmp eq reg 2 UDP ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	nftConn.AddRule(&nftables.Rule{ // out any proto
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		Exprs: []expr.Any{
			// [ dest IP: payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			// [ lookup reg 1, set Wireguard endpoints whitelist ]
			&expr.Lookup{SourceRegister: 1, SetName: wgEndpointAddrsIPv4.Name, SetID: wgEndpointAddrsIPv4.ID},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow TCP+UDP dst port 53 to our DNS servers, incl. custom DNS
	nftConn.AddRule(&nftables.Rule{ // out TCP+UDP, dst port 53
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ dest IP: payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			// [ lookup reg 1, set DNS servers whitelist ]
			&expr.Lookup{SourceRegister: 1, SetName: privatelineDnsAddrsIPv4.Name, SetID: privatelineDnsAddrsIPv4.ID},
			// [ meta load l4proto => reg 2 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
			// [ lookup reg 2, set tcpAndUdp whitelist ]
			&expr.Lookup{SourceRegister: 2, SetName: tcpAndUdp.Name, SetID: tcpAndUdp.ID},
			// [ dst port: payload load 2b @ transport header + 2 => reg 3 ]
			&expr.Payload{DestRegister: 3, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 3, Data: binaryutil.BigEndian.PutUint16(53)},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow UDP src port 53 from our DNS servers, incl. custom DNS
	nftConn.AddRule(&nftables.Rule{ // in UDP, src port 53
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			// [ lookup reg 1, set DNS servers whitelist ]
			&expr.Lookup{SourceRegister: 1, SetName: privatelineDnsAddrsIPv4.Name, SetID: privatelineDnsAddrsIPv4.ID},
			// [ meta load l4proto => reg 2 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
			// [ cmp eq reg 2 UDP ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
			// [ src port: payload load 2b @ transport header + 0 => reg 3 ]
			&expr.Payload{DestRegister: 3, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 3, Data: binaryutil.BigEndian.PutUint16(53)},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// TODO FIXME: Vlad - permit all apps outbound TCP+UDP traffic to PL IP ranges by default, until we re-implement App Whitelist

	// TODO FIXME: Vlad - allow PL service binaries in-out. Then we don't need to explicitly create allow rules for REST API servers, etc.
	// TODO FIXME: Vlad - also allow in-out for our other default allowed apps (PL Comms, etc.)
	// 	TODO: permit PL Comms etc. only inbound UDP
	allowedAppsCgroupClassid := 0x70561e1d

	// TODO FIXME: Vlad - replicate further rules from firewall_windows.go
	// ...

	// Apply the above (commands are queued till a call to Flush())
	if err := nftConn.Flush(); err != nil {
		return log.ErrorFE("enable - error nft flush: %w", err)
	}

	// To fulfill such flow (example): Connected -> FWDisable -> FWEnable
	// Here we should restore all exceptions (all hosts which are allowed)
	// return reApplyExceptions() // TODO FIXME: Vlad - refactor

	return err
}

// TODO FIXME: Vlad - flesh out
func doDisable() (err error) {
	return nil
}

func implSetEnabled(isEnabled, _ bool) error {
	curStateEnabled = isEnabled

	if isEnabled {
		return doEnable()
	} else { // TODO FIXME: Vlad - disable FW ...
		curAllowedLanIPs = nil // forget allowed LAN IP addresses
		isPersistent = false
		allowedForICMP = nil
	}

	return nil
}

func implSetPersistent(persistent bool) error {
	isPersistent = persistent
	if persistent {
		// The persistence is based on such facts:
		// 	- daemon is starting as on system boot
		// 	- SetPersistent() called by service object on daemon start
		// This means we just have to ensure that firewall enabled.

		// Just ensure that firewall is enabled
		ret := implSetEnabled(true, false)

		// Some Linux distributions erasing IVPN rules during system boot
		// During some period of time (60 seconds should be enough)
		// check if FW rules still exist (if not - re-apply them)
		go ensurePersistent(60)

		return ret
	}
	return nil
}

// Some Linux distributions erasing IVPN rules during system boot
// During some period of time (60 seconds should be enough)
// check if FW rules still exist (if not - re-apply them)
func ensurePersistent(secondsToWait int) {
	const delaySec = 5
	log.Info("[ensurePersistent] started")
	for i := 0; i <= secondsToWait/delaySec; i++ {
		time.Sleep(time.Second * delaySec)
		if !isPersistent {
			break
		}
		enabled, err := implGetEnabled()
		if err != nil {
			log.Error("[ensurePersistent] ", err)
			continue
		}
		if isPersistent && !enabled {
			log.Warning("[ensurePersistent] Persistent FW rules not available. Retry to apply...")
			implSetEnabled(true, false)
		}
	}
	log.Info("[ensurePersistent] stopped.")
}

// ClientConnected - allow communication for local vpn/client IP address
func implClientConnected(clientLocalIPAddress net.IP, clientLocalIPv6Address net.IP, clientPort int, serverIP net.IP, serverPort int, isTCP bool) error {
	inf, err := netinfo.InterfaceByIPAddr(clientLocalIPAddress)
	if err != nil {
		return fmt.Errorf("failed to get local interface by IP: %w", err)
	}

	protocol := "udp"
	if isTCP {
		protocol = "tcp"
	}
	scriptArgs := fmt.Sprintf("-connected %s %s %d %s %d %s",
		inf.Name,
		clientLocalIPAddress,
		clientPort,
		serverIP,
		serverPort,
		protocol)
	err = shell.Exec(nil, platform.FirewallScript(), scriptArgs)
	if err != nil {
		return fmt.Errorf("failed to add rule for current connection directions: %w", err)
	}

	// Connection already established. The rule for VPN interface is defined.
	// Removing host IP from exceptions
	return removeHostsFromExceptions([]string{serverIP.String()}, false, false)
}

// ClientDisconnected - Disable communication for local vpn/client IP address
func implClientDisconnected() error {
	// remove all exceptions related to current connection (all non-persistent exceptions)
	err := removeAllHostsFromExceptions()
	if err != nil {
		log.Error(err)
	}

	return shell.Exec(nil, platform.FirewallScript(), "-disconnected")
}

func implAllowLAN(isAllowLAN bool, isAllowLanMulticast bool) error {
	return doAllowLAN(isAllowLAN, isAllowLanMulticast)
}

func doAllowLAN(isAllowLAN, isAllowLanMulticast bool) error {
	mutexInternal.Lock()
	defer mutexInternal.Unlock()

	// save expected state of AllowLAN
	curStateAllowLAN = isAllowLAN
	curStateAllowLanMulticast = isAllowLanMulticast

	if isAllowLAN && !curStateEnabled {
		return nil // do nothing if firewall disabled
	}

	// constants
	const persistent = true
	const notOnlyForICMP = false

	// disallow everything (LAN + multicast)
	if len(curAllowedLanIPs) > 0 {
		if err := removeHostsFromExceptions(curAllowedLanIPs, persistent, notOnlyForICMP); err != nil {
			log.Warning("failed to erase 'Allow LAN' rules")
		}
	}
	curAllowedLanIPs = nil

	if !isAllowLAN {
		return nil // LAN NOT ALLOWED
	}

	// LAN ALLOWED

	// TODO: implement LAN access also for IPv6 addresses
	const ipV4 = false
	localRanges := ipNetListToStrings(filterIPNetList(netinfo.GetNonRoutableLocalAddrRanges(), ipV4))
	multicastRanges := ipNetListToStrings(filterIPNetList(netinfo.GetMulticastAddresses(), ipV4))

	curAllowedLanIPs = localRanges
	if isAllowLanMulticast {
		// allow LAN + multicast
		curAllowedLanIPs = append(curAllowedLanIPs, multicastRanges...)
	}

	// allow LAN
	return addHostsToExceptions(curAllowedLanIPs, persistent, notOnlyForICMP)
}

// implAddHostsToExceptions - allow communication with this hosts
// Note: if isPersistent == false -> all added hosts will be removed from exceptions after client disconnection (after call 'ClientDisconnected()')
// Arguments:
//   - IPs			-	list of IP addresses to ba allowed
//   - onlyForICMP	-	try add rule to allow only ICMP protocol for this IP
//   - isPersistent	-	keep rule enabled even if VPN disconnected
//
// NOTE! if (isPersistent==false and onlyForICMP==false) - this exceptions have highest priority (e.g. they will not be blocked by DNS restrictions of the FW)
func implAddHostsToExceptions(IPs []net.IP, onlyForICMP bool, isPersistent bool) error {
	IPsStr := make([]string, 0, len(IPs))
	for _, ip := range IPs {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			continue // we do not need localhost in exceptions
		}
		IPsStr = append(IPsStr, ip.String())
	}

	return addHostsToExceptions(IPsStr, isPersistent, onlyForICMP)
}

func implRemoveHostsFromExceptions(IPs []net.IP, onlyForICMP bool, isPersistent bool) error {
	IPsStr := make([]string, 0, len(IPs))
	for _, ip := range IPs {
		IPsStr = append(IPsStr, ip.String())
	}

	return removeHostsFromExceptions(IPsStr, isPersistent, onlyForICMP)
}

// OnChangeDNS - must be called on each DNS change (to update firewall rules according to new DNS configuration)
func implOnChangeDNS(addr net.IP) error {
	log.Info("implOnChangeDNS addr=" + addr.String())
	if addr.Equal(customDNS) {
		return nil
	}

	customDNS = addr

	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}
	if !enabled {
		return nil
	}

	return implReEnable() // TODO FIXME: Vlad - do we really need full reenable here? maybe just add the allow inbound rule for the new DNS srv?
}

// implOnUserExceptionsUpdated() called when 'userExceptions' value were updated. Necessary to update firewall rules.
func implOnUserExceptionsUpdated() error {

	applyFunc := func(isIpv4 bool) error {
		userExceptions := getUserExceptions(isIpv4, !isIpv4)

		var expMasks []string
		for _, mask := range userExceptions {
			expMasks = append(expMasks, mask.String())
		}

		scriptCommand := "-set_user_exceptions_static"
		if !isIpv4 {
			scriptCommand = "-set_user_exceptions_static_ipv6"
		}

		ipList := strings.Join(expMasks, ",")

		if len(ipList) > 250 {
			log.Info(scriptCommand, " <...multiple addresses...>")
		} else {
			log.Info(scriptCommand, " ", ipList)
		}

		return shell.Exec(nil, platform.FirewallScript(), scriptCommand, ipList)
	}

	err := applyFunc(false)
	errIpv6 := applyFunc(true)
	if err == nil && errIpv6 != nil {
		return errIpv6
	}
	return err
}

func implSingleDnsRuleOff() (retErr error) {
	return shell.Exec(log, platform.FirewallScript(), "-only_dns_off")
}

func implSingleDnsRuleOn(dnsAddr net.IP) (retErr error) {
	exceptions := ""
	if prioritized, _ := getAllowedIpExceptions(); len(prioritized) > 0 {
		exceptions = strings.Join(prioritized, ",")
	}

	return shell.Exec(log, platform.FirewallScript(), "-only_dns", dnsAddr.String(), exceptions)
}

//---------------------------------------------------------------------

func applyAddHostsToExceptions(hostsIPs []string, isPersistent bool, onlyForICMP bool) error {
	ipList := strings.Join(hostsIPs, ",")

	if len(ipList) > 0 {
		scriptCommand := "-add_exceptions"

		if onlyForICMP {
			scriptCommand = "-add_exceptions_icmp"
		} else if isPersistent {
			scriptCommand = "-add_exceptions_static"
		}

		if len(ipList) > 250 {
			log.Info(scriptCommand, " <...multiple addresses...>")
		} else {
			log.Info(scriptCommand, " ", ipList)
		}

		return shell.Exec(nil, platform.FirewallScript(), scriptCommand, ipList)
	}
	return nil
}

func applyRemoveHostsFromExceptions(hostsIPs []string, isPersistent bool, onlyForICMP bool) error {
	ipList := strings.Join(hostsIPs, ",")

	if len(ipList) > 0 {
		scriptCommand := "-remove_exceptions"

		if onlyForICMP {
			scriptCommand = "-remove_exceptions_icmp"
		} else if isPersistent {
			scriptCommand = "-remove_exceptions_static"
		}

		if len(ipList) > 250 {
			log.Info(scriptCommand, " <...multiple addresses...>")
		} else {
			log.Info(scriptCommand, " ", ipList)
		}

		return shell.Exec(nil, platform.FirewallScript(), scriptCommand, ipList)
	}
	return nil
}

func reApplyExceptions() error {
	// Allow LAN communication (if necessary)
	// Restore all exceptions (all hosts which are allowed)

	allowedIPs, allowedIPsPersistent := getAllowedIpExceptions()
	allowedIPsICMP := make([]string, 0, len(allowedForICMP))
	if len(allowedForICMP) > 0 {
		for ipStr := range allowedForICMP {
			allowedIPsICMP = append(allowedIPsICMP, ipStr)
		}
	}

	const persistentTRUE = true
	const persistentFALSE = false
	const onlyIcmpTRUE = true
	const onlyIcmpFALSE = false

	// define DNS rules
	err := implOnChangeDNS(getDnsIP())
	if err != nil {
		log.Error(err)
	}

	// Apply all allowed hosts
	err = applyAddHostsToExceptions(allowedIPsICMP, persistentFALSE, onlyIcmpTRUE)
	if err != nil {
		log.Error(err)
	}
	err = applyAddHostsToExceptions(allowedIPs, persistentFALSE, onlyIcmpFALSE)
	if err != nil {
		log.Error(err)
		return err
	}
	err = applyAddHostsToExceptions(allowedIPsPersistent, persistentTRUE, onlyIcmpFALSE)
	if err != nil {
		log.Error(err)
	}

	err = implAllowLAN(curStateAllowLAN, curStateAllowLanMulticast)
	if err != nil {
		log.Error(err)
	}

	err = implOnUserExceptionsUpdated()
	if err != nil {
		log.Error(err)
	}

	return err
}

//---------------------------------------------------------------------

// allow communication with specified hosts
// if isPersistent == false - exception will be removed when client disconnects
func addHostsToExceptions(IPs []string, isPersistent bool, onlyForICMP bool) error {
	if len(IPs) == 0 {
		return nil
	}

	newIPs := make([]string, 0, len(IPs))
	if !onlyForICMP {
		for _, ip := range IPs {
			// do not add new IP if it already in exceptions
			if _, exists := allowedHosts[ip]; !exists {
				allowedHosts[ip] = isPersistent // add to map
				newIPs = append(newIPs, ip)
			}
		}
	} else {
		if allowedForICMP == nil {
			allowedForICMP = make(map[string]struct{})
		}

		for _, ip := range IPs {
			// do not add new IP if it already in exceptions
			if _, exists := allowedForICMP[ip]; !exists {
				allowedForICMP[ip] = struct{}{} // add to map
				newIPs = append(newIPs, ip)
			}
		}
	}

	if len(newIPs) == 0 {
		return nil
	}

	err := applyAddHostsToExceptions(newIPs, isPersistent, onlyForICMP)
	if err != nil {
		log.Error(err)
	}
	return err
}

// Deprecate communication with this hosts
func removeHostsFromExceptions(IPs []string, isPersistent bool, onlyForICMP bool) error {
	if len(IPs) == 0 {
		return nil
	}

	toRemoveIPs := make([]string, 0, len(IPs))
	if !onlyForICMP {
		for _, ip := range IPs {
			if persVal, exists := allowedHosts[ip]; exists {
				if persVal != isPersistent {
					continue
				}
				delete(allowedHosts, ip) // remove from map
				toRemoveIPs = append(toRemoveIPs, ip)
			}
		}
	} else if allowedForICMP != nil {
		for _, ip := range IPs {
			if _, exists := allowedForICMP[ip]; exists {
				delete(allowedForICMP, ip) // remove from map
				toRemoveIPs = append(toRemoveIPs, ip)
			}
		}
	}

	if len(toRemoveIPs) == 0 {
		return nil
	}

	err := applyRemoveHostsFromExceptions(toRemoveIPs, isPersistent, onlyForICMP)
	if err != nil {
		log.Error(err)
	}
	return err
}

// removeAllHostsFromExceptions - Remove hosts (which are related to a current connection) from exceptions
// Note: some exceptions should stay without changes, they are marked as 'persistent'
//
//	(has 'true' value in allowedHosts; eg.: LAN and Multicast connectivity)
func removeAllHostsFromExceptions() error {
	toRemoveIPs := make([]string, 0, len(allowedHosts))
	for ipStr := range allowedHosts {
		toRemoveIPs = append(toRemoveIPs, ipStr)
	}
	isPersistent := false
	return removeHostsFromExceptions(toRemoveIPs, isPersistent, false)
}

//---------------------------------------------------------------------

func getAllowedIpExceptions() (prioritized, persistent []string) {
	prioritized = make([]string, 0, len(allowedHosts))
	persistent = make([]string, 0, len(allowedHosts))
	for ipStr, isPersistent := range allowedHosts {
		if isPersistent {
			persistent = append(persistent, ipStr)
		} else {
			prioritized = append(prioritized, ipStr)
		}
	}
	return prioritized, persistent
}

func getUserExceptions(ipv4, ipv6 bool) []net.IPNet {
	ret := []net.IPNet{}
	for _, e := range userExceptions {
		isIPv6 := e.IP.To4() == nil
		isIPv4 := !isIPv6

		if !(isIPv4 && ipv4) && !(isIPv6 && ipv6) {
			continue
		}

		ret = append(ret, e)
	}
	return ret
}

func implHaveTopFirewallPriority(recursionDepth uint8) (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	return true, "", "", "", nil
}

func implReregisterFirewallAtTopPriority(canStopOtherVpn bool) (retErr error) {
	return nil
}

func implDeployPostConnectionRules() (retErr error) {
	return nil
}

func implCleanupRegistration() (err error) {
	return nil
}

func implReEnable() (retErr error) {
	log.Info("implReEnable")

	if err := doDisable(); err != nil {
		return fmt.Errorf("failed to disable firewall: %w", err)
	}

	if err := doEnable(); err != nil {
		return fmt.Errorf("failed to enable firewall: %w", err)
	}

	return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
}

func implTotalShieldEnabled() bool {
	return false // TODO FIXME: Vlad - update
}

func implTotalShieldApply(_totalShieldEnabled bool) (err error) {
	return nil
}

// TODO FIXME: Vlad - flesh out
func doAddClientIPFilters(clientLocalIP net.IP, clientLocalIPv6 net.IP) (retErr error) {
	return nil
}

// TODO FIXME: Vlad - flesh out and check usage
func doRemoveClientIPFilters() (retErr error) {
	return nil
}
