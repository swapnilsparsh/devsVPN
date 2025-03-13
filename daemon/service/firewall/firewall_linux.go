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
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall/vpncoexistence"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/unix"
)

const (
	ENOENT_ERRMSG = "no such file or directory"

	TABLE      = "filter" // type IPv4
	TABLE_TYPE = nftables.TableFamilyIPv4

	VPN_COEXISTENCE_CHAIN_IN  = "privateline-vpn-coexistence-in"
	VPN_COEXISTENCE_CHAIN_OUT = "privateline-vpn-coexistence-out"

	PL_DNS_SET = "privateLINE_DNS"
)

var (
	mutexInternal                 sync.Mutex           // global lock for firewall read and write operations in firewall_linux.go
	stopMonitoringFirewallChanges = make(chan bool, 2) // used to send a stop signal to implFirewallBackgroundMonitor() thread
	// implReregisterFirewallAtTopPriorityMutex sync.Mutex           // to ensure there's only one instance of implReregisterFirewallAtTopPriority function
	implFirewallBackgroundMonitorMutex sync.Mutex // to ensure there's only one instance of implFirewallBackgroundMonitor function
	// implDeployPostConnectionRulesMutex sync.Mutex // to ensure there's only one instance of implDeployPostConnectionRules function

	nftMonitor *nftables.Monitor
	nftEvents  chan *nftables.MonitorEvents

	nftConn = &nftables.Conn{}
	ourSets []*nftables.Set // List of all our nft sets, to delete in one batch. Protected by mutexInternal.

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

func printTableFilter() {
	// TODO FIXME: /usr/sbin/nft list table ip filter
	outText, outErrText, exitCode, isBufferTooSmall, err := shell.ExecAndGetOutput(log, 32768, "", "/usr/sbin/nft", "list", "table", "ip", "filter")
	// trim trailing newlines
	outText = strings.TrimSuffix(outText, "\n")
	outErrText = strings.TrimSuffix(outErrText, "\n")
	log.Info("exitCode=", exitCode, ", isBufferTooSmall=", isBufferTooSmall, ", err=", err, "\n", outErrText, "\n", outText)
}

func init() {
	allowedHosts = make(map[string]bool)
}

func implInitialize() error {
	return nil
}
func createTableChainsObjects() (filter *nftables.Table,
	input *nftables.Chain,
	output *nftables.Chain,
	vpnCoexistenceChainIn *nftables.Chain,
	vpnCoexistenceChainOut *nftables.Chain) {

	filter = &nftables.Table{Family: TABLE_TYPE, Name: TABLE}

	return filter,
		&nftables.Chain{Name: "INPUT", Table: filter, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter},
		&nftables.Chain{Name: "OUTPUT", Table: filter, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter},
		&nftables.Chain{Name: VPN_COEXISTENCE_CHAIN_IN, Table: filter, Type: nftables.ChainTypeFilter},
		&nftables.Chain{Name: VPN_COEXISTENCE_CHAIN_OUT, Table: filter, Type: nftables.ChainTypeFilter}
}

func createTableAndChains() (filter *nftables.Table, vpnCoexistenceChainIn *nftables.Chain, vpnCoexistenceChainOut *nftables.Chain, err error) {
	filter, input, output, vpnCoexistenceChainIn, vpnCoexistenceChainOut := createTableChainsObjects()

	// Create filter table, if not present
	filter = nftConn.AddTable(filter)

	// create INPUT, OUTPUT chains, if not present
	input = nftConn.AddChain(input)
	output = nftConn.AddChain(output)

	// Create VPN coexistence chains
	vpnCoexistenceChainIn = nftConn.AddChain(vpnCoexistenceChainIn)
	vpnCoexistenceChainOut = nftConn.AddChain(vpnCoexistenceChainOut)

	// if err := nftConn.Flush(); err != nil { // Apply the above (commands are queued till a call to Flush())
	// 	return nil, nil, nil, log.ErrorFE("createTableAndChains - error nft flush 1: %w", err)
	// }

	// // get INPUT, OUTPUT rulesets - to be able to insert our jump rules on top
	// inputRules, err := nftConn.GetRules(filter, input)
	// if err != nil {
	// 	return nil, nil, nil, log.ErrorFE("error listing input rules: %w", err)
	// }
	// outputRules, err := nftConn.GetRules(filter, output)
	// if err != nil {
	// 	return nil, nil, nil, log.ErrorFE("error listing output rules: %w", err)
	// }

	// add rules to jump to our chains from the top of INPUT, OUTPUT
	jumpInRule := nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: VPN_COEXISTENCE_CHAIN_IN,
			},
		},
	}
	// if len(inputRules) >= 1 {
	// 	jumpInRule.Position = inputRules[0].Handle
	// }
	nftConn.InsertRule(&jumpInRule)

	jumpOutRule := nftables.Rule{
		Table: filter,
		Chain: output,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: VPN_COEXISTENCE_CHAIN_OUT,
			},
		},
	}
	// if len(outputRules) >= 1 {
	// 	jumpOutRule.Position = outputRules[0].Handle
	// }
	nftConn.InsertRule(&jumpOutRule)

	if err := nftConn.Flush(); err != nil { // Apply the above (commands are queued till a call to Flush())
		return nil, nil, nil, log.ErrorFE("createTableAndChains - error nft flush 2: %w", err)
	}

	return filter, vpnCoexistenceChainIn, vpnCoexistenceChainOut, nil
}

func implHaveTopFirewallPriority(recursionDepth uint8) (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	weHaveTopFirewallPriority, retErr = implGetEnabled()
	return weHaveTopFirewallPriority, "", "", "", retErr
}

func registerNftMonitor() (err error) {
	nftMonitor = nftables.NewMonitor(nftables.WithMonitorEventBuffer(20480)) // will be closed when implFirewallBackgroundMonitor() exits
	// TODO: Vlad - add filtering conditions? W/ conditions a single monitor can only monitor a single object, and/or a single action (add, del, etc.)

	if nftEvents, err = nftConn.AddGenerationalMonitor(nftMonitor); err != nil {
		return log.ErrorFE("error AddGenerationalMonitor: %w", err)
	}

	return nil
}

// implReregisterFirewallAtTopPriority - here we assume VPN connection is already established, so we include creation of all firewall objects, incl. post-connection
func implReregisterFirewallAtTopPriority(canStopOtherVpn bool) (firewallReconfigured bool, retErr error) {
	// to ensure there's only one instance of this function, and that no other read or write operations are taking place in parallel
	mutexInternal.Lock()
	defer mutexInternal.Unlock()

	// log.Debug("implReregisterFirewallAtTopPriority entered")
	// defer log.Debug("implReregisterFirewallAtTopPriority exited")

	if weHaveTopFirewallPriority, err := implGetEnabled(); err != nil {
		return false, log.ErrorFE("error in implGetEnabled(): %w", err)
	} else if weHaveTopFirewallPriority {
		return false, nil
	}

	// signal loss of top firewall priority to UI
	go onKillSwitchStateChangedCallback()

	log.Debug("implReregisterFirewallAtTopPriority - don't have top pri, need to reenable firewall")

	if err := implReEnable(true); err != nil {
		return true, log.ErrorFE("error in implReEnable: %w", err)
	}

	go implDeployPostConnectionRules(false) // forking in the background, as otherwise DNS timeouts are up to ~15 sec, they freeze UI changes

	return true, nil
}

func implFirewallBackgroundMonitorAvailable() bool {
	return true
}

// implFirewallBackgroundMonitor runs as a background thread, listens for nftable change events.
// If events are relevant - it checks whether we have top firewall priority. If don't have top pri - it recreates our firewall objects.
// To stop this thread - send to stopMonitoringFirewallChanges chan.
func implFirewallBackgroundMonitor() (err error) {
	implFirewallBackgroundMonitorMutex.Lock() // to ensure there's only one instance of implFirewallBackgroundMonitor
	defer implFirewallBackgroundMonitorMutex.Unlock()

	log.Debug("implFirewallBackgroundMonitor entered")
	defer log.Debug("implFirewallBackgroundMonitor exited")

	if err := registerNftMonitor(); err != nil { // start listening for nft events for the duration of the whole function
		return log.ErrorFE("error registerNftMonitor: %w", err)
	}
	defer nftMonitor.Close()

	runEnableCoexistenceWithOtherVpns := true
	var firewallReconfigured bool
	for {
		// Run VPN coexistence logic synchronously here, before processing nft events.
		// The reason is that VPN coexistence logic generates nft events itself, so we want to:
		//	- Run VPN coexistence logic first
		//	- Process buffered nft events later - and, if needed, run implReEnable() hopefully only once
		if runEnableCoexistenceWithOtherVpns {
			if err := vpncoexistence.EnableCoexistenceWithOtherVpns(getPrefsCallback()); err != nil {
				log.ErrorFE("error running EnableCoexistenceWithOtherVpns(): %w", err) // and continue
			}
			runEnableCoexistenceWithOtherVpns = false

			go onKillSwitchStateChangedCallback() // signal firewall status to UI
		}

		select {
		case _ = <-stopMonitoringFirewallChanges:
			log.Debug("implFirewallBackgroundMonitor exiting on stop signal")
			go vpncoexistence.DisableCoexistenceWithOtherVpns() // nah, run asynchronously in the background after all - 8sec is way too long to wait in the UI
			return nil
		case event, ok := <-nftEvents:
			if !ok {
				return log.ErrorFE("error - reading from nftEvents channel not ok, implFirewallBackgroundMonitor exiting")
			}

			if event != nil && event.GeneratedBy != nil && event.GeneratedBy.Data != nil &&
				reflect.TypeOf(event.GeneratedBy.Data) == reflect.TypeFor[*nftables.GenMsg]() {
				genMsg := event.GeneratedBy.Data.(*nftables.GenMsg)
				if strings.Contains(genMsg.ProcComm, "privateline-con") {
					continue // ignore our own firewall changes
				}
				// log.Debug("implFirewallBackgroundMonitor event generated by " + genMsg.ProcComm)
			}

			for _, change := range event.Changes {
				if change.Error != nil {
					return log.ErrorFE("nftMonitor event change error, implFirewallBackgroundMonitor exiting. err=%w", change.Error)
				}
				// log.Debug("implFirewallBackgroundMonitor event.Changes loop iteration")

				switch change.Type {
				case nftables.MonitorEventTypeNewRule:
					if firewallReconfigured, err = implReregisterFirewallAtTopPriority(false); err != nil {
						log.ErrorFE("error in implReregisterFirewallAtTopPriority(): %w", err) // and continue
					} else if firewallReconfigured {
						runEnableCoexistenceWithOtherVpns = true
					}

				case nftables.MonitorEventTypeDelRule:
					gotRule := change.Data.(*nftables.Rule)
					verdict, _ := gotRule.Exprs[0].(*expr.Verdict)
					if reflect.TypeOf(gotRule.Exprs[0]) == reflect.TypeFor[*expr.Verdict]() && verdict.Kind == expr.VerdictJump &&
						(verdict.Chain == VPN_COEXISTENCE_CHAIN_IN || verdict.Chain == VPN_COEXISTENCE_CHAIN_OUT) {
						if firewallReconfigured, err = implReregisterFirewallAtTopPriority(false); err != nil {
							log.ErrorFE("error in implReregisterFirewallAtTopPriority(): %w", err) // and continue
						} else if firewallReconfigured {
							runEnableCoexistenceWithOtherVpns = true
						}
					}

				case nftables.MonitorEventTypeDelChain:
					gotChain := change.Data.(*nftables.Chain)
					switch gotChain.Name {
					case "INPUT":
					case "OUTPUT":
					case VPN_COEXISTENCE_CHAIN_IN:
					case VPN_COEXISTENCE_CHAIN_OUT:
						if firewallReconfigured, err = implReregisterFirewallAtTopPriority(false); err != nil {
							log.ErrorFE("error in implReregisterFirewallAtTopPriority(): %w", err) // and continue
						} else if firewallReconfigured {
							runEnableCoexistenceWithOtherVpns = true
						}
					}

				case nftables.MonitorEventTypeDelTable:
					gotTable := change.Data.(*nftables.Table)
					if gotTable.Name == TABLE {
						if firewallReconfigured, err = implReregisterFirewallAtTopPriority(false); err != nil {
							log.ErrorFE("error in implReregisterFirewallAtTopPriority(): %w", err) // and continue
						} else if firewallReconfigured {
							runEnableCoexistenceWithOtherVpns = true
						}
					}
				}
			}
		}
	}
}

func implStopFirewallBackgroundMonitor() (mutex *sync.Mutex) {
	// must check whether implFirewallBackgroundMonitor() is actually running (it could've exited due to an error), else don't send to stopMonitoringFirewallChanges chan
	if !implFirewallBackgroundMonitorMutex.TryLock() {
		stopMonitoringFirewallChanges <- true     // send implFirewallBackgroundMonitor() a stop signal
		implFirewallBackgroundMonitorMutex.Lock() // wait for it to stop
	}

	return &implFirewallBackgroundMonitorMutex
}

// implGetEnabled needs to be fast, as it's called for every nft firewall change event
func implGetEnabled() (exists bool, retErr error) {
	filter, input, output, _, _ := createTableChainsObjects()

	// get INPUT, OUTPUT rulesets - to check that our jump rules are on top of INPUT, OUTPUT
	inputRules, err := nftConn.GetRules(filter, input)
	if err != nil {
		return false, log.ErrorFE("error listing INPUT rules: %w", err)
	}
	outputRules, err := nftConn.GetRules(filter, output)
	if err != nil {
		return false, log.ErrorFE("error listing OUTPUT rules: %w", err)
	}

	// check that the 0th rules in INPUT, OUTPUT are jumps to our chains
	if len(inputRules) >= 1 {
		verdict, _ := inputRules[0].Exprs[0].(*expr.Verdict)
		if reflect.TypeOf(inputRules[0].Exprs[0]) != reflect.TypeFor[*expr.Verdict]() || verdict.Kind != expr.VerdictJump || verdict.Chain != VPN_COEXISTENCE_CHAIN_IN {
			log.Debug("jump to our table " + VPN_COEXISTENCE_CHAIN_IN + " is not a 0th rule in INPUT")
			return false, nil
		}
	} else {
		log.Debug("INPUT chain empty or not found")
		return false, nil
	}

	if len(outputRules) >= 1 {
		verdict, _ := outputRules[0].Exprs[0].(*expr.Verdict)
		if reflect.TypeOf(outputRules[0].Exprs[0]) != reflect.TypeFor[*expr.Verdict]() || verdict.Kind != expr.VerdictJump || verdict.Chain != VPN_COEXISTENCE_CHAIN_OUT {
			log.Debug("jump to our table " + VPN_COEXISTENCE_CHAIN_OUT + " is not a 0th rule in OUTPUT")
			return false, nil
		}
	} else {
		log.Debug("OUTPUT chain empty or not found")
		return false, nil
	}

	// Check that our chains exist

	var coexChainInFound, coexChainOutFound bool
	chains, err := nftConn.ListChainsOfTableFamily(TABLE_TYPE)
	if err != nil {
		return false, log.ErrorFE("error listing chains: %w", err)
	}
	for _, chain := range chains {
		if chain.Name == VPN_COEXISTENCE_CHAIN_IN {
			coexChainInFound = true
		} else if chain.Name == VPN_COEXISTENCE_CHAIN_OUT {
			coexChainOutFound = true
		}
	}

	if !coexChainInFound {
		return false, log.ErrorE(errors.New("error - "+VPN_COEXISTENCE_CHAIN_IN+" chain not found in table "+filter.Name), 0)
	}
	if !coexChainOutFound {
		return false, log.ErrorE(errors.New("error - "+VPN_COEXISTENCE_CHAIN_OUT+" chain not found in table "+filter.Name), 0)
	}

	// // TODO: Also check that helper script returns true - that cgroup exists, etc.
	// if exitCode, err := shell.ExecGetExitCode(nil, platform.FirewallScript(), "test"); err != nil {
	// 	return false, log.ErrorFE("error running '%s test': %w", platform.FirewallScript(), err)
	// } else if exitCode != 0 {
	// 	return false, log.ErrorFE("error - '%s test' exit code = %d", platform.FirewallScript(), exitCode)
	// }

	return true, nil
}

func implReEnable(internalMutexGrabbed bool) (retErr error) {
	if !internalMutexGrabbed {
		mutexInternal.Lock()
		defer mutexInternal.Unlock()
	}

	log.Debug("implReEnable")
	// log.Debug("implReEnable entered")
	// defer log.Debug("implReEnable exited")

	if err := doDisable(true); err != nil {
		return log.ErrorFE("failed to disable firewall: %w", err)
	}

	if err := doEnable(true); err != nil {
		return log.ErrorFE("failed to enable firewall: %w", err)
	}

	return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
}

func doEnable(internalMutexGrabbed bool) (err error) {
	if !internalMutexGrabbed {
		mutexInternal.Lock()
		defer mutexInternal.Unlock()
	}

	log.Debug("doEnable entered")
	defer log.Debug("doEnable exited")

	// if !implFirewallBackgroundMonitorMutex.TryLock() { // if TryLock() failed - then instance of implFirewallBackgroundMonitor() is already running, must stop it
	// 	stopMonitoringFirewallChanges <- true     // send implFirewallBackgroundMonitor() a stop signal
	// 	implFirewallBackgroundMonitorMutex.Lock() // wait for it to stop, lock its mutex till the end of doEnable()
	// }
	// defer implFirewallBackgroundMonitorMutex.Unlock() // release its mutex unconditionally at the end of doEnable()

	if exitCode, err := shell.ExecGetExitCode(nil, platform.FirewallScript(), "start"); err != nil {
		return log.ErrorFE("error initializing firewall script: %w", err)
	} else if exitCode != 0 {
		return log.ErrorE(fmt.Errorf("error initializing firewall script - exit code %d", exitCode), 0)
	}

	prefs := getPrefsCallback()

	filter, vpnCoexistenceChainIn, vpnCoexistenceChainOut, err := createTableAndChains()
	if err != nil {
		return log.ErrorFE("error createTableAndChains: %w", err)
	}

	// create a set of Wireguard endpoint IPs, and a set of our DNS servers, incl. custom DNS
	wgEndpointAddrsIPv4 := &nftables.Set{
		Name:    "Wireguard_endpoint_IPv4_addrs",
		Table:   filter,
		KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses
	}
	if err := nftConn.AddSet(wgEndpointAddrsIPv4, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	ourSets = append(ourSets, wgEndpointAddrsIPv4)

	privatelineDnsAddrsIPv4 := &nftables.Set{
		Name:    PL_DNS_SET,
		Table:   filter,
		KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses so far
		Dynamic: true,                // allow additions-deletions
	}
	if err := nftConn.AddSet(privatelineDnsAddrsIPv4, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	ourSets = append(ourSets, privatelineDnsAddrsIPv4)

	for _, vpnEntryHostParsed := range prefs.VpnEntryHostsParsed {
		if err = nftConn.SetAddElements(wgEndpointAddrsIPv4, []nftables.SetElement{{Key: vpnEntryHostParsed.VpnEntryHostIP}}); err != nil {
			return log.ErrorFE("enable - error adding vpnEntryHostParsed.VpnEntryHostIP to set: %w", err)
		}
		for _, dnsSrv := range vpnEntryHostParsed.DnsServersIPv4 {
			if err = nftConn.SetAddElements(privatelineDnsAddrsIPv4, []nftables.SetElement{{Key: dnsSrv}}); err != nil {
				return log.ErrorFE("enable - error adding dnsSrv to set: %w", err)
			}
		}
	}

	if customDNS != nil && !net.IPv4zero.Equal(customDNS) {
		nftConn.SetAddElements(privatelineDnsAddrsIPv4, []nftables.SetElement{{Key: customDNS.To4()}})
	}

	// create a set of TCP & UDP protocols
	tcpAndUdp := &nftables.Set{
		Name:    "TCP_UDP",
		Table:   filter,
		KeyType: nftables.TypeInetProto, // protocol type is 1 byte
	}
	if err := nftConn.AddSet(tcpAndUdp, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	ourSets = append(ourSets, tcpAndUdp)
	nftConn.SetAddElements(tcpAndUdp, []nftables.SetElement{{Key: []byte{unix.IPPROTO_TCP}}, {Key: []byte{unix.IPPROTO_UDP}}})

	// Create rules

	// TODO: Vlad - allow ICMP: allow echo request out, echo reply in, and bi-directional fragmentation messages
	//	- to/fro Wireguard endpoints
	//	- PL IP ranges
	//
	//	? Maybe not necessary to create allow rules explicitly? Connmark established,related allows pinging many (but not all) PL internal hosts.

	// Allow our Wireguard gateways: in UDP and established+related, out TCP+UDP (any proto)
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
			&expr.Counter{},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	nftConn.AddRule(&nftables.Rule{ // in established+related
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			// [ lookup reg 1, set Wireguard endpoints whitelist ]
			&expr.Lookup{SourceRegister: 1, SetName: wgEndpointAddrsIPv4.Name, SetID: wgEndpointAddrsIPv4.ID},
			&expr.Ct{Register: 2, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 2,
				DestRegister:   2,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 2, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
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
			&expr.Counter{},
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
			&expr.Counter{},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow TCP+UDP dst port 53 to our DNS servers, incl. custom DNS
	nftConn.AddRule(&nftables.Rule{ // out TCP+UDP, dst port 53
		Table: filter,
		Chain: vpnCoexistenceChainOut,
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
			&expr.Counter{},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// TODO: Vlad - permit all apps in UDP, out TCP+UDP (any proto) with PL IP ranges by default, until we re-implement App Whitelist
	//	"related, established" will take care of TCP inbound packets
	for _, vpnEntryHostParsed := range prefs.VpnEntryHostsParsed {
		for _, allowedNet := range vpnEntryHostParsed.AllowedIPs {
			nftConn.AddRule(&nftables.Rule{ // in UDP
				Table: filter,
				Chain: vpnCoexistenceChainIn,
				Exprs: []expr.Any{
					// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
					// By specifying Xor to 0x0,0x0,0x0,0x0 and Mask to the CIDR mask, the rule will match the CIDR of the IP (e.g in this case 10.0.0.0/24).
					&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Xor: []byte{0x0, 0x0, 0x0, 0x0}, Mask: allowedNet.Netmask.To4()},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: allowedNet.IP.To4()},
					// [ meta load l4proto => reg 2 ]
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
					// [ cmp eq reg 2 UDP ]
					&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
			nftConn.AddRule(&nftables.Rule{ // out any proto
				Table: filter,
				Chain: vpnCoexistenceChainOut,
				Exprs: []expr.Any{
					// [ dst IP: payload load 4b @ network header + 16 => reg 1 ]
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
					// By specifying Xor to 0x0,0x0,0x0,0x0 and Mask to the CIDR mask, the rule will match the CIDR of the IP (e.g in this case 10.0.0.0/24).
					&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Xor: []byte{0x0, 0x0, 0x0, 0x0}, Mask: allowedNet.Netmask.To4()},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: allowedNet.IP.To4()},
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}
	}

	// allow PL service binaries in-out. Then we don't need to explicitly create allow rules for REST API servers, etc.
	// also allow in-out for our other default allowed apps (PL Comms, etc.)
	// 	TODO: permit PL Comms etc. only inbound UDP
	allowedAppsCgroupClassid := []byte{0x1d, 0x1e, 0x56, 0x70} // have to list bytes in reverse order here, x86 is little-endian
	nftConn.AddRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ meta load cgroup ID => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyCGROUP, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: allowedAppsCgroupClassid},
			&expr.Counter{},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	nftConn.AddRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		Exprs: []expr.Any{
			// [ meta load cgroup ID => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyCGROUP, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: allowedAppsCgroupClassid},
			&expr.Counter{},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept}},
	})

	// if err := nftConn.Flush(); err != nil { // preliminary flush
	// 	return log.ErrorFE("doEnable - error nft flush 1: %w", err)
	// }

	// create rules for wgprivateline interface - even if it doesn't exist yet
	wgprivateline := []byte("wgprivateline\x00")

	// vpnCoexistenceChainInRules, err := nftConn.GetRules(filter, vpnCoexistenceChainIn)
	// if err != nil {
	// 	return log.ErrorFE("error listing vpnCoexistenceChainIn rules: %w", err)
	// }
	// vpnCoexistenceChainOutRules, err := nftConn.GetRules(filter, vpnCoexistenceChainOut)
	// if err != nil {
	// 	return log.ErrorFE("error listing vpnCoexistenceChainOut rules: %w", err)
	// }

	// conntrack state established,related accept on input on interface wgprivateline
	nftConn.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		// Position: vpnCoexistenceChainInRules[0].Handle,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgprivateline},
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// conttrack state invalid drop on input on interface wgprivateline
	nftConn.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		// Position: vpnCoexistenceChainInRules[0].Handle,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgprivateline},
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// conntrack state established accept on output on interface wgprivateline
	nftConn.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		// Position: vpnCoexistenceChainOutRules[0].Handle,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgprivateline},
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// allow lo traffic
	lo := []byte("lo\x00")
	nftConn.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ meta load iif => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	nftConn.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		Exprs: []expr.Any{
			// [ meta load iif => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept}},
	})

	if totalShieldEnabled && vpnConnectedCallback() { // add DROP rules at the end of our chains; enable Total Shield blocks only if VPN is connected or connecting
		log.Debug("doEnable: enabling TotalShield")
		nftConn.AddRule(&nftables.Rule{Table: filter, Chain: vpnCoexistenceChainIn, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
		nftConn.AddRule(&nftables.Rule{Table: filter, Chain: vpnCoexistenceChainOut, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
	}

	if err := nftConn.Flush(); err != nil {
		return log.ErrorFE("doEnable - error nft flush 2: %w", err)
	}

	// log.Debug("doEnable flushed")
	// printTableFilter()

	// TODO: Vlad - replicate further rules from firewall_windows.go as needed

	// To fulfill such flow (example): Connected -> FWDisable -> FWEnable
	// Here we should restore all exceptions (all hosts which are allowed)
	// return reApplyExceptions() // TODO FIXME: Vlad - refactor

	// Fork the task to check that we have top firewall priority and to keep on re-grabbing it as needed. Must be a single instance.
	// By now we have a lock on implFirewallBackgroundMonitorMutex
	//go implFirewallBackgroundMonitor() // TODO FIXME: Vlad - disabled here

	go onKillSwitchStateChangedCallback() // signal firewall status to UI

	return err
}

// Rules to add after VPN is connected:
//
//	allow meet.privateline.network, same as in firewall_windows.go
//
//	have to insert post-rules on top of our chains, otherwise they'd interfere with DROP rules at the end of our chains
//
// TODO: Vlad - do we need to worry about forward chains?
func implDeployPostConnectionRules(internalMutexGrabbed bool) (retErr error) {
	if !internalMutexGrabbed {
		mutexInternal.Lock()
		defer mutexInternal.Unlock()
	}

	// implDeployPostConnectionRulesMutex.Lock() // ensure only one instance of this func can run at a time
	// defer implDeployPostConnectionRulesMutex.Unlock()

	// log.Debug("implDeployPostConnectionRules entered")
	// defer log.Debug("implDeployPostConnectionRules exited")

	if firewallEnabled, err := implGetEnabled(); err != nil {
		return log.ErrorFE("status check error: %w", err)
	} else if !firewallEnabled || !vpnConnectedCallback() {
		return nil // our tables not up or VPN not connected/connecting, so skipping
	}

	filter, _, _, vpnCoexistenceChainIn, _ := createTableChainsObjects()

	// Allow our hosts (meet.privateline.network, etc.) in: UDP
	for _, plInternalHostname := range platform.PLInternalHostnamesToAcceptIncomingUdpFrom() {
		var (
			IPs            []net.IP
			ourHostIPsIPv4 = &nftables.Set{
				Name:    "privateLINE_allow_incoming_IPv4_UDP_for_" + plInternalHostname,
				Table:   filter,
				KeyType: nftables.TypeIPAddr, // set for IPv4 addresses
				Dynamic: true,                // allow additions-deletions
			}
			// ourHostIPsIPv6 = &nftables.Set{
			// 	Name:    "Allow incoming IPv6 UDP for " + plInternalHostname,
			// 	Table:   filter,
			// 	KeyType: nftables.TypeIP6Addr, // set for IPv6 addresses
			//	Dynamic: true,                // allow additions-deletions
			// }
		)

		// Check whether the set for a given hostname already exists - if so, assume the rules exist also
		if existingSet, err := nftConn.GetSetByName(filter, ourHostIPsIPv4.Name); err != nil {
			if !strings.Contains(err.Error(), ENOENT_ERRMSG) {
				return log.ErrorFE("error nftConn.GetSetByName(filter, %s): %w", ourHostIPsIPv4.Name, err)
			}
		} else if existingSet != nil {
			// log.Debug("set ", ourHostIPsIPv4.Name, " already exists, not adding new entries or rules")
			continue
		}

		if IPs, retErr = net.LookupIP(plInternalHostname); retErr != nil {
			retErr = log.ErrorFE("could not lookup IPs for '%s': %w", plInternalHostname, retErr)
			continue
		} else if len(IPs) == 0 {
			retErr = log.ErrorFE("no IPs returned for '%s'", plInternalHostname)
			continue
		}

		if err := nftConn.AddSet(ourHostIPsIPv4, []nftables.SetElement{}); err != nil {
			return log.ErrorFE("implDeployPostConnectionRules - error creating nft set: %w", err)
		}
		ourSets = append(ourSets, ourHostIPsIPv4)
		// if err := nftConn.AddSet(ourHostIPsIPv6, []nftables.SetElement{}); err != nil {
		// 	return log.ErrorFE("implDeployPostConnectionRules - error creating nft set: %w", err)
		// }
		// ourSets = append(ourSets, ourHostIPsIPv6)

		for _, IP := range IPs { // add IPs for this hostname to set
			if IP.To4() != nil { // IPv4
				log.Info("IPv4 UDP: allow remote hostname ", plInternalHostname, " at ", IP.String())
				if err := nftConn.SetAddElements(ourHostIPsIPv4, []nftables.SetElement{{Key: IP.To4()}}); err != nil {
					return log.ErrorFE("enable - error adding IPv4 addr %s for '%s' to set: %w", IP.String(), plInternalHostname, err)
				}
				// } else { // IPv6
				// log.Info("IPv6 UDP: allow remote hostname ", plInternalHostname, " at ", IP.String())
				// 	if err := nftConn.SetAddElements(ourHostIPsIPv6, []nftables.SetElement{{Key: IP}}); err != nil {
				//		return log.ErrorFE("enable - error adding IPv6 addr %s for '%s' to set: %w", IP.String(), plInternalHostname, err)
				// 	}
			}
		}

		// in UDP
		nftConn.InsertRule(&nftables.Rule{ // IPv4
			Table: filter,
			Chain: vpnCoexistenceChainIn,
			Exprs: []expr.Any{
				// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				// [ lookup reg 1, ourHostIPsIPv4 set ]
				&expr.Lookup{SourceRegister: 1, SetName: ourHostIPsIPv4.Name, SetID: ourHostIPsIPv4.ID},
				// [ meta load l4proto => reg 2 ]
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
				// [ cmp eq reg 2 UDP ]
				&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Counter{},
				//[ immediate reg 0 accept ]
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		// nftConn.InsertRule(&nftables.Rule{ // IPv6
		// 	Table: filter,
		// 	Chain: vpnCoexistenceChainIn,
		// 	Exprs: []expr.Any{
		// 		// [ src IPv6 addr: payload load 16b @ network header + 8 => reg 1 ]
		// 		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
		// 		// [ lookup reg 1, ourHostIPsIPv6 set ]
		// 		&expr.Lookup{SourceRegister: 1, SetName: ourHostIPsIPv6.Name, SetID: ourHostIPsIPv6.ID},
		// 		// [ meta load l4proto => reg 2 ]
		// 		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
		// 		// [ cmp eq reg 2 UDP ]
		// 		&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
		// 		&expr.Counter{},
		// 		//[ immediate reg 0 accept ]
		// 		&expr.Verdict{Kind: expr.VerdictAccept},
		// 	},
		// })
	}

	if err := nftConn.Flush(); err != nil {
		return log.ErrorFE("implDeployPostConnectionRules - error: %w", err)
	}

	return retErr
}

func doDisable(internalMutexGrabbed bool) (err error) {
	if !internalMutexGrabbed {
		mutexInternal.Lock()
		defer mutexInternal.Unlock()
	}

	log.Debug("doDisable entered")
	defer log.Debug("doDisable exited")

	// if !implFirewallBackgroundMonitorMutex.TryLock() { // if TryLock() failed - then instance of implFirewallBackgroundMonitor() is already running
	// 	stopMonitoringFirewallChanges <- true     // send implFirewallBackgroundMonitor() a stop signal
	// 	implFirewallBackgroundMonitorMutex.Lock() // wait for it to stop, lock its mutex till the end of doDisable()
	// }
	// defer implFirewallBackgroundMonitorMutex.Unlock() // release its lock unconditionally after doDisable() exit

	// TODO: Vlad - wrap down our configuration changes we did to other VPNs, when needed

	filter, input, output, vpnCoexistenceChainIn, vpnCoexistenceChainOut := createTableChainsObjects()

	// get INPUT, OUTPUT rulesets - to delete our jump rules
	inputRules, err := nftConn.GetRules(filter, input)
	if err != nil {
		return log.ErrorFE("error listing input rules: %w", err)
	}
	outputRules, err := nftConn.GetRules(filter, output)
	if err != nil {
		return log.ErrorFE("error listing output rules: %w", err)
	}

	for _, inRule := range inputRules {
		if reflect.TypeOf(inRule.Exprs[0]) != reflect.TypeFor[*expr.Verdict]() {
			continue
		}
		verdict, _ := inRule.Exprs[0].(*expr.Verdict)
		if verdict.Kind == expr.VerdictJump && verdict.Chain == VPN_COEXISTENCE_CHAIN_IN {
			if err = nftConn.DelRule(inRule); err != nil {
				log.Debug(fmt.Errorf("error deleting jump rule in input: %w", err))
			}

		}
	}

	for _, outRule := range outputRules {
		if reflect.TypeOf(outRule.Exprs[0]) != reflect.TypeFor[*expr.Verdict]() {
			continue
		}
		verdict, _ := outRule.Exprs[0].(*expr.Verdict)
		if verdict.Kind == expr.VerdictJump && verdict.Chain == VPN_COEXISTENCE_CHAIN_OUT {
			if err = nftConn.DelRule(outRule); err != nil {
				log.Debug(fmt.Errorf("error deleting jump rule in output: %w", err))
			}
		}
	}

	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		return log.ErrorFE("error during flush 1 in doDisable: %w", err)
	}

	// drop our chains
	nftConn.FlushChain(vpnCoexistenceChainIn)
	nftConn.DelChain(vpnCoexistenceChainIn)
	nftConn.FlushChain(vpnCoexistenceChainOut)
	nftConn.DelChain(vpnCoexistenceChainOut)

	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		return log.ErrorFE("error during flush 2 in doDisable: %w", err)
	}

	// drop our sets
	for _, ourSet := range ourSets {
		// log.Debug("flushing set ", ourSet.Name)
		nftConn.FlushSet(ourSet)
	}
	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		return log.ErrorFE("error during flush 3 in doDisable: %w", err)
	}

	for _, ourSet := range ourSets {
		// log.Debug("deleting set ", ourSet.Name)
		nftConn.DelSet(ourSet)
	}
	ourSets = []*nftables.Set{}

	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) { // yes, need to flush multiple times to erase everything
		return log.ErrorFE("error during flush 4 in doDisable: %w", err)
	}
	// log.Debug("doDisable flushed")
	// printTableFilter()

	return nil
}

func implSetEnabled(isEnabled, _ bool) error {
	log.Debug("implSetEnabled: ", isEnabled)

	curStateEnabled = isEnabled

	if isEnabled {
		return doEnable(false)
	} else { // TODO FIXME: Vlad - refactor
		curAllowedLanIPs = nil // forget allowed LAN IP addresses
		isPersistent = false
		allowedForICMP = nil

		return doDisable(false)
	}
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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
// If addr is not nil, non-zero, and different from previous customDNS - just add the new DNS to privateLINE_DNS set
func implOnChangeDNS(addr net.IP) (err error) {
	log.Info("implOnChangeDNS addr=" + addr.String())
	if addr == nil || addr.Equal(customDNS) || net.IPv4zero.Equal(addr) {
		return nil
	}

	customDNS = addr

	if enabled, err := implGetEnabled(); err != nil {
		return log.ErrorFE("failed to get info if firewall is on: %w", err)
	} else if !enabled {
		return nil
	}

	// just add the new DNS srv to privateLINE_DNS set
	mutexInternal.Lock()
	defer mutexInternal.Unlock()

	filter := &nftables.Table{Family: TABLE_TYPE, Name: TABLE}

	privatelineDnsAddrsIPv4, err := nftConn.GetSetByName(filter, PL_DNS_SET)
	if err != nil || privatelineDnsAddrsIPv4 == nil {
		return log.ErrorFE("error GetSetByName(filter, %s): %w", PL_DNS_SET, err)
	}
	nftConn.SetAddElements(privatelineDnsAddrsIPv4, []nftables.SetElement{{Key: customDNS.To4()}})

	if err := nftConn.Flush(); err != nil {
		return log.ErrorFE("implOnChangeDNS - error nft flush: %w", err)
	}

	return nil
}

// implOnUserExceptionsUpdated() called when 'userExceptions' value were updated. Necessary to update firewall rules.
func implOnUserExceptionsUpdated() error {
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

	return shell.Exec(log, platform.FirewallScript(), "-only_dns_off")
}

func implSingleDnsRuleOn(dnsAddr net.IP) (retErr error) {
	// TODO FIXME: Vlad - stubbing out for now
	return nil

	exceptions := ""
	if prioritized, _ := getAllowedIpExceptions(); len(prioritized) > 0 {
		exceptions = strings.Join(prioritized, ",")
	}

	return shell.Exec(log, platform.FirewallScript(), "-only_dns", dnsAddr.String(), exceptions)
}

//---------------------------------------------------------------------

func applyAddHostsToExceptions(hostsIPs []string, isPersistent bool, onlyForICMP bool) error {
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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

func implCleanupRegistration() (err error) {
	return doDisable(false)
}

func implTotalShieldApply(_totalShieldEnabled bool) (err error) {
	mutexInternal.Lock()
	defer mutexInternal.Unlock()

	if totalShieldEnabled == _totalShieldEnabled {
		return nil
	}

	if firewallEnabled, err := implGetEnabled(); err != nil {
		return log.ErrorFE("status check error: %w", err)
	} else if !firewallEnabled {
		log.Debug("implTotalShieldApply: saving TotalShield=", _totalShieldEnabled, " in settings")
		totalShieldEnabled = _totalShieldEnabled
		return nil
	}

	// if the firewall is up - gotta add or remove DROP rules to reflect new Total Shield setting

	filter, _, _, vpnCoexistenceChainIn, vpnCoexistenceChainOut := createTableChainsObjects()
	vpnCoexistenceChainInRules, err := nftConn.GetRules(filter, vpnCoexistenceChainIn)
	if err != nil {
		return log.ErrorFE("error listing vpnCoexistenceChainIn rules: %w", err)
	}
	vpnCoexistenceChainOutRules, err := nftConn.GetRules(filter, vpnCoexistenceChainOut)
	if err != nil {
		return log.ErrorFE("error listing vpnCoexistenceChainOut rules: %w", err)
	}

	var (
		lastInRule, lastOutRule                      *nftables.Rule
		lastInRuleIsDrop, lastOutRuleIsDrop, doFlush bool
	)

	if len(vpnCoexistenceChainInRules) >= 1 {
		lastInRule = vpnCoexistenceChainInRules[len(vpnCoexistenceChainInRules)-1]
		if len(lastInRule.Exprs) >= 1 {
			verdict, _ := lastInRule.Exprs[1].(*expr.Verdict)
			if reflect.TypeOf(lastInRule.Exprs[1]) == reflect.TypeFor[*expr.Verdict]() && verdict.Kind == expr.VerdictDrop {
				lastInRuleIsDrop = true
			}
		}
	}

	if len(vpnCoexistenceChainOutRules) >= 1 {
		lastOutRule = vpnCoexistenceChainOutRules[len(vpnCoexistenceChainOutRules)-1]
		if len(lastOutRule.Exprs) >= 1 {
			verdict, _ := lastOutRule.Exprs[1].(*expr.Verdict)
			if reflect.TypeOf(lastOutRule.Exprs[1]) == reflect.TypeFor[*expr.Verdict]() && verdict.Kind == expr.VerdictDrop {
				lastOutRuleIsDrop = true
			}
		}
	}

	toEnableTotalShield := _totalShieldEnabled && vpnConnectedCallback() // Enable Total Shield DROP rules only if VPN is connected or connecting
	if toEnableTotalShield {
		if !lastInRuleIsDrop { // if last rules are not DROP rules already - append DROP rules to the end
			nftConn.AddRule(&nftables.Rule{Table: filter, Chain: vpnCoexistenceChainIn, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
			doFlush = true
		}
		if !lastOutRuleIsDrop {
			nftConn.AddRule(&nftables.Rule{Table: filter, Chain: vpnCoexistenceChainOut, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
			doFlush = true
		}
	} else { // Disable Total Shield in the firewall. If the last rules are DROP rules - delete them.
		if lastInRuleIsDrop {
			nftConn.DelRule(lastInRule)
			doFlush = true
		}
		if lastOutRuleIsDrop {
			nftConn.DelRule(lastOutRule)
			doFlush = true
		}
	}

	if doFlush {
		log.Debug("implTotalShieldApply: setting TotalShield=", toEnableTotalShield, " in firewall")
		if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
			return log.ErrorFE("nft flush error in implTotalShieldApply: %w", err)
		}
	}

	totalShieldEnabled = _totalShieldEnabled
	return nil
}

// TODO FIXME: Vlad - flesh out. Do we need this?... we always allow localhost traffic (lo interface)
func doAddClientIPFilters(clientLocalIP net.IP, clientLocalIPv6 net.IP) (retErr error) {
	return nil
}
func doRemoveClientIPFilters() (retErr error) {
	return nil
}
