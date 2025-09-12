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

// Here we have Linux firewall logic for nftables firewall interface

package firewall

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/unix"
)

const (
	TABLE      = "filter" // type IPv4
	TABLE_TYPE = nftables.TableFamilyIPv4

	PL_DNS_SET                   = "privateLINE_DNS"
	PL_INTERNAL_HOSTS_SET_PREFIX = "privateLINE_allow_incoming_IPv4_UDP_for_"

	VPN_COEXISTENCE_CHAIN_NFT_IN  = VPN_COEXISTENCE_CHAIN_PREFIX + "-nft-in"
	VPN_COEXISTENCE_CHAIN_NFT_OUT = VPN_COEXISTENCE_CHAIN_PREFIX + "-nft-out"
)

var (
	fwLinuxNftablesMutex             sync.Mutex           // global lock for firewall_linux_nftables read and write operations
	stopMonitoringFirewallChangesNft = make(chan bool, 1) // used to send a stop signal to implFirewallBackgroundMonitorNft() thread
	// implReregisterFirewallAtTopPriorityNftMutex sync.Mutex           // to ensure there's only one instance of implReregisterFirewallAtTopPriorityNft function
	implFirewallBackgroundMonitorNftRunningMutex  sync.Mutex // to ensure there's only one instance of implFirewallBackgroundMonitorNft function
	implFirewallBackgroundMonitorNftStopFuncMutex sync.Mutex // to ensure there's only one instance of StopFirewallBackgroundMonitor function for this instance

	perVpnNftEventsHelperMutex sync.Mutex // mutex for helpers for particular VPNs

	nftMonitor *nftables.Monitor
	nftEvents  chan *nftables.MonitorEvents

	nftConn = &nftables.Conn{}
	ourSets []*nftables.Set // List of all our nft sets, to delete in one batch. Protected by fwLinuxNftablesMutex.
)

func implInitializeNft() error {
	return nil
}

func printNftToLog() {
	if isDaemonStoppingCallback() {
		return
	}

	// outText, outErrText, exitCode, isBufferTooSmall, err := shell.ExecAndGetOutput(log, 32768, "", "/usr/sbin/nft", "list", "table", "ip", "filter")
	outText, outErrText, exitCode, isBufferTooSmall, err := shell.ExecAndGetOutput(log, 32768, "", "/usr/sbin/nft", "list", "ruleset")

	// trim trailing newlines
	outText = strings.TrimSuffix(outText, "\n")
	outErrText = strings.TrimSuffix(outErrText, "\n")
	log.Info("exitCode=", exitCode, ", isBufferTooSmall=", isBufferTooSmall, ", err=", err, "\n", outErrText, "\n", outText)
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
		&nftables.Chain{Name: VPN_COEXISTENCE_CHAIN_NFT_IN, Table: filter, Type: nftables.ChainTypeFilter},
		&nftables.Chain{Name: VPN_COEXISTENCE_CHAIN_NFT_OUT, Table: filter, Type: nftables.ChainTypeFilter}
}

func createTableAndChains() (filter *nftables.Table, vpnCoexistenceChainIn *nftables.Chain, vpnCoexistenceChainOut *nftables.Chain, err error) {
	if isDaemonStoppingCallback() {
		return nil, nil, nil, log.ErrorFE("error - daemon is stopping")
	}

	filter, input, output, vpnCoexistenceChainIn, vpnCoexistenceChainOut := createTableChainsObjects()

	// Create filter table, if not present
	filter = nftConn.AddTable(filter)

	// create INPUT, OUTPUT chains, if not present
	input = nftConn.AddChain(input)
	output = nftConn.AddChain(output)

	if err := nftConn.Flush(); err != nil { // creating INPUT, OUTPUT chains with non-default priority -99, so try on best-effort
		log.ErrorFE("createTableAndChains - error nft flush 1: %w", err) // and continue
	}

	// Create VPN coexistence chains
	vpnCoexistenceChainIn = nftConn.AddChain(vpnCoexistenceChainIn)
	vpnCoexistenceChainOut = nftConn.AddChain(vpnCoexistenceChainOut)

	// if err := nftConn.Flush(); err != nil { // Apply the above (commands are queued till a call to Flush())
	// 	return nil, nil, nil, log.ErrorFE("createTableAndChains - error nft flush 2: %w", err)
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
				Chain: VPN_COEXISTENCE_CHAIN_NFT_IN,
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
				Chain: VPN_COEXISTENCE_CHAIN_NFT_OUT,
			},
		},
	}
	// if len(outputRules) >= 1 {
	// 	jumpOutRule.Position = outputRules[0].Handle
	// }
	nftConn.InsertRule(&jumpOutRule)

	if err := nftConn.Flush(); err != nil { // Apply the above (commands are queued till a call to Flush())
		return nil, nil, nil, log.ErrorFE("createTableAndChains - error nft flush 3: %w", err)
	}

	return filter, vpnCoexistenceChainIn, vpnCoexistenceChainOut, nil
}

func implHaveTopFirewallPriorityNft() (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	weHaveTopFirewallPriority, retErr = implGetEnabledNft(false)
	return weHaveTopFirewallPriority, "", "", "", retErr
}

// implGetEnabledNft checks whether 1st rules in INPUT, OUTPUT chains are jumps to our chains.
// It needs to be fast, as it's called for every nft firewall change event
func implGetEnabledNft(blockingWait bool) (exists bool, retErr error) {
	if blockingWait {
		fwLinuxNftablesMutex.Lock()
		defer fwLinuxNftablesMutex.Unlock()
	}

	defer func() {
		if retErr != nil {
			printNftToLog()
		}
	}()

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
		if reflect.TypeOf(inputRules[0].Exprs[0]) != reflect.TypeFor[*expr.Verdict]() || verdict.Kind != expr.VerdictJump || verdict.Chain != VPN_COEXISTENCE_CHAIN_NFT_IN {
			log.Debug("jump to our table " + VPN_COEXISTENCE_CHAIN_NFT_IN + " is not a 0th rule in INPUT")
			return false, nil
		}
	} else {
		//log.Debug("INPUT chain empty or not found")
		return false, nil
	}

	if len(outputRules) >= 1 {
		verdict, _ := outputRules[0].Exprs[0].(*expr.Verdict)
		if reflect.TypeOf(outputRules[0].Exprs[0]) != reflect.TypeFor[*expr.Verdict]() || verdict.Kind != expr.VerdictJump || verdict.Chain != VPN_COEXISTENCE_CHAIN_NFT_OUT {
			log.Debug("jump to our table " + VPN_COEXISTENCE_CHAIN_NFT_OUT + " is not a 0th rule in OUTPUT")
			return false, nil
		}
	} else {
		//log.Debug("OUTPUT chain empty or not found")
		return false, nil
	}

	// // Check that our chains exist

	// var coexChainInFound, coexChainOutFound bool
	// chains, err := nftConn.ListChainsOfTableFamily(TABLE_TYPE)
	// if err != nil {
	// 	return false, log.ErrorFE("error listing chains: %w", err)
	// }
	// for _, chain := range chains {
	// 	if chain.Name == VPN_COEXISTENCE_CHAIN_IN {
	// 		coexChainInFound = true
	// 	} else if chain.Name == VPN_COEXISTENCE_CHAIN_OUT {
	// 		coexChainOutFound = true
	// 	}
	// }

	// if !coexChainInFound {
	// 	return false, log.ErrorE(errors.New("error - "+VPN_COEXISTENCE_CHAIN_IN+" chain not found in table "+filter.Name), 0)
	// }
	// if !coexChainOutFound {
	// 	return false, log.ErrorE(errors.New("error - "+VPN_COEXISTENCE_CHAIN_OUT+" chain not found in table "+filter.Name), 0)
	// }

	// // TODO: Also check that helper script returns true - that cgroup exists, etc.
	// if exitCode, err := shell.ExecGetExitCode(nil, platform.FirewallScript(), "test"); err != nil {
	// 	return false, log.ErrorFE("error running '%s test': %w", platform.FirewallScript(), err)
	// } else if exitCode != 0 {
	// 	return false, log.ErrorFE("error - '%s test' exit code = %d", platform.FirewallScript(), exitCode)
	// }

	return true, nil
}

func registerNftMonitor() (err error) {
	nftMonitor = nftables.NewMonitor(nftables.WithMonitorEventBuffer(20480)) // will be closed when implFirewallBackgroundMonitorNft() exits
	// TODO: Vlad - add filtering conditions? W/ conditions a single monitor can only monitor a single object, and/or a single action (add, del, etc.)

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	if nftEvents, err = nftConn.AddGenerationalMonitor(nftMonitor); err != nil {
		return log.ErrorFE("error AddGenerationalMonitor: %w", err)
	}

	return nil
}

// implReregisterFirewallAtTopPriorityNft - here we assume VPN connection is already established, so we include creation of all firewall objects, incl. post-connection
func implReregisterFirewallAtTopPriorityNft(forceReconfigureFirewall, forceRedetectOtherVpns, canReconfigureOtherVpns bool) (firewallReconfigured bool, retErr error) {
	if isDaemonStoppingCallback() {
		log.ErrorFE("error - daemon is stopping")
		return
	}

	// to ensure there's only one instance of this function, and that no other read or write operations are taking place in parallel
	fwLinuxNftablesMutex.Lock()
	defer fwLinuxNftablesMutex.Unlock()

	// log.Debug("implReregisterFirewallAtTopPriorityNft entered")
	// defer log.Debug("implReregisterFirewallAtTopPriorityNft exited")

	entryMsg := ""
	if !forceReconfigureFirewall {
		if weHaveTopFirewallPriority, err := implGetEnabledNft(false); err != nil {
			return false, log.ErrorFE("error in implGetEnabledNft(): %w", err)
		} else if weHaveTopFirewallPriority {
			return false, nil
		} else if isDaemonStoppingCallback() {
			return false, log.ErrorFE("error - daemon is stopping")
		}

		entryMsg = "don't have top pri, need to reenable firewall"
	} else {
		entryMsg = "forced to reenable firewall"
	}

	// signal loss of top firewall priority to UI
	go waitForTopFirewallPriAfterWeLostIt()

	log.Debug("implReregisterFirewallAtTopPriorityNft - ", entryMsg)
	if forceRedetectOtherVpns {
		if _, err := reDetectOtherVpnsImpl(true, false, true, false, canReconfigureOtherVpns); err != nil { // run forced re-detection of other VPNs synchronously - it must finish before implReEnableNft() needs otherVpnsNftMutex
			log.ErrorFE("error reDetectOtherVpnsImpl(true, false, true, false): %w", err) // and continue
		}
	}
	if err := implReEnableNft(true, canReconfigureOtherVpns); err != nil {
		return true, log.ErrorFE("error in implReEnableNft: %w", err)
	}

	go onKillSwitchStateChangedCallback(true)  // send notification out in case state went from FAIL to GOOD
	go implDeployPostConnectionRulesNft(false) // forking in the background, as otherwise DNS timeouts are up to ~15 sec, they freeze UI changes

	return true, nil
}

func mullvadNftEventsHelper(changeTable *nftables.Table) {
	if isDaemonStoppingCallback() {
		log.ErrorFE("error - daemon is stopping")
		return
	}

	if changeTable.Name != "mullvad" || changeTable.Family != nftables.TableFamilyINet { // if not a Mullvad event - ignore
		return
	}

	if !getPrefsCallback().IsTotalShieldOn { // if Total Shield off - nothing to do
		return
	}

	perVpnNftEventsHelperMutex.Lock()
	defer perVpnNftEventsHelperMutex.Unlock()

	if !getPrefsCallback().IsTotalShieldOn { // recheck after mutex
		return
	}

	log.Warning("Other VPN 'Mullvad' is connected/connecting - Total Shield cannot be enabled in PL Connect. Disabling Total Shield.")
	go disableTotalShieldAsyncCallback()
}

// expressVpnNftEventsHelper is called for rules in chains with name starting with "evpn."
func expressVpnNftEventsHelper(chainName string) {
	if isDaemonStoppingCallback() {
		log.ErrorFE("error - daemon is stopping")
		return
	}

	if !strings.HasPrefix(chainName, expressVpnProfile.nftablesChainNamePrefix) { // if not an ExpressVPN event - ignore
		return
	}

	if !getPrefsCallback().IsTotalShieldOn { // if Total Shield off - nothing to do
		return
	}

	perVpnNftEventsHelperMutex.Lock()
	defer perVpnNftEventsHelperMutex.Unlock()

	if !getPrefsCallback().IsTotalShieldOn { // recheck after mutex
		return
	}

	if expressVpnProfile.nftablesChainNameExclusionsRE.MatchString(chainName) { // If it's an excluded event - ignore. Delay regex check.
		return
	}

	// TODO: "expressvpnctl status" does not report connecting status, and doesn't report connected status for a while - disabling that check
	/*if expressVpnConnected, err := expressVpnProfile.CheckVpnConnected(); err != nil {
		log.ErrorFE("error expressVpnProfile.CheckVpnConnected(): %w", err)
	} else*/if /*expressVpnConnected &&*/ expressVpnProfile.incompatWithTotalShieldWhenConnected {
		log.Warning("Other VPN 'ExpressVPN' may be connecting/connected - Total Shield cannot be enabled in PL Connect. Disabling Total Shield.")
		go disableTotalShieldAsyncCallback()
	}
}

// implFirewallBackgroundMonitorNft runs as a background thread, listens for nftable change events.
// If events are relevant - it checks whether we have top firewall priority. If don't have top pri - it recreates our firewall objects.
// To stop this thread - send to stopMonitoringFirewallChanges chan.
func implFirewallBackgroundMonitorNft() {
	if isDaemonStoppingCallback() {
		log.ErrorFE("error - daemon is stopping")
		return
	}

	implFirewallBackgroundMonitorNftRunningMutex.Lock() // to ensure there's only one instance of implFirewallBackgroundMonitorNft
	defer implFirewallBackgroundMonitorNftRunningMutex.Unlock()

	log.Debug("implFirewallBackgroundMonitorNft entered")
	defer log.Debug("implFirewallBackgroundMonitorNft exited")

	if err := registerNftMonitor(); err != nil { // start listening for nft events for the duration of the whole function
		log.ErrorFE("error registerNftMonitor: %w", err)
		return
	}
	defer nftMonitor.Close()

	if _, err := implReregisterFirewallAtTopPriorityNft(false, false, getPrefsCallback().PermissionReconfigureOtherVPNs); err != nil { // check that we have top-pri once on start of this func
		log.ErrorFE("error in implReregisterFirewallAtTopPriorityNft(): %w", err) // and continue
	}

	for {
		select {
		case <-stopMonitoringFirewallChangesNft:
			go DisableCoexistenceWithOtherVpns() // nah, run asynchronously in the background after all - 8sec is way too long to wait in the UI
			log.Debug("implFirewallBackgroundMonitorNft exiting on stop signal")
			return
		case event, ok := <-nftEvents:
			if isDaemonStoppingCallback() {
				log.ErrorFE("error - daemon is stopping")
				return
			}

			if !ok {
				log.ErrorFE("error - reading from nftEvents channel not ok, implFirewallBackgroundMonitorNft exiting")
				return
			}

			if event != nil && event.GeneratedBy != nil && event.GeneratedBy.Data != nil &&
				reflect.TypeOf(event.GeneratedBy.Data) == reflect.TypeFor[*nftables.GenMsg]() {
				genMsg := event.GeneratedBy.Data.(*nftables.GenMsg)
				if strings.Contains(genMsg.ProcComm, "privateline-con") {
					continue // ignore our own firewall changes
				}
				// log.Debug("implFirewallBackgroundMonitorNft event generated by " + genMsg.ProcComm)
			}

			for _, change := range event.Changes {
				if change.Error != nil {
					log.ErrorFE("nftMonitor event change error, implFirewallBackgroundMonitorNft exiting. err=%w", change.Error)
					return
				}
				// log.Debug("implFirewallBackgroundMonitorNft event.Changes loop iteration")

				switch change.Type {
				case nftables.MonitorEventTypeNewRule:
					newRule := change.Data.(*nftables.Rule)
					go mullvadNftEventsHelper(newRule.Table) // if Mullvad is connecting/connected - need to disable Total Shield
					// log.Debug("MonitorEventTypeNewRule: chain=", newRule.Chain.Name)
					go expressVpnNftEventsHelper(newRule.Chain.Name) // if ExpressVPN is connecting/connected - need to disable Total Shield

					if _, err := implReregisterFirewallAtTopPriorityNft(false, true, getPrefsCallback().PermissionReconfigureOtherVPNs); err != nil {
						log.ErrorFE("error in implReregisterFirewallAtTopPriorityNft(): %w", err) // and continue
					}

				case nftables.MonitorEventTypeDelRule:
					gotRule := change.Data.(*nftables.Rule)
					verdict, _ := gotRule.Exprs[0].(*expr.Verdict)
					if reflect.TypeOf(gotRule.Exprs[0]) == reflect.TypeFor[*expr.Verdict]() && verdict.Kind == expr.VerdictJump &&
						(verdict.Chain == VPN_COEXISTENCE_CHAIN_NFT_IN || verdict.Chain == VPN_COEXISTENCE_CHAIN_NFT_OUT) {
						if _, err := implReregisterFirewallAtTopPriorityNft(false, true, getPrefsCallback().PermissionReconfigureOtherVPNs); err != nil {
							log.ErrorFE("error in implReregisterFirewallAtTopPriorityNft(): %w", err) // and continue
						}
					}

				case nftables.MonitorEventTypeDelChain:
					gotChain := change.Data.(*nftables.Chain)
					switch gotChain.Name {
					case "INPUT":
					case "OUTPUT":
					case VPN_COEXISTENCE_CHAIN_NFT_IN:
					case VPN_COEXISTENCE_CHAIN_NFT_OUT:
						if _, err := implReregisterFirewallAtTopPriorityNft(false, true, getPrefsCallback().PermissionReconfigureOtherVPNs); err != nil {
							log.ErrorFE("error in implReregisterFirewallAtTopPriorityNft(): %w", err) // and continue
						}
					}

				case nftables.MonitorEventTypeDelTable:
					gotTable := change.Data.(*nftables.Table)
					if gotTable.Name == TABLE {
						if _, err := implReregisterFirewallAtTopPriorityNft(false, true, getPrefsCallback().PermissionReconfigureOtherVPNs); err != nil {
							log.ErrorFE("error in implReregisterFirewallAtTopPriorityNft(): %w", err) // and continue
						}
					}

				case nftables.MonitorEventTypeNewTable:
					go mullvadNftEventsHelper(change.Data.(*nftables.Table)) // if Mullvad is connecting/connected - need to disable Total Shield
				}
			}
		}
	}
}

// func implStopFirewallBackgroundMonitor() (mutex *sync.Mutex) {
// 	// must check whether implFirewallBackgroundMonitorNft() is actually running (it could've exited due to an error), else don't send to stopMonitoringFirewallChanges chan
// 	if !implFirewallBackgroundMonitorNftMutex.TryLock() {
// 		stopMonitoringFirewallChangesNft <- true     // send implFirewallBackgroundMonitorNft() a stop signal
// 		implFirewallBackgroundMonitorNftMutex.Lock() // wait for it to stop
// 	}

// 	return &implFirewallBackgroundMonitorNftMutex
// }

func implReEnableNft(fwLinuxNftablesMutexGrabbed, canReconfigureOtherVpns bool) (retErr error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	if !fwLinuxNftablesMutexGrabbed {
		fwLinuxNftablesMutex.Lock()
		defer fwLinuxNftablesMutex.Unlock()
	}

	log.Debug("implReEnableNft entered")
	defer log.Debug("implReEnableNft exited")

	var implReEnableNftTasks sync.WaitGroup
	implReEnableNftTasks.Add(2)

	go func() { // run nftables-specific VPN coexistence logic in parallel with our usual nftables logic disable-enable
		defer implReEnableNftTasks.Done()
		if vpnCoexNftErr := enableVpnCoexistenceLinuxNft(canReconfigureOtherVpns); vpnCoexNftErr != nil {
			retErr = log.ErrorFE("error enableVpnCoexistenceLinuxNft(): %w", vpnCoexNftErr)
		}
	}()

	go func() { // our usual nftables logic disable-enable
		defer implReEnableNftTasks.Done()
		if err := doDisableNft(true); err != nil {
			log.ErrorFE("failed to disable nft firewall: %w", err) // and continue
		}

		if err := doEnableNft(true, false); err != nil {
			retErr = log.ErrorFE("failed to enable nft firewall: %w", err)
		}
	}()

	implReEnableNftTasks.Wait()
	//return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
	return retErr
}

// doEnableNft - normally call it with enableNftVpnCoexistence=true, unless calling from one of the reenable functions
func doEnableNft(fwLinuxNftablesMutexGrabbed, enableNftVpnCoexistence bool) (err error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	if !fwLinuxNftablesMutexGrabbed {
		fwLinuxNftablesMutex.Lock()
		defer fwLinuxNftablesMutex.Unlock()
	}

	log.Debug("doEnableNft entered")
	defer log.Debug("doEnableNft exited")

	defer func() {
		if err != nil {
			printNftToLog()
		}
	}()

	// if !implFirewallBackgroundMonitorNftMutex.TryLock() { // if TryLock() failed - then instance of implFirewallBackgroundMonitorNft() is already running, must stop it
	// 	stopMonitoringFirewallChanges <- true     // send implFirewallBackgroundMonitorNft() a stop signal
	// 	implFirewallBackgroundMonitorNftMutex.Lock() // wait for it to stop, lock its mutex till the end of doEnableNft()
	// }
	// defer implFirewallBackgroundMonitorNftMutex.Unlock() // release its mutex unconditionally at the end of doEnableNft()

	var doEnableNftTasks sync.WaitGroup
	if enableNftVpnCoexistence { // if requested to run enableVpnCoexistenceLinuxNft() - run it in parallel with our nft logic creation
		doEnableNftTasks.Add(1)
		go func() {
			defer doEnableNftTasks.Done()
			if vpnCoexNftErr := enableVpnCoexistenceLinuxNft(true); vpnCoexNftErr != nil {
				err = log.ErrorFE("error enableVpnCoexistenceLinuxNft(): %w", vpnCoexNftErr)
			}
		}()
	}

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

	// create these sets:
	// 	- a set of Wireguard endpoint IPs
	//	- a set of external IPs for our REST API servers
	// 	- a set of our DNS servers, incl. custom DNS
	wgEndpointAddrsIPv4 := &nftables.Set{
		Name:    "privateLINE_Wireguard_endpoint_IPv4_addrs",
		Table:   filter,
		KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses
	}
	if err := nftConn.AddSet(wgEndpointAddrsIPv4, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	ourSets = append(ourSets, wgEndpointAddrsIPv4)

	defaultRestApiAddrsIPv4 := &nftables.Set{
		Name:    "privateLINE_default_REST_API_IPv4_addrs",
		Table:   filter,
		KeyType: nftables.TypeIPAddr, // our keys are IPv4 addresses
	}
	if err := nftConn.AddSet(defaultRestApiAddrsIPv4, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	ourSets = append(ourSets, defaultRestApiAddrsIPv4)

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

	if len(customDnsServers) >= 1 { // append custom DNS servers, if configured
		newDnsEntries := []nftables.SetElement{}
		for _, customDnsSrv := range customDnsServers {
			if !prefs.AllDnsServersIPv4Set.Contains(customDnsSrv.String()) && !net.IPv4zero.Equal(customDnsSrv) {
				newDnsEntries = append(newDnsEntries, nftables.SetElement{Key: customDnsSrv.To4()})
			}
		}

		if len(newDnsEntries) >= 1 {
			if err = nftConn.SetAddElements(privatelineDnsAddrsIPv4, newDnsEntries); err != nil {
				return log.ErrorFE("enable - error adding new DNS entries to set: %w", err)
			}
		}
	}

	for _, restApiHost := range getRestApiHostsCallback() {
		if err = nftConn.SetAddElements(defaultRestApiAddrsIPv4, []nftables.SetElement{{Key: restApiHost.DefaultIP.To4()}}); err != nil {
			log.ErrorFE("enable - error adding restApiHost.DefaultIP.To4() to set: %w", err) // and continue
		}
	}

	// if err := nftConn.Flush(); err != nil { // preliminary flush
	// 	return log.ErrorFE("doEnableNft - error nft flush 1: %w", err)
	// }

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

	// create a set with ports 80, 443
	portsHttpHttps := &nftables.Set{
		Name:    "http_https",
		Table:   filter,
		KeyType: nftables.TypeInetService, // aka port
	}
	if err := nftConn.AddSet(portsHttpHttps, []nftables.SetElement{}); err != nil {
		return log.ErrorFE("enable - error creating nft set: %w", err)
	}
	ourSets = append(ourSets, portsHttpHttps)
	nftConn.SetAddElements(portsHttpHttps, []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint16(80)}, {Key: binaryutil.BigEndian.PutUint16(443)}})

	// if err := nftConn.Flush(); err != nil { // preliminary flush
	// 	return log.ErrorFE("doEnableNft - error nft flush 2: %w", err)
	// }

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

	/*
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
	*/

	// Allow all DNS - tentative workaround for ExpressVPN, but applying it generally for now.
	// TODO: FIXME: allow only until login (SessionNew) is done

	// Allow UDP src port 53 from any IP
	nftConn.InsertRule(&nftables.Rule{ // in UDP, src port 53
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
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

	// Allow TCP+UDP dst port 53 to any IP
	nftConn.InsertRule(&nftables.Rule{ // out TCP+UDP, dst port 53
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		Exprs: []expr.Any{
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

	// TODO: Vlad - permit all PL apps in UDP, out TCP+UDP (any proto) with PL IP ranges by default, until we re-implement App Whitelist
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

	// Allow our hosts (meet.privateline.network, etc.) in: UDP
	// Since we may not be connected to our VPN yet, use default cached IPs here
	for _, plInternalHost := range *platform.PLInternalHostsToAcceptIncomingUdpFrom() {
		plInternalHostIPv4 := &nftables.Set{
			Name:    PL_INTERNAL_HOSTS_SET_PREFIX + plInternalHost.Hostname,
			Table:   filter,
			KeyType: nftables.TypeIPAddr, // set for IPv4 addresses
			Dynamic: true,                // allow additions-deletions
		}

		if err := nftConn.AddSet(plInternalHostIPv4, []nftables.SetElement{{Key: plInternalHost.DefaultIP.To4()}}); err != nil {
			return log.ErrorFE("implDeployPostConnectionRulesNft - error creating nft set: %w", err)
		}
		ourSets = append(ourSets, plInternalHostIPv4)

		nftConn.AddRule(&nftables.Rule{ // allow IPv4 in UDP
			Table: filter,
			Chain: vpnCoexistenceChainIn,
			Exprs: []expr.Any{
				// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				// [ lookup reg 1, ourHostIPsIPv4 set ]
				&expr.Lookup{SourceRegister: 1, SetName: plInternalHostIPv4.Name, SetID: plInternalHostIPv4.ID},
				// [ meta load l4proto => reg 2 ]
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
				// [ cmp eq reg 2 UDP ]
				&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Counter{},
				//[ immediate reg 0 accept ]
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	// allow PL service binaries in-out. Then we won't need to explicitly create allow rules for REST API servers, etc.
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

	// Eh, allow our REST API servers explicitly also - just in case
	nftConn.AddRule(&nftables.Rule{ // outbound TCP ports 80,443
		Table: filter,
		Chain: vpnCoexistenceChainOut,
		Exprs: []expr.Any{
			// [ dest IP: payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			// [ lookup reg 1, set defaultRestApiAddrsIPv4 ]
			&expr.Lookup{SourceRegister: 1, SetName: defaultRestApiAddrsIPv4.Name, SetID: defaultRestApiAddrsIPv4.ID},
			// [ meta load l4proto => reg 2 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
			// [ cmp eq reg 2 TCP ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_TCP}},
			// [ dst port: payload load 2b @ transport header + 2 => reg 3 ]
			&expr.Payload{DestRegister: 3, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			// [ lookup reg 3, set ports 80,443 ]
			&expr.Lookup{SourceRegister: 3, SetName: portsHttpHttps.Name, SetID: portsHttpHttps.ID},
			&expr.Counter{},
			//[ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	nftConn.AddRule(&nftables.Rule{ // inbound related, established
		Table: filter,
		Chain: vpnCoexistenceChainIn,
		Exprs: []expr.Any{
			// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			// [ lookup reg 1, set defaultRestApiAddrsIPv4 ]
			&expr.Lookup{SourceRegister: 1, SetName: defaultRestApiAddrsIPv4.Name, SetID: defaultRestApiAddrsIPv4.ID},
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

	// if err := nftConn.Flush(); err != nil { // preliminary flush
	// 	return log.ErrorFE("doEnableNft - error nft flush 3: %w", err)
	// }

	// create rules for wgInterfaceName interface - even if it doesn't exist yet
	wgInterfaceName := []byte(platform.WGInterfaceName() + "\x00")

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
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgInterfaceName},
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
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgInterfaceName},
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
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: wgInterfaceName},
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

	if TotalShieldDeployedState() { // add DROP rules at the end of our chains; enable Total Shield blocks only if VPN is CONNECTED
		log.Debug("doEnableNft: enabling TotalShield")
		nftConn.AddRule(&nftables.Rule{Table: filter, Chain: vpnCoexistenceChainIn, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
		nftConn.AddRule(&nftables.Rule{Table: filter, Chain: vpnCoexistenceChainOut, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
	}

	if err := nftConn.Flush(); err != nil {
		return log.ErrorFE("doEnableNft - error nft flush 4: %w", err)
	}

	// log.Debug("doEnableNft flushed")
	// printNftTableFilter()

	// TODO: Vlad - replicate further rules from firewall_windows.go as needed

	// To fulfill such flow (example): Connected -> FWDisable -> FWEnable
	// Here we should restore all exceptions (all hosts which are allowed)
	// return reApplyExceptions() // TODO: FIXME: Vlad - refactor

	doEnableNftTasks.Wait()
	return err
}

// Rules to add after VPN is connected:
//
//	allow meet.privateline.network, same as in firewall_windows.go
//
//	have to insert post-rules on top of our chains, otherwise they'd interfere with DROP rules at the end of our chains
//
// TODO: Vlad - do we need to worry about forward chains?
func implDeployPostConnectionRulesNft(fwLinuxNftablesMutexGrabbed bool) (retErr error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	if !fwLinuxNftablesMutexGrabbed {
		fwLinuxNftablesMutex.Lock()
		defer fwLinuxNftablesMutex.Unlock()
	}

	// implDeployPostConnectionRulesNftMutex.Lock() // ensure only one instance of this func can run at a time
	// defer implDeployPostConnectionRulesNftMutex.Unlock()

	log.Debug("implDeployPostConnectionRulesNft entered")
	defer log.Debug("implDeployPostConnectionRulesNft exited")

	if firewallEnabled, err := implGetEnabledNft(false); err != nil {
		return log.ErrorFE("status check error: %w", err)
	} else if !firewallEnabled || !vpnConnectedOrConnectingCallback() {
		return nil // our tables not up or VPN not connected/connecting, so skipping
	}

	// filter, _, _, vpnCoexistenceChainIn, _ := createTableChainsObjects()
	filter, _, _, _, _ := createTableChainsObjects()
	toFlush := false

	// Allow our hosts (meet.privateline.network, etc.) in: UDP
	for _, plInternalHost := range *platform.PLInternalHostsToAcceptIncomingUdpFrom() {
		var (
			IPs                   []net.IP
			plInternalHostIPsIPv4 = &nftables.Set{
				Name:    PL_INTERNAL_HOSTS_SET_PREFIX + plInternalHost.Hostname,
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

		// TODO: Vlad - disabled this check, as we create the set in doEnableNft()
		// // Check whether the set for a given hostname already exists - if so, assume the rules exist also
		// if existingSet, err := nftConn.GetSetByName(filter, ourHostIPsIPv4.Name); err != nil {
		// 	if !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		// 		return log.ErrorFE("error nftConn.GetSetByName(filter, %s): %w", ourHostIPsIPv4.Name, err)
		// 	}
		// } else if existingSet != nil {
		// 	// log.Debug("set ", ourHostIPsIPv4.Name, " already exists, not adding new entries or rules")
		// 	continue
		// }

		if IPs, retErr = net.LookupIP(plInternalHost.Hostname); retErr != nil {
			retErr = log.ErrorFE("could not lookup IPs for '%s': %w", plInternalHost, retErr)
			continue
		} else if len(IPs) == 0 {
			retErr = log.ErrorFE("no IPs returned for '%s'", plInternalHost)
			continue
		}

		if err := nftConn.AddSet(plInternalHostIPsIPv4, []nftables.SetElement{}); err != nil {
			log.ErrorFE("implDeployPostConnectionRulesNft - error creating nft set: %w", err) // and continue
		}
		// ourSets = append(ourSets, plInternalHostIPsIPv4)
		// if err := nftConn.AddSet(ourHostIPsIPv6, []nftables.SetElement{}); err != nil {
		// 	return log.ErrorFE("implDeployPostConnectionRulesNft - error creating nft set: %w", err)
		// }
		// ourSets = append(ourSets, ourHostIPsIPv6)

		for _, IP := range IPs { // add newly found IPs for this hostname to set, unless they match the default known IP
			if !plInternalHost.DefaultIP.Equal(IP) && IP.To4() != nil && !net.IPv4zero.Equal(IP) { // IPv4
				log.Info("IPv4 UDP: allow remote hostname ", plInternalHost, " at ", IP.String())
				if err := nftConn.SetAddElements(plInternalHostIPsIPv4, []nftables.SetElement{{Key: IP.To4()}}); err != nil {
					return log.ErrorFE("enable - error adding IPv4 addr %s for '%s' to set: %w", IP.String(), plInternalHost, err)
				}
				// } else { // IPv6
				// log.Info("IPv6 UDP: allow remote hostname ", plInternalHostname, " at ", IP.String())
				// 	if err := nftConn.SetAddElements(ourHostIPsIPv6, []nftables.SetElement{{Key: IP}}); err != nil {
				//		return log.ErrorFE("enable - error adding IPv6 addr %s for '%s' to set: %w", IP.String(), plInternalHostname, err)
				// 	}
				toFlush = true
			}
		}

		// TODO: Vlad - no need to create rules here, we already created accept rule(s) in doEnableNft()
		// // in UDP
		// nftConn.InsertRule(&nftables.Rule{ // IPv4
		// 	Table: filter,
		// 	Chain: vpnCoexistenceChainIn,
		// 	Exprs: []expr.Any{
		// 		// [ src IP: payload load 4b @ network header + 12 => reg 1 ]
		// 		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		// 		// [ lookup reg 1, ourHostIPsIPv4 set ]
		// 		&expr.Lookup{SourceRegister: 1, SetName: plInternalHostIPsIPv4.Name, SetID: plInternalHostIPsIPv4.ID},
		// 		// [ meta load l4proto => reg 2 ]
		// 		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 2},
		// 		// [ cmp eq reg 2 UDP ]
		// 		&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{unix.IPPROTO_UDP}},
		// 		&expr.Counter{},
		// 		//[ immediate reg 0 accept ]
		// 		&expr.Verdict{Kind: expr.VerdictAccept},
		// 	},
		// })
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

	if toFlush {
		if err := nftConn.Flush(); err != nil {
			return log.ErrorFE("implDeployPostConnectionRulesNft - error: %w", err)
		}
	}

	return retErr
}

func doDisableNft(fwLinuxNftablesMutexGrabbed bool) (err error) {
	if !fwLinuxNftablesMutexGrabbed {
		fwLinuxNftablesMutex.Lock()
		defer fwLinuxNftablesMutex.Unlock()
	}

	log.Debug("doDisableNft entered")
	defer log.Debug("doDisableNft exited")

	defer func() {
		if err != nil {
			printNftToLog()
		}
	}()

	// if !implFirewallBackgroundMonitorNftMutex.TryLock() { // if TryLock() failed - then instance of implFirewallBackgroundMonitorNft() is already running
	// 	stopMonitoringFirewallChanges <- true     // send implFirewallBackgroundMonitorNft() a stop signal
	// 	implFirewallBackgroundMonitorNftMutex.Lock() // wait for it to stop, lock its mutex till the end of doDisableNft()
	// }
	// defer implFirewallBackgroundMonitorNftMutex.Unlock() // release its lock unconditionally after doDisableNft() exit

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
		if verdict.Kind == expr.VerdictJump && verdict.Chain == VPN_COEXISTENCE_CHAIN_NFT_IN {
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
		if verdict.Kind == expr.VerdictJump && verdict.Chain == VPN_COEXISTENCE_CHAIN_NFT_OUT {
			if err = nftConn.DelRule(outRule); err != nil {
				log.Debug(fmt.Errorf("error deleting jump rule in output: %w", err))
			}
		}
	}

	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		return log.ErrorFE("error during flush 1 in doDisableNft: %w", err)
	}

	// drop our chains
	nftConn.FlushChain(vpnCoexistenceChainIn)
	nftConn.DelChain(vpnCoexistenceChainIn)
	nftConn.FlushChain(vpnCoexistenceChainOut)
	nftConn.DelChain(vpnCoexistenceChainOut)

	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		return log.ErrorFE("error during flush 2 in doDisableNft: %w", err)
	}

	// drop our sets
	for _, ourSet := range ourSets {
		// log.Debug("flushing set ", ourSet.Name)
		nftConn.FlushSet(ourSet)
	}
	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
		return log.ErrorFE("error during flush 3 in doDisableNft: %w", err)
	}

	for _, ourSet := range ourSets {
		// log.Debug("deleting set ", ourSet.Name)
		nftConn.DelSet(ourSet)
	}
	ourSets = []*nftables.Set{}

	if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) { // yes, need to flush multiple times to erase everything
		return log.ErrorFE("error during flush 4 in doDisableNft: %w", err)
	}
	// log.Debug("doDisableNft flushed")
	// printNftTableFilter()

	return nil
}

func implOnChangeDnsNft(newDnsServers *[]net.IP) (err error) { // by now we know customDNS is non-null; just add it to privateLINE_DNS set
	fwLinuxNftablesMutex.Lock()
	defer fwLinuxNftablesMutex.Unlock()

	defer func() {
		if err != nil {
			printNftToLog()
		}
	}()

	filter := &nftables.Table{Family: TABLE_TYPE, Name: TABLE}

	privatelineDnsAddrsIPv4, err := nftConn.GetSetByName(filter, PL_DNS_SET)
	if err != nil || privatelineDnsAddrsIPv4 == nil {
		return log.ErrorFE("error GetSetByName(filter, %s): %w", PL_DNS_SET, err)
	}

	newDnsEntries := []nftables.SetElement{}
	for _, newDnsSrv := range *newDnsServers { // append new DNS servers
		newDnsEntries = append(newDnsEntries, nftables.SetElement{Key: newDnsSrv.To4()})
	}
	if err = nftConn.SetAddElements(privatelineDnsAddrsIPv4, newDnsEntries); err != nil {
		return log.ErrorFE("enable - error adding new DNS entries to set: %w", err)
	}
	if err := nftConn.Flush(); err != nil {
		return log.ErrorFE("implOnChangeDnsNft - error nft flush: %w", err)
	}

	return nil
}

func implTotalShieldApplyNft(totalShieldNewState bool) (err error) {
	fwLinuxNftablesMutex.Lock()
	defer fwLinuxNftablesMutex.Unlock()

	defer func() {
		if err != nil {
			printNftToLog()
		}
	}()

	// by now we know the firewall is up - gotta add or remove DROP rules to reflect new Total Shield setting

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

	if totalShieldNewState {
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
		log.Debug("implTotalShieldApplyNft: setting TotalShield=", totalShieldNewState, " in firewall")
		if err := nftConn.Flush(); err != nil && !strings.Contains(err.Error(), ENOENT_ERRMSG) {
			return log.ErrorFE("nft flush error in implTotalShieldApplyNft: %w", err)
		}
	}

	return nil
}
