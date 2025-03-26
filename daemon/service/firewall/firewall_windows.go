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

package firewall

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall/winlib"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/windows"
)

type TotalShieldBlockInfo struct {
	layerGUID        syscall.GUID
	isIPv6           bool
	blockAllFilterID uint64 // ID of block filter when Total Shield is enabled, 0 when disabled
}

var (
	providerKey          = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x01}}
	ourSublayerKey       = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x02}}
	providerKeySingleDns = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x03}}
	sublayerKeySingleDns = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x04}}

	v4LayersOut = []syscall.GUID{winlib.FwpmLayerAleAuthConnectV4, winlib.FwpmLayerAleFlowEstablishedV4}
	v4LayersIn  = []syscall.GUID{winlib.FwpmLayerAleAuthRecvAcceptV4}
	v4LayersAll = slices.Concat(v4LayersOut, v4LayersIn)

	v6LayersOut = []syscall.GUID{winlib.FwpmLayerAleAuthConnectV6, winlib.FwpmLayerAleFlowEstablishedV6}
	v6LayersIn  = []syscall.GUID{winlib.FwpmLayerAleAuthRecvAcceptV6}
	v6LayersAll = slices.Concat(v6LayersOut, v6LayersIn)

	layersAllIn  = slices.Concat(v4LayersIn, v6LayersIn)
	layersAllOut = slices.Concat(v4LayersOut, v6LayersOut)

	// used to block-all when Total Shield is enabled
	totalShieldLayers = []*TotalShieldBlockInfo{
		&TotalShieldBlockInfo{winlib.FwpmLayerAleAuthConnectV4, false, 0},
		&TotalShieldBlockInfo{winlib.FwpmLayerAleAuthRecvAcceptV4, false, 0},
		&TotalShieldBlockInfo{winlib.FwpmLayerAleAuthConnectV6, true, 0},
		&TotalShieldBlockInfo{winlib.FwpmLayerAleAuthRecvAcceptV6, true, 0},
	}

	v4LayersICMP  = []syscall.GUID{winlib.FwpmLayerOutboundIcmpErrorV4, winlib.FwpmLayerInboundIcmpErrorV4}
	v6LayersICMP  = []syscall.GUID{winlib.FwpmLayerOutboundIcmpErrorV6, winlib.FwpmLayerInboundIcmpErrorV6}
	layersIcmpAll = slices.Concat(v4LayersICMP, v6LayersICMP)

	layersAllToClean = slices.Concat(v4LayersAll, v6LayersAll, layersIcmpAll)

	microsoftPortsToBlock = []uint16{135, 137, 138, 139, 445} // block these on TCP and UDP

	manager                winlib.Manager
	clientLocalIPFilterIDs []uint64

	_isEnabled          bool
	isAllowLAN          bool
	isAllowLANMulticast bool

	// These vars can be out of date. If need to report to UI - recheck all. Also lock the mutex when retrieving the otherSublayerGUID
	otherSublayerMutex sync.Mutex
	ourSublayerWeight  uint16       = 0
	otherSublayerGUID  syscall.GUID // If we could not register our sublayer with max weight (0xFFFF) yet, this will hold the GUID of another sublayer, who has max weight.

	powershellBinaryPath   string     = "powershell"
	enableDisableIPv6Mutex sync.Mutex // used to ensure that enableDisableIPv6() is single-instance
)

const (
	providerDName          = "privateLINE Firewall Provider"
	sublayerDName          = "privateLINE Firewall Sublayer"
	filterDName            = "privateLINE Firewall Filter"
	providerDNameSingleDns = "privateLINE Firewall Provider single DNS"
	sublayerDNameSingleDns = "privateLINE Firewall Sublayer single DNS"
	filterDNameSingleDns   = "privateLINE Firewall Filter single DNS"
)

func checkSublayerInstalled() (installed bool, err error) {
	installed, ourSublayer, err := manager.GetSubLayerByKey(ourSublayerKey)
	if err != nil {
		return false, fmt.Errorf("failed to check whether sublayer is installed: %w", err)
	} else if installed {
		ourSublayerWeight = ourSublayer.Weight
	}
	return installed, nil
}

func createAddSublayer() error {
	sublayer := winlib.CreateSubLayer(ourSublayerKey, providerKey,
		sublayerDName, "",
		winlib.SUBLAYER_MAX_WEIGHT,
		isPersistent)
	if err := manager.AddSubLayer(sublayer); err != nil {
		return log.ErrorE(fmt.Errorf("failed to add sublayer: %w", err), 0)
	}

	return nil
}

func implReregisterFirewallAtTopPriority(canStopOtherVpn bool) (firewallReconfigured bool, retErr error) {
	// Can't delete the sublayer if there are rules registered under it. So if VPN is connected - disable firewall, reregister sublayer, enable firewall.

	// if err := manager.TransactionStart(); err != nil { // start WFP transaction
	// 	return fmt.Errorf("failed to start transaction: %w", err)
	// }
	// defer func() { // do not forget to stop WFP transaction
	// 	var r any = recover()
	// 	if retErr == nil && r == nil {
	// 		manager.TransactionCommit() // commit WFP transaction
	// 	} else {
	// 		manager.TransactionAbort() // abort WFP transaction

	// 		if r != nil {
	// 			log.Error("PANIC (recovered): ", r)
	// 			if e, ok := r.(error); ok {
	// 				retErr = e
	// 			} else {
	// 				retErr = errors.New(fmt.Sprint(r))
	// 			}
	// 		}
	// 	}
	// }()

	var wasEnabled bool
	wasEnabled, retErr = implGetEnabled()
	if retErr != nil {
		return false, log.ErrorE(fmt.Errorf("status check error: %w", retErr), 0)
	}

	if wasEnabled {
		if retErr = implSetEnabled(false, false); retErr != nil {
			return false, log.ErrorE(fmt.Errorf("error disabling firewall: %w", retErr), 0)
		}
	}
	var retErr2 error = nil
	defer func() {
		if wasEnabled {
			if retErr2 = implSetEnabled(true, false); retErr != nil {
				retErr2 = log.ErrorE(fmt.Errorf("error re-enabling firewall: %w", retErr), 0)
				return
			}

			if retErr2 = doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6); retErr2 != nil {
				retErr2 = log.ErrorE(fmt.Errorf("error doAddClientIPFilters: %w", retErr), 0)
				return
			}
		}

		if retErr == nil {
			retErr = retErr2
		}
	}()

	if retErr = checkCreateProviderAndSublayer(false, canStopOtherVpn); retErr != nil {
		log.Error(fmt.Errorf("error re-registering firewall sublayer at top priority: %w", retErr), 0)
		return false, retErr
	}

	if retErr != nil {
		return false, retErr
	} else {
		return false, retErr2
	}
}

func findOtherSublayerWithMaxWeight() (found bool, otherSublayerKey syscall.GUID, err error) {
	otherSublayerMutex.Lock()
	defer otherSublayerMutex.Unlock()

	found, otherSublayerGUID, err = manager.FindSubLayerWithMaxWeight() // check if max weight slot is vacant
	if err != nil {
		return false, syscall.GUID{}, fmt.Errorf("failed to check for sublayer with max weight: %w", err)
	}

	return found, otherSublayerGUID, nil
}

// We'll check whether our provider and sublayer are up, will create if necessary.
// If our sublayer is not registered at max weight, and max weight slot is vacant - then we'll try to reregister our sublayer at max weight.
func checkCreateProviderAndSublayer(wfpTransactionAlreadyInProgress, canStopOtherVpn bool) (err error) {
	var (
		pInfo                                                        winlib.ProviderInfo
		found, installed, maxWeightSublayerFound, otherSublayerFound bool
		otherSublayer                                                winlib.SubLayer
		_otherSublayerGUID                                           syscall.GUID
		otherVpn                                                     *OtherVpnInfoParsed = nil

		otherVpnUnknownErr FirewallError = FirewallError{containedErr: nil, otherVpnUnknownToUs: false}
	)

	defer func() { // if other VPN was not registered in our db - propagate that info up, to be shown in client
		if otherVpnUnknownErr.otherVpnUnknownToUs && (err != nil || otherVpnUnknownErr.containedErr != nil) {
			if err != nil {
				otherVpnUnknownErr.containedErr = err
			}
			err = &otherVpnUnknownErr
		}
	}()

	// to figure out who called us
	// log.LogCallStack()

	// add provider
	found, pInfo, err = manager.GetProviderInfo(providerKey)
	if err != nil {
		return fmt.Errorf("failed to get provider info: %w", err)
	}
	if !found || !pInfo.IsInstalled {
		provider := winlib.CreateProvider(providerKey, providerDName, "", isPersistent)
		if err = manager.AddProvider(provider); err != nil {
			return fmt.Errorf("failed to add provider : %w", err)
		}
	}

	// add sublayer
	installed, err = checkSublayerInstalled()
	if err != nil {
		return fmt.Errorf("failed to check sublayer is installed: %w", err)
	}
	if !installed {
		return createAddSublayer()
	}

	if ourSublayerWeight < winlib.SUBLAYER_MAX_WEIGHT { // our sublayer installed, check if it has max weight
		maxWeightSublayerFound, _otherSublayerGUID, err = findOtherSublayerWithMaxWeight() // check if max weight slot is vacant
		if err != nil {
			return fmt.Errorf("failed to check for sublayer with max weight: %w", err)
		}
		if maxWeightSublayerFound {
			otherVpnUnknownErr.otherVpnGUID = windows.GUID(_otherSublayerGUID).String()
			otherSublayerMsg := fmt.Sprintf("Another sublayer with key/UUID '%s' is registered with max weight", windows.GUID(_otherSublayerGUID).String())
			otherSublayerFound, otherSublayer, err = manager.GetSubLayerByKey(_otherSublayerGUID)
			if err == nil && otherSublayerFound {
				otherVpnUnknownErr.otherVpnName = otherSublayer.Name
				otherSublayerMsg += ". Other sublayer information:\n" + otherSublayer.String()
			} else {
				otherSublayer.Key = _otherSublayerGUID
			}
			log.Warning(otherSublayerMsg)

			if canStopOtherVpn { // if requested to stop other VPN and unregister their firewall sublayer, try it
				otherVpn /*, err*/ = ParseOtherVpnBySublayerGUID(otherSublayerFound, &otherSublayer, &manager)
				/* if err != nil {
					err = log.ErrorE(fmt.Errorf("error parsing VPN info for other VPN '%s' - '%s', so not taking any VPN-specific steps, taking only generic interoperation approach",
						windows.GUID(_otherSublayerGUID).String(), otherSublayer.Name), 0)
				} else */if otherVpn == nil { // not expected to get nil back, it'd be a bug
					err = fmt.Errorf("error (unexpected nil): other VPN '%s' '%s' is not known to us, and guessing service names didn't succeed, so we can only try generic interoperation approach",
						windows.GUID(_otherSublayerGUID).String(), otherSublayer.Name)
					log.Warning(err)
				} else {
					log.Debug(fmt.Sprintf("otherVpn = %+v", otherVpn))
					otherVpnUnknownErr.otherVpnUnknownToUs = !otherVpn.OtherVpnKnown
					if err = otherVpn.PreSteps(); err != nil {
						err = fmt.Errorf("error taking pre-steps for other VPN '%s' '%s', continuing with generic interoperation approach. Error: %w",
							windows.GUID(_otherSublayerGUID).String(), otherSublayer.Name, err)
						log.Warning(err)
					}
					defer otherVpn.PostSteps()
				}

				if sublayerNotFound, err := manager.DeleteSubLayer(_otherSublayerGUID); err != nil { // now try to delete the WFP sublayer of the other VPN
					if sublayerNotFound {
						log.Info(fmt.Sprintf("Couldn't delete the other sublayer '%s' '%s' - sublayer not found", otherSublayer.Name, windows.GUID(_otherSublayerGUID).String()))
					} else {
						log.Error(fmt.Errorf("error deleting the other sublayer '%s' '%s': %w", otherSublayer.Name, windows.GUID(_otherSublayerGUID).String(), err))
					}
				}
			} else {
				log.Warning("Not requested to unregister the other sublayer, so we can't register our sublayer at max weight at the moment.")
				return nil
			}
		}

		// So max weight slot should be vacant by now, so try to delete our sublayer and recreate it at max weight.
		// We can delete the sublayer only if it's empty. The caller, firewall.TryReregisterFirewallAtTopPriority(), stopped the firewall before calling us.
		log.Debug("deleting our sublayer")
		if sublayerNotFound, err := manager.DeleteSubLayer(ourSublayerKey); err != nil {
			log.Debug("called DeleteSublayer() on our sublayer")
			if sublayerNotFound {
				log.Info("Couldn't delete our sublayer - sublayer not found")
			} else {
				log.Warning(fmt.Errorf("warning - failed to delete our sublayer: %w", err))
			}
		}
		reregisterMsg := fmt.Sprintf("checkCreateProviderAndSublayer - trying to re-create our sublayer with max weight 0x%04X", winlib.SUBLAYER_MAX_WEIGHT)
		if err = createAddSublayer(); err != nil {
			log.Error(reregisterMsg + ": FAILED")
		} else {
			log.Debug("called createAddSublayer()")
			installed, err = checkSublayerInstalled()
			if err != nil {
				return fmt.Errorf("failed to check sublayer is installed: %w", err)
			}
			if installed && ourSublayerWeight == winlib.SUBLAYER_MAX_WEIGHT {
				log.Info(reregisterMsg + ": SUCCESS")
				return nil
			} else {
				otherVpnUnknownErr.containedErr = fmt.Errorf("error registering our sublayer with max weight 0x%04X", winlib.SUBLAYER_MAX_WEIGHT)
			}
		}
	}

	return err
}

// implInitialize doing initialization stuff (called on application start)
func implInitialize() (retErr error) {
	if retErr = winlib.Initialize(platform.WindowsWFPDllPath()); retErr != nil {
		return retErr
	}

	// get path to 'powershell' binary
	envVarSystemroot := strings.ToLower(os.Getenv("SYSTEMROOT"))
	if len(envVarSystemroot) == 0 {
		log.Error("!!! ERROR !!! Unable to determine 'SYSTEMROOT' environment variable!")
	} else {
		powershellBinaryPath = strings.ReplaceAll(path.Join(envVarSystemroot, "system32", "WindowsPowerShell", "v1.0", "powershell.exe"), "/", "\\")
	}

	return checkCreateProviderAndSublayer(false, false)
}

func implGetEnabled() (bool, error) {
	found, pInfo, err := manager.GetProviderInfo(providerKey)
	if err != nil {
		_isEnabled = false
		return false, fmt.Errorf("failed to get provider info: %w", err)
	}
	return found && pInfo.IsInstalled && _isEnabled, nil
}

func implSetEnabled(isEnabled, wfpTransactionAlreadyInProgress bool) (retErr error) {
	if !wfpTransactionAlreadyInProgress {
		if retErr = manager.TransactionStart(); retErr != nil { // start WFP transaction
			return fmt.Errorf("failed to start transaction: %w", retErr)
		}
	}
	defer func() { // do not forget to stop WFP transaction
		if wfpTransactionAlreadyInProgress {
			return
		}
		var r any = recover()
		if retErr == nil && r == nil {
			manager.TransactionCommit() // commit WFP transaction
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	if isEnabled {
		return doEnable(true)
	}
	return doDisable(true)
}

func implSetPersistent(persistent bool) (retErr error) {
	// if persistent {
	// 	return fmt.Errorf("error - WFP (Windows Filtering Platform) persistence not supported")
	// }

	// save persistent state
	isPersistent = persistent

	found, pinfo, err := manager.GetProviderInfo(providerKey)
	if err != nil {
		return fmt.Errorf("failed to get provider info: %w", err)
	}

	if found && pinfo.IsInstalled {
		if pinfo.IsPersistent == isPersistent {
			log.Info(fmt.Sprintf("Already enabled (persistent=%t).", isPersistent))
			return nil
		}

		log.Info(fmt.Sprintf("Re-enabling with persistent flag = %t", isPersistent))
		return implReEnable()
	}

	return doEnable(false)
}

// ClientConnected - allow communication for local vpn/client IP address
func implClientConnected(clientLocalIPAddress net.IP, clientLocalIPv6Address net.IP, clientPort int, serverIP net.IP, serverPort int, isTCP bool) (retErr error) {
	// TODO FIXME: Vlad - do we need this?
	if err := manager.TransactionStart(); err != nil { // start WFP transaction
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { // do not forget to stop WFP transaction
		var r any = recover()
		if retErr == nil && r == nil {
			manager.TransactionCommit() // commit WFP transaction
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	err := doRemoveClientIPFilters()
	if err != nil {
		log.Error("Failed to remove previously defined client IP filters: ", err)
	}
	return doAddClientIPFilters(clientLocalIPAddress, clientLocalIPv6Address)
}

// ClientDisconnected - Disable communication for local vpn/client IP address
func implClientDisconnected() (retErr error) {
	// TODO FIXME: Vlad - do we need this?
	if err := manager.TransactionStart(); err != nil { // start WFP transaction
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { // do not forget to stop WFP transaction
		var r any = recover()
		if retErr == nil && r == nil {
			manager.TransactionCommit() // commit WFP transaction
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	return doRemoveClientIPFilters()
}

func implAddHostsToExceptions(IPs []net.IP, onlyForICMP bool, isPersistent bool) error {
	// nothing to do for windows implementation
	return nil
}

func implRemoveHostsFromExceptions(IPs []net.IP, onlyForICMP bool, isPersistent bool) error {
	// nothing to do for windows implementation
	return nil
}

// AllowLAN - allow/forbid LAN communication
func implAllowLAN(allowLan bool, allowLanMulticast bool) error {
	if isAllowLAN == allowLan && isAllowLANMulticast == allowLanMulticast {
		return nil
	}
	log.Debug(fmt.Sprintf("implAllowLAN: allowLan=%t allowLanMulticast=%t", allowLan, allowLanMulticast))

	isAllowLAN = allowLan
	isAllowLANMulticast = allowLanMulticast

	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}
	if !enabled {
		return nil
	}

	return implReEnable()
}

// OnChangeDNS - must be called on each DNS change (to update firewall rules according to new DNS configuration)
func implOnChangeDNS(dnsServers *[]net.IP) (err error) {
	log.Info("implOnChangeDNS")
	if dnsServers == nil || reflect.DeepEqual(*dnsServers, customDnsServers) || net.IPv4zero.Equal((*dnsServers)[0]) {
		return nil
	}

	customDnsServers = *dnsServers

	if enabled, err := implGetEnabled(); err != nil {
		return log.ErrorFE("failed to get info if firewall is on: %w", err)
	} else if !enabled {
		return nil
	}

	// for those new servers that match one of stock DNS servers for our Wireguard config(s), no need to add new firewall rules or nft set entries for them
	prefs := getPrefsCallback()
	var _newDnsServers []net.IP
	for _, dnsSrv := range customDnsServers {
		if !prefs.AllDnsServersIPv4Set.Contains(dnsSrv.String()) && !net.IPv4zero.Equal(dnsSrv) {
			_newDnsServers = append(_newDnsServers, dnsSrv)
		}
	}
	if len(_newDnsServers) < 1 {
		return nil
	}

	return implReEnable() // TODO FIXME: Vlad - do we really need full reenable here? maybe just add the allow inbound rule for the new DNS srv?
}

// implOnUserExceptionsUpdated() called when 'userExceptions' value were updated. Necessary to update firewall rules.
func implOnUserExceptionsUpdated() error {
	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}
	if !enabled {
		return nil
	}

	return implReEnable()
}

// implReEnable unconditionally starts WFP transaction, so callers must not have started one already
func implReEnable() (retErr error) {
	log.Info("implReEnable")
	if err := manager.TransactionStart(); err != nil { // start WFP transaction
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { // do not forget to stop WFP transaction
		var r any = recover()
		if retErr == nil && r == nil {
			manager.TransactionCommit() // commit WFP transaction
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	if err := doDisable(true); err != nil {
		return fmt.Errorf("failed to disable firewall: %w", err)
	}

	if err := doEnable(true); err != nil {
		return fmt.Errorf("failed to enable firewall: %w", err)
	}

	return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
}

func icmpAllowHelper(icmpType, icmpCode uint16, layer syscall.GUID, IP, mask net.IP) error {
	icmpFilterDescr := fmt.Sprintf("ICMP %d-%d: allow remote net %s/%s", icmpType, icmpCode, IP, mask)
	_, err := manager.AddFilter(winlib.NewFilterICMPTypeCode(
		providerKey,
		layer,
		ourSublayerKey,
		filterDName,
		icmpFilterDescr,
		winlib.FwpActionPermit,
		icmpType,
		icmpCode,
		IP,
		mask,
		isPersistent,
		winlib.FILTER_MAX_WEIGHT))
	if err != nil {
		return log.ErrorE(fmt.Errorf("failed to add filter '%s': %w", icmpFilterDescr, err), 0)
	}
	return nil
}

// icmpv4DefaultsForHostNet - allow echo request out, echo reply in, and bi-directional fragmentation messages. Weight 15.
func icmpv4DefaultsForHostNet(ipOrNet, netmask net.IP) (err error) {
	if err = icmpAllowHelper(winlib.ICMP_IPv4_ECHO_REQUEST_Type, winlib.ICMP_IPv4_ECHO_REQUEST_Code, winlib.FwpmLayerOutboundIcmpErrorV4,
		ipOrNet, netmask); err != nil {
		return err
	}
	if err = icmpAllowHelper(winlib.ICMP_IPv4_ECHO_REPLY_Type, winlib.ICMP_IPv4_ECHO_REPLY_Code, winlib.FwpmLayerInboundIcmpErrorV4,
		ipOrNet, netmask); err != nil {
		return err
	}
	for _, icmpv4AllowLayer := range []syscall.GUID{winlib.FwpmLayerOutboundIcmpErrorV4, winlib.FwpmLayerInboundIcmpErrorV4} { // weight 15
		if err = icmpAllowHelper(winlib.ICMP_IPv4_DESTINATION_UNREACHABLE_Type, winlib.ICMP_IPv4_FRAGMENTATION_REQUIRED_Code,
			icmpv4AllowLayer, ipOrNet, netmask); err != nil {
			return err
		}
	}

	return nil
}

func doEnable(wfpTransactionAlreadyInProgress bool) (err error) {
	log.Info("doEnable")
	implSingleDnsRuleOff()

	if enabled, err := implGetEnabled(); err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	} else if enabled {
		return nil
	}

	var localAddressesV6, localAddressesV4, multicastAddressesV6, multicastAddressesV4 []net.IPNet
	if isAllowLAN {
		localAddressesV6 = filterIPNetList(netinfo.GetNonRoutableLocalAddrRanges(), true)
		localAddressesV4 = filterIPNetList(netinfo.GetNonRoutableLocalAddrRanges(), false)

		if isAllowLANMulticast { // Multicast
			multicastAddressesV6 = filterIPNetList(netinfo.GetMulticastAddresses(), true)
			multicastAddressesV4 = filterIPNetList(netinfo.GetMulticastAddresses(), false)

		}
	}

	if err = checkCreateProviderAndSublayer(wfpTransactionAlreadyInProgress, false); err != nil {
		return fmt.Errorf("failed to check/create provider or sublayer: %w", err)
	}

	vpnEntryHostsParsed := getPrefsCallback().VpnEntryHostsParsed

	// IPv6 filters - in and out
	for _, ipv6Layer := range v6LayersAll {
		ipv6loopback := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}     // LOOPBACK 		::1/128
		ipv6llocal := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // LINKLOCAL		fe80::/10 // TODO: "fe80::/10" is already part of localAddressesV6. To think: do we need it here?

		// TODO FIXME: Vlad - do we need to whitelist IPv6 loopback?
		if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, ipv6Layer, ourSublayerKey, filterDName,
			"IPv6: loopback", ipv6loopback, 128, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
			return fmt.Errorf("failed to add filter 'allow remote IP' for ipv6loopback: %w", err)
		}
		if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, ipv6Layer, ourSublayerKey, filterDName,
			"IPv6: local", ipv6llocal, 10, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
			return fmt.Errorf("failed to add filter 'allow remote IP' for ipv6llocal: %w", err)
		}

		// TODO FIXME: Vlad - do we really need to enable these LAN rules?
		if isAllowLAN { // LAN
			for _, ip := range localAddressesV6 {
				prefixLen, _ := ip.Mask.Size()
				if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, ipv6Layer, ourSublayerKey, filterDName,
					"IPv6: allow lan", ip.IP, byte(prefixLen), isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
					return fmt.Errorf("failed to add filter 'allow lan IPv6': %w", err)
				}
			}

			if isAllowLANMulticast { // LAN multicast
				for _, ip := range multicastAddressesV6 {
					prefixLen, _ := ip.Mask.Size()
					if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, ipv6Layer, ourSublayerKey, filterDName,
						"IPv6: allow LAN multicast", ip.IP, byte(prefixLen), isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
						return fmt.Errorf("failed to add filter 'allow LAN multicast IPv6': %w", err)
					}
				}
			}
		}

		// user exceptions
		userExpsNets := getUserExceptions(false, true)
		for _, n := range userExpsNets {
			prefixLen, _ := n.Mask.Size()
			if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, ipv6Layer, ourSublayerKey, filterDName,
				"IPv6: user exception"+n.IP.String(), n.IP, byte(prefixLen), isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return fmt.Errorf("failed to add filter 'user exception': %w", err)
			}
		}
	}

	// IPv6 filters - out: TODO: nothing yet
	// for _, ipv6LayerOut := range v6LayersOut {
	// 	// // block all
	// 	// _, err := manager.AddFilter(winlib.NewFilterBlockAll(providerKey, layer, sublayerKey, filterDName, "Block all", true, isPersistent, false, winlib.FILTER_MAX_WEIGHT))
	// 	// if err != nil {
	// 	// 	return fmt.Errorf("failed to add filter 'block all IPv6': %w", err)
	// 	// }
	// 	// if isPersistent {
	// 	// 	// For 'persistent' state we have to add boot-time blocking rule
	// 	// 	bootTime := true
	// 	// 	_, err = manager.AddFilter(winlib.NewFilterBlockAll(providerKey, layer, sublayerKey, filterDName, "Block all (boot time)", true, false, bootTime, winlib.FILTER_MAX_WEIGHT))
	// 	// 	if err != nil {
	// 	// 		return fmt.Errorf("failed to add boot-time filter 'block all IPv6': %w", err)
	// 	// 	}
	// 	// }

	// 	// // block DNS
	// 	// _, err = manager.AddFilter(winlib.NewFilterBlockDNS(providerKey, layer, sublayerKey, filterDName, "Block DNS", nil, isPersistent, winlib.FILTER_MAX_WEIGHT))
	// 	// if err != nil {
	// 	// 	return fmt.Errorf("failed to add filter 'block dns': %w", err)
	// 	// }

	// 	// TODO: Vlad - allow our IPv6 DNS servers when we have them
	// }

	// IPv6 filters - inbound
	for _, ipv6LayerIn := range v6LayersIn {
		// Block inbound forbidden ports: Microsoft, etc. Weight 15.
		for _, portToBlock := range microsoftPortsToBlock {
			filterDesc := fmt.Sprintf("IPv6: block local port %d", portToBlock)
			if _, err = manager.AddFilter(winlib.NewFilterBlockLocalPort(providerKey, ipv6LayerIn, ourSublayerKey, filterDName, filterDesc,
				portToBlock, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return fmt.Errorf("failed to add filter '%s': %w", filterDesc, err)
			}
		}
	}

	// IPv6 filters ICMP: TODO: allow bi-directional fragmentation messages, maybe more

	// IPv4 filters ICMP. TODO: Vlad - replicate ICMP logic to IPv6 also
	for _, vpnEntryHostParsed := range vpnEntryHostsParsed {
		vpnEntryHostIP := vpnEntryHostParsed.VpnEntryHostIP
		// ICMP: our Wireguard endpoint: allow echo request out, echo reply in, and bi-directional fragmentation messages. Weight 15.
		if err = icmpv4DefaultsForHostNet(vpnEntryHostIP, net.IPv4bcast); err != nil {
			return err
		}

		for _, allowedIP := range vpnEntryHostParsed.AllowedIPs {
			// Allow ICMP in+out to-from PL IP ranges. Allow echo request out, echo reply in, and bi-directional fragmentation messages. Weight 15.
			if err = icmpv4DefaultsForHostNet(allowedIP.IP, allowedIP.Netmask); err != nil {
				return err
			}

			// Block outgoing ICMP Destination Unreachable, IPv4. Rule weight 14.
			// This is to prevent UDP port scanning, per https://learn.microsoft.com/en-us/windows/win32/fwp/preventing-port-scanning
			// Vlad: not needed, Windows already includes filters to prevent port scanning, their description starts with "This filter prevents port scanning"
			// icmpFilterDescr := fmt.Sprintf("ICMP IPv4: DESTINATION_UNREACHABLE type - block remote net %s/%s", allowedIP.IP, allowedIP.Netmask)
			// _, err = manager.AddFilter(winlib.NewFilterICMPType(providerKey, winlib.FwpmLayerOutboundIcmpErrorV4, ourSublayerKey, filterDName, icmpFilterDescr,
			// 	winlib.FwpActionBlock, winlib.ICMP_IPv4_DESTINATION_UNREACHABLE_Type, allowedIP.IP, allowedIP.Netmask, isPersistent, winlib.FILTER_MAX_WEIGHT-1))
			// if err != nil {
			// 	return log.ErrorE(fmt.Errorf("failed to add filter '%s': %w", icmpFilterDescr, err), 0)
			// }
		}
	}

	// IPv4 filters - in and out
	for _, ipv4Layer := range v4LayersAll {
		// TODO: Vlad - do we need AllowRemoteIP for 127.0.0.1?
		if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, ipv4Layer, ourSublayerKey, filterDName,
			"allow remote IP 127.0.0.1", net.ParseIP("127.0.0.1"), net.IPv4bcast, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
			return fmt.Errorf("failed to add filter 'allow remote IP 127.0.0.1': %w", err)
		}

		// Allow our Wireguard gateway(s) in+out: UDP
		for _, vpnEntryHostParsed := range vpnEntryHostsParsed {
			vpnEntryHostIP := vpnEntryHostParsed.VpnEntryHostIP
			if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPProto(providerKey, ipv4Layer, ourSublayerKey, filterDName, "IPv4: allow remote IP - WG gateway "+vpnEntryHostIP.String(),
				vpnEntryHostIP, net.IPv4bcast, windows.IPPROTO_UDP, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return fmt.Errorf("failed to add filter 'IPv4: allow remote IP - WG gateway': '%s': %w", vpnEntryHostIP, err)
			}
		}

		// allow service binaries in+out
		for _, svcExe := range platform.PLServiceBinariesForFirewallToUnblock() {
			if _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, ipv4Layer, ourSublayerKey, filterDName,
				"IPv4: "+svcExe, svcExe, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return fmt.Errorf("failed to add filter 'IPv4: allow application': \"%s\": %w", svcExe, err)
			}
		}
	}

	// IPv4 filters - outbound
	for _, ipv4LayerOut := range v4LayersOut {
		// // block all
		// _, err := manager.AddFilter(winlib.NewFilterBlockAll(providerKey, layer, sublayerKey, filterDName, "Block all", false, isPersistent, false, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'block all': %w", err)
		// }
		// if isPersistent {
		// 	// For 'persistent' state we have to add boot-time blocking rule
		// 	bootTime := true
		// 	_, err = manager.AddFilter(winlib.NewFilterBlockAll(providerKey, layer, sublayerKey, filterDName, "Block all (boot time)", false, false, bootTime, winlib.FILTER_MAX_WEIGHT))
		// 	if err != nil {
		// 		return fmt.Errorf("failed to add boot-time filter 'block all': %w", err)
		// 	}
		// }

		// // block DNS
		// _, err = manager.AddFilter(winlib.NewFilterBlockDNS(providerKey, layer, sublayerKey, filterDName, "Block DNS", customDNS, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'block dns': %w", err)
		// }

		// allow outbound TCP+UDP to port 53 to our DNS servers, weight 15
		for _, vpnEntryHostParsed := range vpnEntryHostsParsed {
			for _, dnsSrv := range vpnEntryHostParsed.DnsServersIPv4 {
				if _, err = manager.AddFilter(winlib.NewFilterAllowDnsIPv4(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
					"Allow PL DNS "+dnsSrv.String(), dnsSrv, net.IPv4bcast, isPersistent)); err != nil {
					return fmt.Errorf("failed to add filter 'Allow PL DNS %s': %w", dnsSrv, err)
				}
			}
		}

		// Also allow custom DNS servers, if any
		for _, customDnsSrv := range customDnsServers {
			if !net.IPv4zero.Equal(customDnsSrv) {
				if _, err = manager.AddFilter(winlib.NewFilterAllowDnsIPv4(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
					"Allow PL customDNS "+customDnsSrv.String(), customDnsSrv, net.IPv4bcast, isPersistent)); err != nil {
					return fmt.Errorf("failed to add filter 'Allow PL customDNS %s': %w", customDnsSrv, err)
				}
			}
		}

		// Allow our Wireguard gateway(s) outgoing (to allow TCP)
		for _, vpnEntryHostParsed := range vpnEntryHostsParsed {
			vpnEntryHostIP := vpnEntryHostParsed.VpnEntryHostIP
			if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
				"IPv4: allow remote IP - WG gateway "+vpnEntryHostIP.String(), vpnEntryHostIP, net.IPv4bcast, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return fmt.Errorf("failed to add filter 'IPv4: allow remote IP - WG gateway': '%s': %w", vpnEntryHostIP, err)
			}
		}

		// TODO: Vlad - disabled, no need to allow REST API hosts explicitly anymore, after I added "ALE Flow Established v4 Layer" to allowed outbound layers for service binaries.
		// // Allow outbound TCP to our REST API hosts
		// for _, restApiHostname := range api.REST_API_hosts {
		// 	restApiHostIPs, err := net.LookupIP(restApiHostname)
		// 	if err != nil {
		// 		log.ErrorFE("error - could not lookup IPs for '%s': %w", restApiHostname, err)
		// 		continue
		// 	}

		// 	for _, restApiHostIP := range restApiHostIPs {
		// 		filterDesc := fmt.Sprintf("IPv4 TCP out: allow remote hostname %s", restApiHostname)
		// 		log.Debug(fmt.Sprintf("added filter '%s' with IP=%s", filterDesc, restApiHostIP))

		// 		if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPProto(providerKey, ipv4LayerOut, ourSublayerKey, filterDName, filterDesc,
		// 			restApiHostIP, net.IPv4bcast, windows.IPPROTO_TCP, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
		// 			return log.ErrorFE("failed to add filter '%s': %w", filterDesc, err)
		// 		}
		// 	}
		// }

		// // allow DNS requests to 127.0.0.1:53
		// _, err = manager.AddFilter(winlib.AllowRemoteLocalhostDNS(providerKey, layer, sublayerKey, filterDName, "", isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow localhost dns': %w", err)
		// }

		// // allow DHCP port
		// _, err = manager.AddFilter(winlib.NewFilterAllowLocalPort(providerKey, layer, sublayerKey, filterDName, "", 68, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow dhcp': %w", err)
		// }

		// // allow OpenVPN executable
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, filterDName, "", platform.OpenVpnBinaryPath(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - openvpn': %w", err)
		// }
		// // allow obfsproxy
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, filterDName, "", platform.ObfsproxyStartScript(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - obfsproxy': %w", err)
		// }
		// // allow V2Ray
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, filterDName, "", platform.V2RayBinaryPath(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - V2Ray': %w", err)
		// }
		// // allow dnscrypt-proxy
		// dnscryptProxyBin, _, _, _ := platform.DnsCryptProxyInfo()
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, filterDName, "", dnscryptProxyBin, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - dnscrypt-proxy': %w", err)
		// }

		// Permit all apps outbound access to privateLINE private IP ranges
		// TODO: until we implement App Whitelist on Windows
		for _, vpnEntryHostParsed := range vpnEntryHostsParsed {
			for _, allowedIP := range vpnEntryHostParsed.AllowedIPs { // default out (TCP+UDP)
				if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
					"IPv4: allow remote IP - allowedIPs entry", allowedIP.IP, allowedIP.Netmask, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
					return fmt.Errorf("failed to add filter 'IPv4: allow remote IP - allowedIPs entry': '%s/%s': %w", allowedIP.IP, allowedIP.Netmask, err)
				}
			}
		}

		// TODO FIXME: Vlad - do we really need to enable these LAN rules?
		if isAllowLAN { // LAN
			for _, ip := range localAddressesV4 {
				if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
					"IPv4: allow LAN", ip.IP, net.IP(ip.Mask), isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
					return fmt.Errorf("failed to add filter 'IPv4: allow LAN': %w", err)
				}
			}

			// Multicast
			if isAllowLANMulticast { // LAN multicast
				for _, ip := range multicastAddressesV4 {
					if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
						"IPv4: allow LAN multicast", ip.IP, net.IP(ip.Mask), isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
						return fmt.Errorf("failed to add filter 'IPv4: allow LAN multicast': %w", err)
					}
				}
			}
		}

		// user exceptions
		userExpsNets := getUserExceptions(true, false)
		for _, n := range userExpsNets {
			if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, ipv4LayerOut, ourSublayerKey, filterDName,
				"IPv4: user exception", n.IP, net.IP(n.Mask), isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return fmt.Errorf("failed to add filter IPv4: 'user exception': %w", err)
			}
		}
	}

	// IPv4 filters - inbound
	for _, ipv4LayerIn := range v4LayersIn {
		// Allow incoming UDP packets with source port 53 from PL DNS servers. Weight 15.
		for _, vpnEntryHostParsed := range vpnEntryHostsParsed {
			for _, dnsSrv := range vpnEntryHostParsed.DnsServersIPv4 {
				if _, err = manager.AddFilter(winlib.NewFilterAllowDnsUdpIPv4(providerKey, ipv4LayerIn, ourSublayerKey, filterDName,
					"Allow PL DNS "+dnsSrv.String(), dnsSrv, net.IPv4bcast, isPersistent)); err != nil {
					return fmt.Errorf("failed to add filter 'Allow PL DNS %s': %w", dnsSrv, err)
				}
			}
		}

		// Also allow custom DNS servers, if any
		for _, customDnsSrv := range customDnsServers {
			if !net.IPv4zero.Equal(customDnsSrv) {
				if _, err = manager.AddFilter(winlib.NewFilterAllowDnsUdpIPv4(providerKey, ipv4LayerIn, ourSublayerKey, filterDName,
					"Allow PL customDNS "+customDnsSrv.String(), customDnsSrv, net.IPv4bcast, isPersistent)); err != nil {
					return fmt.Errorf("failed to add filter 'Allow PL customDNS %s': %w", customDnsSrv, err)
				}
			}
		}

		// Allow our other apps (PL Comms, etc.) in: UDP. Weight 15.
		if plOtherApps, err := platform.PLOtherAppsToAcceptIncomingConnections(); err != nil {
			log.Error(fmt.Errorf("error enumerating other PL apps: %w", err)) // silently continue
		} else {
			for _, plOtherApp := range plOtherApps {
				filterDesc := fmt.Sprintf("IPv4 UDP: allow %s", plOtherApp)
				if _, err = manager.AddFilter(winlib.NewFilterAllowApplicationProto(providerKey, ipv4LayerIn, ourSublayerKey, filterDName,
					filterDesc, plOtherApp, windows.IPPROTO_UDP, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
					return fmt.Errorf("failed to add filter '%s': %w", filterDesc, err)
				}
			}
		}

		// Also allow inbound UDP for PL internal hosts. Weight 15.
		// If VPN is not yet connected - we may not know their current IPs yet, so here we are registering default cached IPs.
		for _, plInternalHost := range *platform.PLInternalHostsToAcceptIncomingUdpFrom() {
			filterDesc := fmt.Sprintf("IPv4 UDP: allow cached IP %s for internal remote hostname %s", plInternalHost.DefaultIpString, plInternalHost.Hostname)
			if _, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPProto(providerKey, ipv4LayerIn, ourSublayerKey, filterDName, filterDesc,
				plInternalHost.DefaultIP.To4(), net.IPv4bcast, windows.IPPROTO_UDP, isPersistent, winlib.FILTER_MAX_WEIGHT)); err != nil {
				return log.ErrorFE("failed to add filter '%s': %w", filterDesc, err)
			}
		}

		// Block inbound forbidden ports: Microsoft, etc. Weight 14.
		for _, portToBlock := range microsoftPortsToBlock {
			filterDesc := fmt.Sprintf("IPv4: block local port %d", portToBlock)
			if _, err = manager.AddFilter(winlib.NewFilterBlockLocalPort(providerKey, ipv4LayerIn, ourSublayerKey, filterDName, filterDesc,
				portToBlock, isPersistent, winlib.FILTER_MAX_WEIGHT-1)); err != nil {
				return fmt.Errorf("failed to add filter '%s': %w", filterDesc, err)
			}
		}
	}

	_isEnabled = true
	return nil
}

func doDisable(wfpTransactionAlreadyInProgress bool) error {
	log.Info("doDisable")
	implSingleDnsRuleOff()

	var err error
	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}

	// retry moving our sublayer to top priority - actually don't, as otherwise cleanup on uninstall doesn't work properly
	// if err = checkCreateProviderAndSublayer(wfpTransactionAlreadyInProgress, false); err != nil {
	// 	err = log.ErrorE(fmt.Errorf("failed to check/create provider or sublayer: %w", err), 0)
	// }

	if !enabled { // Vlad - doDisable() is essentially cleaning out old rules, may need to run this even if firewall was disabled to begin with
		log.Info("firewall was already disabled, but cleaning out rules in all our layers anyway")
		//return nil
	}

	for _, l := range layersAllToClean { // delete filters
		// delete filters and callouts registered for the provider+layer
		if err := manager.DeleteFilterByProviderKey(providerKey, l); err != nil {
			return fmt.Errorf("failed to delete filter : %w", err)
		}
	}

	clientLocalIPFilterIDs = nil

	_isEnabled = false
	return err
}

func deleteSublayerAndProvider(sublayerKey, _providerKey syscall.GUID) (retErr error) {
	// delete sublayer
	installed, _, err := manager.GetSubLayerByKey(sublayerKey)
	if err != nil {
		retErr = log.ErrorE(fmt.Errorf("failed to check whether sublayer '%s' is installed: %w", windows.GUID(sublayerKey).String(), err), 0)
	} else if installed {
		for _, l := range layersAllToClean { // delete filters
			// delete filters and callouts registered for the provider+layer
			if err := manager.DeleteFilterByProviderKey(_providerKey, l); err != nil {
				retErr = log.ErrorE(fmt.Errorf("failed to delete filter under provider '%s' : %w", windows.GUID(_providerKey).String(), err), 0)
			}
		}

		if _, err := manager.DeleteSubLayer(sublayerKey); err != nil {
			retErr = log.ErrorE(fmt.Errorf("failed to delete sublayer '%s': %w", windows.GUID(sublayerKey).String(), err), 0)
		}
	}

	// delete provider
	if found, pinfo, err := manager.GetProviderInfo(_providerKey); err != nil {
		retErr = log.ErrorE(fmt.Errorf("failed to get provider '%s' info: %w", windows.GUID(_providerKey).String(), err), 0)
	} else if found && pinfo.IsInstalled {
		if err := manager.DeleteProvider(_providerKey); err != nil {
			retErr = log.ErrorE(fmt.Errorf("failed to delete provider '%s': %w", windows.GUID(_providerKey).String(), err), 0)
		}
	}

	return retErr
}

func implCleanupRegistration() (retErr error) {
	log.Info("========================================================================================================================")
	log.Info("implCleanupRegistration")

	if retErr = deleteSublayerAndProvider(ourSublayerKey, providerKey); retErr != nil {
		retErr = log.ErrorE(fmt.Errorf("error deleting main sublayer and provider: %w", retErr), 0)
	}

	if err := deleteSublayerAndProvider(sublayerKeySingleDns, providerKeySingleDns); err != nil {
		log.Warning(fmt.Errorf("error deleting single DNS sublayer and provider: %w", err), 0)
	}

	log.Info("========================================================================================================================")
	return retErr
}

// implDeployPostConnectionRules might be called asynchronously w/o checking return, so log everything
func implDeployPostConnectionRules() (retErr error) {
	if err := manager.TransactionStart(); err != nil { // start WFP transaction
		return log.ErrorE(fmt.Errorf("failed to start transaction: %w", err), 0)
	}
	defer func() { // do not forget to stop WFP transaction
		var r any = recover()
		if r == nil { // we don't care abt retErr here, commit anyway if retErr != nil
			manager.TransactionCommit() // commit WFP transaction
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	// Allow our hosts (meet.privateline.network, etc.) in: UDP
	for _, plInternalHost := range *platform.PLInternalHostsToAcceptIncomingUdpFrom() {
		var (
			IPs        []net.IP
			filterDesc string
			layersIn   []syscall.GUID
		)

		if IPs, retErr = net.LookupIP(plInternalHost.Hostname); retErr != nil {
			retErr = log.ErrorFE("could not lookup IPs for '%s': %w", plInternalHost.Hostname, retErr)
			continue
		}

		for _, IP := range IPs {
			if IP.To4() == nil { // IPv6
				if net.IPv6zero.Equal(IP) {
					continue
				}
				filterDesc = fmt.Sprintf("IPv6 UDP: allow remote hostname %s", plInternalHost.Hostname)
				layersIn = v6LayersIn
			} else if !plInternalHost.DefaultIP.Equal(IP) { // IPv4, and it's a new IP, not the known cached one
				if net.IPv4zero.Equal(IP) {
					continue
				}
				filterDesc = fmt.Sprintf("IPv4 UDP: allow remote hostname %s", plInternalHost.Hostname)
				layersIn = v4LayersIn
			} else { // IP already registered, skip it
				continue
			}

			log.Debug(fmt.Sprintf("post-connection: added filter '%s' with IP=%s", filterDesc, IP))
			for _, layer := range layersIn {
				if _, retErr = manager.AddFilter(winlib.NewFilterAllowRemoteIPProto(providerKey, layer, ourSublayerKey, filterDName, filterDesc,
					IP, net.IPv4bcast, windows.IPPROTO_UDP, isPersistent, winlib.FILTER_MAX_WEIGHT)); retErr != nil {
					retErr = log.ErrorFE("failed to add filter '%s': %w", filterDesc, retErr)
				}
			}
		}
	}

	return retErr
}

// We either disable IPv6 on all network interfaces for Total Shield on, or enable it back when Total Shield off.
// Running the PowerShell asynchronously (fork and forget) - flipping to Enable or Disable on cmdline takes 6.8-6.9 seconds on my laptop
func enableDisableIPv6(enable bool /*, responseChan chan error*/) {
	enableDisableIPv6Mutex.Lock() // since this func runs async, must lock it to ensure it's single-instance
	defer enableDisableIPv6Mutex.Unlock()

	// don't leave PrintStack calls enabled in production builds beyond the MVP
	// logger.PrintStackToStderr()

	cmd := []string{"-NoProfile", "", "-Name", "\"*\"", "-ComponentID", "ms_tcpip6"}
	if enable {
		cmd[1] = "Enable-NetAdapterBinding"
	} else {
		cmd[1] = "Disable-NetAdapterBinding"
	}

	if err := shell.Exec(log, powershellBinaryPath, cmd...); err != nil {
		// responseChan <- log.ErrorE(fmt.Errorf("failed to change IPv6 bindings (isStEnabled=%v): %w", enable, err), 0)
		log.ErrorFE("failed to change IPv6 bindings (enable=%t): %w", enable, err)
	} /* else {
		responseChan <- nil
	}*/
}

func implTotalShieldApply(_totalShieldEnabled bool) (err error) {
	log.Debug("implTotalShieldApply entered")
	defer log.Debug("implTotalShieldApply exited")

	if totalShieldEnabled == _totalShieldEnabled {
		return nil
	}

	if firewallEnabled, err := implGetEnabled(); err != nil {
		return fmt.Errorf("implTotalShieldApply() failed to get info if firewall is on: %w", err)
	} else if !firewallEnabled { // nothing to do
		return nil
	}

	if err := manager.TransactionStart(); err != nil { // start WFP transaction
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { // do not forget to stop WFP transaction
		var r any = recover()
		if err == nil && r == nil {
			manager.TransactionCommit() // commit WFP transaction
			totalShieldEnabled = _totalShieldEnabled
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					err = e
				} else {
					err = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	var filterDesc = "Total Shield block all"
	toEnableTotalShield := _totalShieldEnabled && vpnConnectedOrConnectingCallback() // Enable Total Shield block rules only if VPN is connected or connecting
	if toEnableTotalShield {
		log.Debug("enabling " + filterDesc)
	} else {
		log.Debug("disabling " + filterDesc)
	}

	for _, totalShieldLayer := range totalShieldLayers {
		if toEnableTotalShield {
			if totalShieldLayer.blockAllFilterID == 0 {
				if totalShieldLayer.blockAllFilterID, err = manager.AddFilter(winlib.NewFilterBlockAll(providerKey, totalShieldLayer.layerGUID, ourSublayerKey,
					filterDName, filterDesc, totalShieldLayer.isIPv6, isPersistent, false)); err != nil {
					return log.ErrorFE("failed to add filter '%s': %w", filterDesc, err)
				}
			}
		} else if totalShieldLayer.blockAllFilterID != 0 { // shouldn't be 0, but just in case
			if err2 := manager.DeleteFilterByID(totalShieldLayer.blockAllFilterID); err2 != nil {
				err2 = log.ErrorFE("failed to delete filter '%s' by id %d: %w", filterDesc, totalShieldLayer.blockAllFilterID, err2)
				if err == nil {
					err = err2 // and continue deleting other filters anyway, gotta cleanup at least partially
				}
			}
			totalShieldLayer.blockAllFilterID = 0
		}
	}

	go enableDisableIPv6(!toEnableTotalShield) // fork it in the background, as it takes ~7 seconds

	return err
}

func doAddClientIPFilters(clientLocalIP net.IP, clientLocalIPv6 net.IP) (retErr error) {
	if clientLocalIP == nil {
		return nil
	}

	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}
	if !enabled {
		return nil
	}

	filters := make([]uint64, 0, len(v4LayersAll))
	for _, layer := range v4LayersAll {
		f := winlib.NewFilterAllowLocalIP(providerKey, layer, ourSublayerKey, filterDName, "clientLocalIP", clientLocalIP, net.IPv4bcast, false)
		id, err := manager.AddFilter(f)
		if err != nil {
			return fmt.Errorf("failed to add filter 'clientLocalIP' : %w", err)
		}
		filters = append(filters, id)
	}

	// IPv6: allow IPv6 communication inside tunnel
	if clientLocalIPv6 != nil {
		for _, layer := range v6LayersAll {
			f := winlib.NewFilterAllowLocalIPV6(providerKey, layer, ourSublayerKey, filterDName, "clientLocalIPv6", clientLocalIPv6, byte(128), false)
			id, err := manager.AddFilter(f)
			if err != nil {
				return fmt.Errorf("failed to add filter 'clientLocalIPv6' : %w", err)
			}
			filters = append(filters, id)
		}
	}

	clientLocalIPFilterIDs = filters

	return nil
}

func doRemoveClientIPFilters() (retErr error) {
	defer func() {
		clientLocalIPFilterIDs = nil
	}()

	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}
	if !enabled {
		return nil
	}

	for _, filterID := range clientLocalIPFilterIDs {
		err := manager.DeleteFilterByID(filterID)
		if err != nil {
			return fmt.Errorf("failed to delete filter : %w", err)
		}
	}

	return nil
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

func implSingleDnsRuleOff() (retErr error) {
	// TODO FIXME: Vlad - disabled
	// log.Debug("implSingleDnsRuleOn - disabled (providerKeySingleDns not installed), exiting")
	return nil

	/*
		// TODO FIXME: Vlad - disable much or all of functionality
		log.Debug("implSingleDnsRuleOff - largely disabled")

		pInfo, err := manager.GetProviderInfo(providerKeySingleDns)
		if err != nil {
			return fmt.Errorf("failed to get provider info: %w", err)
		}
		if !pInfo.IsInstalled {
			log.Debug("providerKeySingleDns not installed, returning from implSingleDnsRuleOff early")
			return nil
		}

		// delete filters
		for _, l := range v6LayersAll {
			// delete filters and callouts registered for the provider+layer
			if err := manager.DeleteFilterByProviderKey(providerKeySingleDns, l); err != nil {
				return fmt.Errorf("failed to delete filter : %w", err)
			}
		}

		for _, l := range v4LayersAll {
			// delete filters and callouts registered for the provider+layer
			if err := manager.DeleteFilterByProviderKey(providerKeySingleDns, l); err != nil {
				return fmt.Errorf("failed to delete filter : %w", err)
			}
		}

		// delete sublayer
		installed, _, err := manager.GetSubLayerByKey(sublayerKeySingleDns)
		if err != nil {
			return fmt.Errorf("failed to check whether sublayer is installed: %w", err)
		}
		if installed {
			var notFound bool
			if notFound, err = manager.DeleteSubLayer(sublayerKeySingleDns); err != nil {
				return fmt.Errorf("failed to delete sublayer : %w", err)
			}
			if notFound {
				log.Info("sublayer sublayerKeySingleDns='" + windows.GUID(sublayerKeySingleDns).String() + "' not found, so couldn't delete")
			}
		}

		// delete provider
		if err := manager.DeleteProvider(providerKeySingleDns); err != nil {
			return fmt.Errorf("failed to delete provider : %w", err)
		}
		return nil
	*/
}

func implSingleDnsRuleOn(dnsAddr net.IP) (retErr error) {
	// TODO FIXME: Vlad - disabled
	log.Debug("implSingleDnsRuleOn - disabled, exiting")
	return nil

	/*
		enabled, err := implGetEnabled()
		if err != nil {
			return err
		} else if enabled {
			return fmt.Errorf("failed to apply specific DNS rule: Firewall already enabled")
		}

		if dnsAddr == nil {
			return fmt.Errorf("DNS address not defined")
		}

		if err := manager.TransactionStart(); err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		// do not forget to stop WFP transaction
		defer func() {
			if r := recover(); r == nil {
				manager.TransactionCommit() // commit WFP transaction
			} else {
				manager.TransactionAbort() // abort WFP transaction

				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}()

		if err = checkCreateProviderAndSublayer(true, false); err != nil {
			return fmt.Errorf("failed to check/create provider or sublayer: %w", err)
		}

		var ipv6DnsIpException net.IP = nil
		var ipv4DnsIpException net.IP = nil
		if dnsAddr.To4() == nil {
			ipv6DnsIpException = dnsAddr
		} else {
			ipv4DnsIpException = dnsAddr
		}

		// IPv6 filters
		for _, layer := range v6Layers {
			// block DNS
			_, err = manager.AddFilter(winlib.NewFilterBlockDNS(providerKeySingleDns, layer, sublayerKeySingleDns, filterDNameSingleDns, "Block DNS", ipv6DnsIpException, false, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'block dns': %w", err)
			}
		}

		// IPv4 filters
		for _, layer := range v4Layers {
			// block DNS
			_, err = manager.AddFilter(winlib.NewFilterBlockDNS(providerKeySingleDns, layer, sublayerKeySingleDns, filterDNameSingleDns, "Block DNS", ipv4DnsIpException, false, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'block dns': %w", err)
			}
			// allow DNS requests to 127.0.0.1:53
			_, err = manager.AddFilter(winlib.AllowRemoteLocalhostDNS(providerKeySingleDns, layer, sublayerKeySingleDns, filterDNameSingleDns, "", false, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'allow localhost dns': %w", err)
			}
			// allow V2Ray: to avoid blocking connections to V2Ray port 53
			_, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKeySingleDns, layer, sublayerKeySingleDns, filterDNameSingleDns, "", platform.V2RayBinaryPath(), false, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'allow application - V2Ray': %w", err)
			}
		}
		return nil
	*/
}

// Try to figure out the name of the other VPN:
//   - if sublayer name is not a GUID, then use it
//   - if sublayer name is a GUID, then try to lookup provider; if its name is not empty - then use it
//   - else use sublayer name
func getOtherVpnInfo(_otherSublayerGUID syscall.GUID) (otherVpnName, otherVpnDescription string, err error) {
	otherSublayerFound, otherSublayer, err := manager.GetSubLayerByKey(_otherSublayerGUID)
	if err != nil || !otherSublayerFound {
		return "", "", err
	}

	if !helpers.IsAGuidString(otherSublayer.Name) || reflect.DeepEqual(otherSublayer.ProviderKey, ZeroGUID) {
		return otherSublayer.Name, otherSublayer.Description, nil
	}

	// if sublayer name is a GUID, try to lookup provider name instead
	if providerFound, providerInfo, err := manager.GetProviderInfo(otherSublayer.ProviderKey); err != nil || !providerFound || providerInfo.Name == "" {
		return otherSublayer.Name, otherSublayer.Description, err
	} else {
		return providerInfo.Name, otherSublayer.Description, nil
	}
}

func implHaveTopFirewallPriority(recursionDepth uint8) (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	if recursionDepth == 0 { // start WFP transaction on the 1st recursion call
		if retErr = manager.TransactionStart(); retErr != nil {
			return false, "", "", "", fmt.Errorf("failed to start transaction: %w", retErr)
		}
	}
	defer func() { // do not forget to stop WFP transaction
		if recursionDepth > 1 {
			return
		}
		var r any = recover()
		if retErr == nil && r == nil {
			manager.TransactionCommit() // commit WFP transaction
		} else {
			manager.TransactionAbort() // abort WFP transaction

			if r != nil {
				log.Error("PANIC (recovered): ", r)
				if e, ok := r.(error); ok {
					retErr = e
				} else {
					retErr = errors.New(fmt.Sprint(r))
				}
			}
		}
	}()

	var (
		ourSublayerInstalled, otherSublayerFound bool
		_otherSublayerGUID                       syscall.GUID
	)

	if ourSublayerInstalled, retErr = checkSublayerInstalled(); retErr != nil {
		return false, "", "", "", fmt.Errorf("error checking whether our sublayer is installed: %w", retErr)
	}
	if !ourSublayerInstalled {
		if recursionDepth == 0 { // if our sublayer wasn't installed - try to create and add it
			if retErr = checkCreateProviderAndSublayer(true, false); retErr != nil {
				return false, "", "", "", fmt.Errorf("error creating our sublayer: %w", retErr)
			}
			return implHaveTopFirewallPriority(recursionDepth + 1)
		}
		return false, "", "", "", fmt.Errorf("error - our sublayer isn't installed: %w", retErr) // already tried creating it in the parent call
	}

	if ourSublayerWeight == winlib.SUBLAYER_MAX_WEIGHT {
		return true, "", "", "", nil
	}

	// ok, by this point we know that our sublayer is installed and that it doesn't have max weight
	otherSublayerFound, _otherSublayerGUID, retErr = findOtherSublayerWithMaxWeight() // check if max weight slot is vacant
	if retErr != nil {
		return false, "", "", "", fmt.Errorf("failed to check for other sublayer with max weight: %w", retErr)
	}
	if otherSublayerFound {
		otherVpnID = windows.GUID(_otherSublayerGUID).String()
		otherVpnName, otherVpnDescription, retErr = getOtherVpnInfo(_otherSublayerGUID)
		return false, otherVpnID, otherVpnName, otherVpnDescription, retErr
	}

	if recursionDepth >= 2 { // terminate the recursion finally
		return false, "", "", "", nil
	}

	// yay, we haven't reached bottom of recursion yet, and the top slot is vacant - try to occupy it
	if retErr = checkCreateProviderAndSublayer(true, false); retErr != nil {
		return false, "", "", "", retErr
	}
	return implHaveTopFirewallPriority(recursionDepth + 1)
}

func implGetFirewallBackgroundMonitors() []*FirewallBackgroundMonitor {
	return []*FirewallBackgroundMonitor{}
}
