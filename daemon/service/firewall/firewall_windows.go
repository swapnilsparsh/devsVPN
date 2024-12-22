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
	"strings"
	"sync"
	"syscall"

	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall/winlib"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"golang.org/x/sys/windows"
)

var (
	providerKey          = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x01}}
	ourSublayerKey       = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x02}}
	providerKeySingleDns = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x03}}
	sublayerKeySingleDns = syscall.GUID{Data1: 0x07008e7d, Data2: 0x48a2, Data3: 0x684e, Data4: [8]byte{0xa4, 0xf3, 0x8b, 0x7c, 0x02, 0x44, 0x50, 0x04}}

	v4Layers = []syscall.GUID{winlib.FwpmLayerAleAuthConnectV4, winlib.FwpmLayerAleAuthRecvAcceptV4}
	v6Layers = []syscall.GUID{winlib.FwpmLayerAleAuthConnectV6, winlib.FwpmLayerAleAuthRecvAcceptV6}

	manager                winlib.Manager
	clientLocalIPFilterIDs []uint64
	customDNS              net.IP

	_isEnabled          bool
	isPersistent        bool = true
	isAllowLAN          bool
	isAllowLANMulticast bool

	// These vars can be out of date. If need to report to UI - recheck all. Also lock the mutex when retrieving the otherSublayerGUID
	otherSublayerMutex sync.Mutex
	ourSublayerWeight  uint16       = 0
	otherSublayerGUID  syscall.GUID // If we could not register our sublayer with max weight (0xFFFF) yet, this will hold the GUID of another sublayer, who has max weight.
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

func implReregisterFirewallAtTopPriority(unregisterOtherVpnSublayer bool) error {
	return checkCreateProviderAndSublayer(false, unregisterOtherVpnSublayer)
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
func checkCreateProviderAndSublayer(wfpTransactionAlreadyInProgress, unregisterOtherVpnSublayer bool) (retErr error) {
	if !wfpTransactionAlreadyInProgress {
		if err := manager.TransactionStart(); err != nil { // start WFP transaction
			return fmt.Errorf("failed to start transaction: %w", err)
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

	// add provider
	pInfo, err := manager.GetProviderInfo(providerKey)
	if err != nil {
		return fmt.Errorf("failed to get provider info: %w", err)
	}
	if !pInfo.IsInstalled {
		provider := winlib.CreateProvider(providerKey, providerDName, "", isPersistent)
		if err = manager.AddProvider(provider); err != nil {
			return fmt.Errorf("failed to add provider : %w", err)
		}
	}

	// add sublayer
	installed, err := checkSublayerInstalled()
	if err != nil {
		return fmt.Errorf("failed to check sublayer is installed: %w", err)
	}
	if !installed {
		return createAddSublayer()
	}

	if ourSublayerWeight < winlib.SUBLAYER_MAX_WEIGHT { // our sublayer installed, check if it has max weight
		maxWeightSublayerFound, _otherSublayerGUID, err := findOtherSublayerWithMaxWeight() // check if max weight slot is vacant
		if err != nil {
			return fmt.Errorf("failed to check for sublayer with max weight: %w", err)
		}
		if maxWeightSublayerFound {
			otherSublayerMsg := fmt.Sprintf("Another sublayer with key/UUID '%s' is registered with max weight", windows.GUID(_otherSublayerGUID).String())
			if otherSublayerFound, otherSublayer, err := manager.GetSubLayerByKey(_otherSublayerGUID); err == nil && otherSublayerFound {
				otherSublayerMsg += ". Other sublayer information:\n" + otherSublayer.String()
			}
			log.Warning(otherSublayerMsg)

			if unregisterOtherVpnSublayer { // if requested to unregister the other guy, try it
				if err := manager.DeleteSubLayer(_otherSublayerGUID); err != nil {
					return log.ErrorE(fmt.Errorf("error deleting the other sublayer '%s': %w", windows.GUID(_otherSublayerGUID).String(), err), 0)
				}
			} else {
				log.Warning("Not requested to unregister the other sublayer, so we can't register our sublayer at max weight at the moment.")
				return nil
			}

		}

		// So max weight slot is vacant by now, try to delete our sublayer and recreate it at max weight.
		if err = manager.DeleteSubLayer(ourSublayerKey); err != nil {
			log.Warning(fmt.Errorf("warning - failed to delete our sublayer: %w", err))
		}
		log.Debug(fmt.Sprintf("checkCreateProviderAndSublayer - trying to re-create our sublayer with weight 0x%04X", winlib.SUBLAYER_MAX_WEIGHT))
		return createAddSublayer()
	}

	return err
}

// implInitialize doing initialization stuff (called on application start)
func implInitialize() error {
	if err := winlib.Initialize(platform.WindowsWFPDllPath()); err != nil {
		return err
	}

	return checkCreateProviderAndSublayer(false, false)
}

func implGetEnabled() (bool, error) {
	pInfo, err := manager.GetProviderInfo(providerKey)
	if err != nil {
		_isEnabled = false
		return false, fmt.Errorf("failed to get provider info: %w", err)
	}
	return pInfo.IsInstalled && _isEnabled, nil
}

func implSetEnabled(isEnabled bool) (retErr error) {
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

	pinfo, err := manager.GetProviderInfo(providerKey)
	if err != nil {
		return fmt.Errorf("failed to get provider info: %w", err)
	}

	if pinfo.IsInstalled {
		if pinfo.IsPersistent == isPersistent {
			log.Info(fmt.Sprintf("Already enabled (persistent=%t).", isPersistent))
			return nil
		}

		log.Info(fmt.Sprintf("Re-enabling with persistent flag = %t", isPersistent))
		return reEnable()
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

	return reEnable()
}

// OnChangeDNS - must be called on each DNS change (to update firewall rules according to new DNS configuration)
func implOnChangeDNS(addr net.IP) error {
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

	return reEnable()
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

	return reEnable()
}

func reEnable() (retErr error) {
	log.Debug("reEnable")
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

	err := doDisable(true)
	if err != nil {
		return fmt.Errorf("failed to disable firewall: %w", err)
	}

	err = doEnable(true)
	if err != nil {
		return fmt.Errorf("failed to enable firewall: %w", err)
	}

	return doAddClientIPFilters(connectedClientInterfaceIP, connectedClientInterfaceIPv6)
}

func doEnable(wfpTransactionAlreadyInProgress bool) (retErr error) {
	implSingleDnsRuleOff()

	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}
	if enabled {
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

	// TODO FIXME: Vlad - enable PL IP ranges in IPv4 loop
	prefs := getPrefsCallback()

	// IPv6 filters
	for _, layer := range v6Layers {
		// // block all
		// _, err := manager.AddFilter(winlib.NewFilterBlockAll(providerKey, layer, sublayerKey, filterDName, "Block all", true, isPersistent, false, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'block all IPv6': %w", err)
		// }
		// if isPersistent {
		// 	// For 'persistent' state we have to add boot-time blocking rule
		// 	bootTime := true
		// 	_, err = manager.AddFilter(winlib.NewFilterBlockAll(providerKey, layer, sublayerKey, filterDName, "Block all (boot time)", true, false, bootTime, winlib.FILTER_MAX_WEIGHT))
		// 	if err != nil {
		// 		return fmt.Errorf("failed to add boot-time filter 'block all IPv6': %w", err)
		// 	}
		// }

		// // block DNS
		// _, err = manager.AddFilter(winlib.NewFilterBlockDNS(providerKey, layer, sublayerKey, sublayerDName, "Block DNS", nil, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'block dns': %w", err)
		// }

		ipv6loopback := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}     // LOOPBACK 		::1/128
		ipv6llocal := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // LINKLOCAL		fe80::/10 // TODO: "fe80::/10" is already part of localAddressesV6. To think: do we need it here?

		// TODO FIXME: Vlad - do we need IPv6 loopback?
		_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, layer, ourSublayerKey, filterDName, "ipv6loopback", ipv6loopback, 128, isPersistent, winlib.FILTER_MAX_WEIGHT))
		if err != nil {
			return fmt.Errorf("failed to add filter 'allow remote IP' for ipv6loopback: %w", err)
		}
		_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, layer, ourSublayerKey, filterDName, "ipv6llocal", ipv6llocal, 10, isPersistent, winlib.FILTER_MAX_WEIGHT))
		if err != nil {
			return fmt.Errorf("failed to add filter 'allow remote IP' for ipv6llocal: %w", err)
		}

		// TODO FIXME: Vlad - allow our IPv6 DNS servers when we have them

		// TODO FIXME: Vlad - do we really need to enable these LAN rules?
		if isAllowLAN { // LAN
			for _, ip := range localAddressesV6 {
				prefixLen, _ := ip.Mask.Size()
				_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, layer, ourSublayerKey, filterDName, "allow lan IPv6", ip.IP, byte(prefixLen), isPersistent, winlib.FILTER_MAX_WEIGHT))
				if err != nil {
					return fmt.Errorf("failed to add filter 'allow lan IPv6': %w", err)
				}
			}

			if isAllowLANMulticast { // LAN multicast
				for _, ip := range multicastAddressesV6 {
					prefixLen, _ := ip.Mask.Size()
					_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, layer, ourSublayerKey, filterDName, "allow LAN multicast IPv6", ip.IP, byte(prefixLen), isPersistent, winlib.FILTER_MAX_WEIGHT))
					if err != nil {
						return fmt.Errorf("failed to add filter 'allow LAN multicast IPv6': %w", err)
					}
				}
			}
		}

		// user exceptions
		userExpsNets := getUserExceptions(false, true)
		for _, n := range userExpsNets {
			prefixLen, _ := n.Mask.Size()
			_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIPV6(providerKey, layer, ourSublayerKey, filterDName, "user exception", n.IP, byte(prefixLen), isPersistent, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'user exception': %w", err)
			}
		}
	}

	// IPv4 filters
	for _, layer := range v4Layers {
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
		// _, err = manager.AddFilter(winlib.NewFilterBlockDNS(providerKey, layer, sublayerKey, sublayerDName, "Block DNS", customDNS, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'block dns': %w", err)
		// }

		// // allow DNS requests to 127.0.0.1:53
		// _, err = manager.AddFilter(winlib.AllowRemoteLocalhostDNS(providerKey, layer, sublayerKey, sublayerDName, "", isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow localhost dns': %w", err)
		// }

		// Allow our Wireguard gateway(s), including ICMP
		// TODO FIXME: Vlad - parse endpoint IP once and cache it in the prefs
		for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
			_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, layer, ourSublayerKey, filterDName, "allow remote IP - Wireguard gateway", net.ParseIP(vpnEntryHost.EndpointIP), net.IPv4bcast, isPersistent, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'allow remote IP - Wireguard gateway': '%s': %w", vpnEntryHost.EndpointIP, err)
			}
		}

		// // allow DHCP port
		// _, err = manager.AddFilter(winlib.NewFilterAllowLocalPort(providerKey, layer, sublayerKey, sublayerDName, "", 68, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow dhcp': %w", err)
		// }

		// allow current executable
		binaryPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to obtain executable info: %w", err)
		}
		_, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, ourSublayerKey, sublayerDName, "", binaryPath, isPersistent, winlib.FILTER_MAX_WEIGHT))
		if err != nil {
			return fmt.Errorf("failed to add filter 'allow application': \"%s\": %w", binaryPath, err)
		}

		// // allow OpenVPN executable
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, sublayerDName, "", platform.OpenVpnBinaryPath(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - openvpn': %w", err)
		// }
		// allow WireGuard executable and wg-quick
		_, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, ourSublayerKey, sublayerDName, "", platform.WgBinaryPath(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		if err != nil {
			return fmt.Errorf("failed to add filter 'allow application': \"%s\": %w", platform.WgBinaryPath(), err)
		}
		_, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, ourSublayerKey, sublayerDName, "", platform.WgToolBinaryPath(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		if err != nil {
			return fmt.Errorf("failed to add filter 'allow application': \"%s\": %w", platform.WgToolBinaryPath(), err)
		}
		// // allow obfsproxy
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, sublayerDName, "", platform.ObfsproxyStartScript(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - obfsproxy': %w", err)
		// }
		// // allow V2Ray
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, sublayerDName, "", platform.V2RayBinaryPath(), isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - V2Ray': %w", err)
		// }
		// // allow dnscrypt-proxy
		// dnscryptProxyBin, _, _, _ := platform.DnsCryptProxyInfo()
		// _, err = manager.AddFilter(winlib.NewFilterAllowApplication(providerKey, layer, sublayerKey, sublayerDName, "", dnscryptProxyBin, isPersistent, winlib.FILTER_MAX_WEIGHT))
		// if err != nil {
		// 	return fmt.Errorf("failed to add filter 'allow application - dnscrypt-proxy': %w", err)
		// }

		// TODO FIXME: Vlad - do we need AllowRemoteIP for 127.0.0.1?
		_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, layer, ourSublayerKey, filterDName, "allow remote IP 127.0.0.1", net.ParseIP("127.0.0.1"), net.IPv4bcast, isPersistent, winlib.FILTER_MAX_WEIGHT))
		if err != nil {
			return fmt.Errorf("failed to add filter 'allow remote IP 127.0.0.1': %w", err)
		}

		// TODO FIXME: Vlad - Permit all apps outbound access to privateLINE private IP ranges
		// TODO FIXME: Vlad - parse IP ranges and netmasks once and cache them in the prefs
		// TODO until we implement App Whitelist on Windows
		for _, vpnEntryHost := range prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
			// Allow DNS to our internal servers explicitly, as otherwise Mullvad rules "Block outbound DNS" drop our DNS packets
			// TODO FIXME: Vlad - do we need to allow inbound DNS packets on port 53? ... and outbound
			for _, dnsSrv := range strings.Split(vpnEntryHost.DnsServers, ",") {
				dnsSrv = strings.TrimSpace(dnsSrv)
				_, err = manager.AddFilter(winlib.NewFilterAllowDNS(providerKey, layer, ourSublayerKey, sublayerDName, "Allow PL DNS "+dnsSrv, net.ParseIP(dnsSrv), net.IPv4bcast, isPersistent, winlib.FILTER_MAX_WEIGHT))
				if err != nil {
					return fmt.Errorf("failed to add filter 'Allow PL DNS %s': %w", dnsSrv, err)
				}
			}

			for _, allowedIpCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // CIDR format like "10.0.0.3/24"
				allowedIpCIDR = strings.TrimSpace(allowedIpCIDR)
				allowedIP, allowedIPNet, err := net.ParseCIDR(allowedIpCIDR)
				if err != nil {
					log.Error("error ParseCIDR '" + allowedIpCIDR + "'")
					continue
				}
				netmaskAsIP := net.IPv4(allowedIPNet.Mask[0], allowedIPNet.Mask[1], allowedIPNet.Mask[2], allowedIPNet.Mask[3])

				_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, layer, ourSublayerKey, filterDName, "allow remote IP - allowedIPs entry", allowedIP, netmaskAsIP, isPersistent, winlib.FILTER_MAX_WEIGHT))
				if err != nil {
					return fmt.Errorf("failed to add filter 'allow remote IP - allowedIPs entry': '%s': %w", allowedIpCIDR, err)
				}

			}
		}

		// TODO FIXME: Vlad - do we really need to enable these LAN rules?
		if isAllowLAN { // LAN
			for _, ip := range localAddressesV4 {
				_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, layer, ourSublayerKey, filterDName, "allow LAN", ip.IP, net.IP(ip.Mask), isPersistent, winlib.FILTER_MAX_WEIGHT))
				if err != nil {
					return fmt.Errorf("failed to add filter 'allow LAN': %w", err)
				}
			}

			// Multicast
			if isAllowLANMulticast { // LAN multicast
				for _, ip := range multicastAddressesV4 {
					_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, layer, ourSublayerKey, filterDName, "allow LAN multicast", ip.IP, net.IP(ip.Mask), isPersistent, winlib.FILTER_MAX_WEIGHT))
					if err != nil {
						return fmt.Errorf("failed to add filter 'allow LAN multicast': %w", err)
					}
				}
			}
		}

		// user exceptions
		userExpsNets := getUserExceptions(true, false)
		for _, n := range userExpsNets {
			_, err = manager.AddFilter(winlib.NewFilterAllowRemoteIP(providerKey, layer, ourSublayerKey, filterDName, "user exception", n.IP, net.IP(n.Mask), isPersistent, winlib.FILTER_MAX_WEIGHT))
			if err != nil {
				return fmt.Errorf("failed to add filter 'user exception': %w", err)
			}
		}
	}

	_isEnabled = true
	return nil
}

func doDisable(wfpTransactionAlreadyInProgress bool) error {
	implSingleDnsRuleOff()

	enabled, err := implGetEnabled()
	if err != nil {
		return fmt.Errorf("failed to get info if firewall is on: %w", err)
	}

	// retry moving our sublayer to top priority
	if err = checkCreateProviderAndSublayer(wfpTransactionAlreadyInProgress, false); err != nil {
		err = log.ErrorE(fmt.Errorf("failed to check/create provider or sublayer: %w", err), 0)
	}

	if !enabled {
		return nil
	}

	// delete filters
	for _, l := range v6Layers {
		// delete filters and callouts registered for the provider+layer
		if err := manager.DeleteFilterByProviderKey(providerKey, l); err != nil {
			return fmt.Errorf("failed to delete filter : %w", err)
		}
	}

	for _, l := range v4Layers {
		// delete filters and callouts registered for the provider+layer
		if err := manager.DeleteFilterByProviderKey(providerKey, l); err != nil {
			return fmt.Errorf("failed to delete filter : %w", err)
		}
	}

	// // delete sublayer
	// installed, err := manager.IsSubLayerInstalled(sublayerKey)
	// if err != nil {
	// 	return fmt.Errorf("failed to check is sublayer installed : %w", err)
	// }
	// if installed {
	// 	if err := manager.DeleteSubLayer(sublayerKey); err != nil {
	// 		return fmt.Errorf("failed to delete sublayer : %w", err)
	// 	}
	// }

	// // delete provider
	// pinfo, err := manager.GetProviderInfo(providerKey)
	// if err != nil {
	// 	return fmt.Errorf("failed to get provider info : %w", err)
	// }
	// if pinfo.IsInstalled {
	// 	if err := manager.DeleteProvider(providerKey); err != nil {
	// 		return fmt.Errorf("failed to delete provider : %w", err)
	// 	}
	// }

	clientLocalIPFilterIDs = nil

	_isEnabled = false
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

	filters := make([]uint64, 0, len(v4Layers))
	for _, layer := range v4Layers {
		f := winlib.NewFilterAllowLocalIP(providerKey, layer, ourSublayerKey, filterDName, "clientLocalIP", clientLocalIP, net.IPv4bcast, false)
		id, err := manager.AddFilter(f)
		if err != nil {
			return fmt.Errorf("failed to add filter 'clientLocalIP' : %w", err)
		}
		filters = append(filters, id)
	}

	// IPv6: allow IPv6 communication inside tunnel
	if clientLocalIPv6 != nil {
		for _, layer := range v6Layers {
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
	// TODO FIXME: Vlad - disable much or all of functionality
	log.Debug("implSingleDnsRuleOff - largely disabled")

	pInfo, err := manager.GetProviderInfo(providerKeySingleDns)
	if err != nil {
		return fmt.Errorf("failed to get provider info: %w", err)
	}
	if !pInfo.IsInstalled {
		return nil
	}

	// delete filters
	for _, l := range v6Layers {
		// delete filters and callouts registered for the provider+layer
		if err := manager.DeleteFilterByProviderKey(providerKeySingleDns, l); err != nil {
			return fmt.Errorf("failed to delete filter : %w", err)
		}
	}

	for _, l := range v4Layers {
		// delete filters and callouts registered for the provider+layer
		if err := manager.DeleteFilterByProviderKey(providerKeySingleDns, l); err != nil {
			return fmt.Errorf("failed to delete filter : %w", err)
		}
	}

	// // delete sublayer
	// installed, err := manager.IsSubLayerInstalled(sublayerKeySingleDns)
	// if err != nil {
	// 	return fmt.Errorf("failed to check is sublayer installed : %w", err)
	// }
	// if installed {
	// 	if err := manager.DeleteSubLayer(sublayerKeySingleDns); err != nil {
	// 		return fmt.Errorf("failed to delete sublayer : %w", err)
	// 	}
	// }

	// // delete provider
	// if err := manager.DeleteProvider(providerKeySingleDns); err != nil {
	// 	return fmt.Errorf("failed to delete provider : %w", err)
	// }
	return nil
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

func implHaveTopFirewallPriority(recursionDepth uint8) (weHaveTopFirewallPriority bool, otherGuyID, otherGuyName, otherGuyDescription string, retErr error) {
	if recursionDepth == 0 { // start WFP transaction on the 1st recursion call
		if err := manager.TransactionStart(); err != nil {
			return false, "", "", "", fmt.Errorf("failed to start transaction: %w", err)
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

	var ourSublayerInstalled, otherSublayerFound bool
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
	otherSublayerFound, _otherSublayerGUID, retErr := findOtherSublayerWithMaxWeight() // check if max weight slot is vacant
	if retErr != nil {
		return false, "", "", "", fmt.Errorf("failed to check for other sublayer with max weight: %w", retErr)
	}
	if otherSublayerFound {
		otherGuyID = windows.GUID(_otherSublayerGUID).String()
		if otherSublayerFound, otherSublayer, err := manager.GetSubLayerByKey(_otherSublayerGUID); err == nil && otherSublayerFound {
			otherGuyName = otherSublayer.Name
			otherGuyDescription = otherSublayer.Description
		}
		return false, otherGuyID, otherGuyName, otherGuyDescription, nil
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
