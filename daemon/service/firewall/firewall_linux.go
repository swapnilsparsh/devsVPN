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

// Here we include Linux firewall logic common to nftables and legacy (xtables, iptables-legacy)

package firewall

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

const (
	ENOENT_ERRMSG = "no such file or directory"

	VPN_COEXISTENCE_CHAIN_PREFIX = "privateline-vpnco" // full chain name has to be under 29 chars w/ iptables-legacy

	PL_CGROUP_ID = 0x70561e1d
)

var (
	// key: is a string representation of allowed IP
	// value: true - if exception rule is persistent (persistent, means will stay available even client is disconnected)
	allowedHosts   = make(map[string]bool)
	allowedForICMP map[string]struct{} // IP addresses allowed for ICMP

	curAllowedLanIPs          []string // IP addresses allowed for LAN
	curStateAllowLAN          bool     // Allow LAN is enabled
	curStateAllowLanMulticast bool     // Allow Multicast is enabled
	curStateEnabled           bool     // Firewall is enabled

	waitForTopFirewallPriAfterWeLostItMutex sync.Mutex
)

func implInitialize() (err error) {
	var (
		implInitializeWaiter sync.WaitGroup
		errNft, errLegacy    error
	)

	implInitializeWaiter.Add(2) // launch legacy before nft, it's expected to be slower
	go func() { errLegacy = implInitializeLegacy(); implInitializeWaiter.Done() }()
	go func() { errNft = implInitializeNft(); implInitializeWaiter.Done() }()
	implInitializeWaiter.Wait()

	if errNft != nil {
		return log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return nil
}

func implHaveTopFirewallPriority(recursionDepth uint8) (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, retErr error) {
	var (
		implHaveTopFirewallPriorityWaiter sync.WaitGroup
		errNft, errLegacy                 error
		topPriNft, topPriLegacy           bool
	)

	implHaveTopFirewallPriorityWaiter.Add(2)
	go func() {
		topPriLegacy, _, _, _, errLegacy = implHaveTopFirewallPriorityLegacy()
		implHaveTopFirewallPriorityWaiter.Done()
	}()
	go func() {
		topPriNft, _, _, _, errNft = implHaveTopFirewallPriorityNft()
		implHaveTopFirewallPriorityWaiter.Done()
	}()
	implHaveTopFirewallPriorityWaiter.Wait()

	if errNft != nil {
		return false, "", "", "", log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return false, "", "", "", log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return topPriNft && topPriLegacy, "", "", "", nil
}

func implGetEnabled() (isEnabled bool, retErr error) {
	var (
		implGetEnabledWaiter          sync.WaitGroup
		errNft, errLegacy             error
		isEnabledNft, isEnabledLegacy bool
	)

	implGetEnabledWaiter.Add(2)
	go func() { isEnabledLegacy, errLegacy = implGetEnabledLegacy(); implGetEnabledWaiter.Done() }()
	go func() { isEnabledNft, errNft = implGetEnabledNft(); implGetEnabledWaiter.Done() }()
	implGetEnabledWaiter.Wait()

	if errNft != nil {
		return false, log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return false, log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return isEnabledNft && isEnabledLegacy, nil
}

func implReregisterFirewallAtTopPriority(canStopOtherVpn bool) (firewallReconfigured bool, retErr error) {
	var (
		implReregisterFirewallAtTopPriorityWaiter           sync.WaitGroup
		errNft, errLegacy                                   error
		firewallReconfiguredNft, firewallReconfiguredLegacy bool
	)

	implReregisterFirewallAtTopPriorityWaiter.Add(2)
	go func() {
		firewallReconfiguredLegacy, errLegacy = implReregisterFirewallAtTopPriorityLegacy()
		implReregisterFirewallAtTopPriorityWaiter.Done()
	}()
	go func() {
		firewallReconfiguredNft, errNft = implReregisterFirewallAtTopPriorityNft()
		implReregisterFirewallAtTopPriorityWaiter.Done()
	}()
	implReregisterFirewallAtTopPriorityWaiter.Wait()

	if errNft != nil {
		return false, log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return false, log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return firewallReconfiguredNft || firewallReconfiguredLegacy, nil
}

func implGetFirewallBackgroundMonitors() (monitors []*FirewallBackgroundMonitor) {
	monitors = []*FirewallBackgroundMonitor{{MonitorFunc: implFirewallBackgroundMonitorNft,
		MonitorEndChan:  stopMonitoringFirewallChangesNft,
		MonitorEndMutex: &implFirewallBackgroundMonitorNftMutex}}

	if iptablesLegacyPresent() {
		monitors = append(monitors, &FirewallBackgroundMonitor{MonitorFunc: implFirewallBackgroundMonitorLegacy,
			MonitorEndChan:  stopMonitoringFirewallChangesLegacy,
			MonitorEndMutex: &implFirewallBackgroundMonitorLegacyMutex})
	}

	return monitors
}

// waitForTopFirewallPriAfterWeLostIt is called after we lost top firewall pri. It'll notify clients about the loss, and will keep on checking top-pri every 5s
// - until we either regain top-pri, or VPN connection gets stopped.
func waitForTopFirewallPriAfterWeLostIt() {
	waitForTopFirewallPriAfterWeLostItMutex.Lock() // single instance
	defer waitForTopFirewallPriAfterWeLostItMutex.Unlock()

	log.Debug("waitForTopFirewallPriAfterWeLostIt entered")
	defer log.Debug("waitForTopFirewallPriAfterWeLostIt exited")

	go onKillSwitchStateChangedCallback() // initial notification out

	for vpnConnectedOrConnectingCallback() { // if VPN is no longer connected - terminate this waiting loop
		time.Sleep(time.Second * 5)

		if weHaveTopFirewallPriority, err := implGetEnabled(); err != nil {
			log.ErrorFE("error in implGetEnabled(): %w", err)
			break
		} else if weHaveTopFirewallPriority {
			break
		}
	}

	go onKillSwitchStateChangedCallback() // final notification out
}

func implReEnable() (retErr error) {
	var (
		implReEnableWaiter sync.WaitGroup
		errNft, errLegacy  error
	)

	if _, err := reDetectOtherVpnsLinux(false, true); err != nil { // re-detect other VPNs (if stale) synchronously - it must finish before reenable logic
		log.ErrorFE("error reDetectOtherVpnsLinux(false, true): %w", err) // and continue
	}

	implReEnableWaiter.Add(2)
	go func() { errLegacy = implReEnableLegacy(false); implReEnableWaiter.Done() }()
	go func() { errNft = implReEnableNft(false); implReEnableWaiter.Done() }()
	implReEnableWaiter.Wait()

	if errNft != nil {
		return log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return nil
}

func implDeployPostConnectionRules() (retErr error) {
	var (
		implDeployPostConnectionRulesWaiter sync.WaitGroup
		errNft, errLegacy                   error
	)

	// TODO FIXME: Vlad - do we still need to run them from here?
	// re-run VPN coexistence rules, since presumably now we're CONNECTED
	if err := enableVpnCoexistenceLinuxNft(); err != nil {
		retErr = log.ErrorFE("error running EnableCoexistenceWithOtherVpns(): %w", err) // and continue
	}

	implDeployPostConnectionRulesWaiter.Add(2)
	go func() {
		errLegacy = implDeployPostConnectionRulesLegacy(false)
		implDeployPostConnectionRulesWaiter.Done()
	}()
	go func() { errNft = implDeployPostConnectionRulesNft(false); implDeployPostConnectionRulesWaiter.Done() }()
	implDeployPostConnectionRulesWaiter.Wait()

	if errNft != nil {
		return log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return retErr
}

func implSetEnabled(isEnabled, _ bool) error {
	log.Debug("implSetEnabled=", isEnabled)

	var (
		implSetEnabledWaiter sync.WaitGroup
		errNft, errLegacy    error
	)

	curStateEnabled = isEnabled

	implSetEnabledWaiter.Add(2)
	if isEnabled {
		if _, err := reDetectOtherVpnsLinux(false, true); err != nil { // re-detect other VPNs (if stale) synchronously - it must finish before enable logic
			log.ErrorFE("error reDetectOtherVpnsLinux(false, true): %w", err) // and continue
		}
		go func() { errLegacy = doEnableLegacy(false); implSetEnabledWaiter.Done() }()
		go func() { errNft = doEnableNft(false, true); implSetEnabledWaiter.Done() }()
	} else {
		go func() { errLegacy = doDisableLegacy(false); implSetEnabledWaiter.Done() }()
		go func() { errNft = doDisableNft(false); implSetEnabledWaiter.Done() }()
	}
	implSetEnabledWaiter.Wait()

	if errNft != nil {
		return log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return log.ErrorFE("error: errLegacy='%w'", errLegacy)
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
		if isEnabled, err := implGetEnabled(); err != nil {
			return log.ErrorFE("Status check error: %w", err)
		} else if !isEnabled {
			return implSetEnabled(true, false)
		}

		// Some Linux distributions erasing IVPN rules during system boot
		// During some period of time (60 seconds should be enough)
		// check if FW rules still exist (if not - re-apply them)
		// go ensurePersistent(60)
		// return ret
	}
	return nil
}

func implCleanupRegistration() (err error) {
	return implSetEnabled(false, false)
}

// OnChangeDNS - must be called on each DNS change (to update firewall rules according to new DNS configuration)
// If addr is not nil, non-zero, and different from previous customDNS - just add the new DNS to privateLINE_DNS set
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

	var (
		implOnChangeDNSWaiter sync.WaitGroup
		errNft, errLegacy     error
	)

	implOnChangeDNSWaiter.Add(2) // launch legacy before nft, it's expected to be slower
	go func() { errLegacy = implOnChangeDnsLegacy(&_newDnsServers); implOnChangeDNSWaiter.Done() }()
	go func() { errNft = implOnChangeDnsNft(&_newDnsServers); implOnChangeDNSWaiter.Done() }()
	implOnChangeDNSWaiter.Wait()

	if errNft != nil {
		return log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return nil
}

func implTotalShieldApply(wfpTransactionAlreadyInProgress, totalShieldNewState bool) (retErr error) {
	var (
		implTotalShieldApplyWaiter sync.WaitGroup
		errNft, errLegacy          error
	)

	implTotalShieldApplyWaiter.Add(2) // launch legacy before nft, it's expected to be slower
	go func() {
		errLegacy = implTotalShieldApplyLegacy(totalShieldNewState)
		implTotalShieldApplyWaiter.Done()
	}()
	go func() {
		errNft = implTotalShieldApplyNft(totalShieldNewState)
		implTotalShieldApplyWaiter.Done()
	}()
	implTotalShieldApplyWaiter.Wait()

	if errNft != nil {
		return log.ErrorFE("error: errNft='%w' errLegacy='%w'", errNft, errLegacy)
	} else if errLegacy != nil {
		return log.ErrorFE("error: errLegacy='%w'", errLegacy)
	}

	return nil
}

// TODO: -------------------------------- Vlad - below functions are stubbed out --------------------------------

// Some Linux distributions erasing IVPN rules during system boot
// During some period of time (60 seconds should be enough)
// check if FW rules still exist (if not - re-apply them)
func ensurePersistent(secondsToWait int) {
	// TODO FIXME: Vlad - stubbed out
	return

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

	return doAllowLAN(isAllowLAN, isAllowLanMulticast)
}

func doAllowLAN(isAllowLAN, isAllowLanMulticast bool) error {
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

	IPsStr := make([]string, 0, len(IPs))
	for _, ip := range IPs {
		IPsStr = append(IPsStr, ip.String())
	}

	return removeHostsFromExceptions(IPsStr, isPersistent, onlyForICMP)
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

// allow communication with specified hosts
// if isPersistent == false - exception will be removed when client disconnects
func addHostsToExceptions(IPs []string, isPersistent bool, onlyForICMP bool) error {
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

	toRemoveIPs := make([]string, 0, len(allowedHosts))
	for ipStr := range allowedHosts {
		toRemoveIPs = append(toRemoveIPs, ipStr)
	}
	isPersistent := false
	return removeHostsFromExceptions(toRemoveIPs, isPersistent, false)
}

//---------------------------------------------------------------------

func getAllowedIpExceptions() (prioritized, persistent []string) {
	// TODO FIXME: Vlad - stubbing out for now
	return

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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

// TODO FIXME: Vlad - flesh out. Do we need this?... we always allow localhost traffic (lo interface)
func doAddClientIPFilters(clientLocalIP net.IP, clientLocalIPv6 net.IP) (retErr error) {
	return nil
}
func doRemoveClientIPFilters() (retErr error) {
	return nil
}

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
	// TODO FIXME: Vlad - stubbing out for now
	return nil

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
	err := implOnChangeDNS(getDnsIPs())
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
