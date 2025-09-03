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
	"unicode"

	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	protocol_types "github.com/swapnilsparsh/devsVPN/daemon/protocol/types"

	"github.com/swapnilsparsh/devsVPN/daemon/service/dns"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	"github.com/swapnilsparsh/devsVPN/daemon/service/srvhelpers"
)

var log *logger.Logger

type DisableTotalShieldAsyncCallback func()
type OnKillSwitchStateChangedCallback func(forceReportNoTopFirewallPri bool)
type GetRestApiHostsCallback func() (restApiHosts []*helpers.HostnameAndIP)

func init() {
	log = logger.NewLogger("frwl")
}

var (
	connectedClientInterfaceIP   net.IP
	connectedClientInterfaceIPv6 net.IP
	connectedClientPort          int
	connectedHostIP              net.IP
	connectedHostPort            int
	connectedIsTCP               bool
	mutex                        sync.Mutex
	isClientPaused               bool
	dnsConfig                    *dns.DnsSettings

	customDnsServers []net.IP

	isPersistent bool

	// List of IP masks that are allowed for any communication
	userExceptions []net.IPNet

	stateAllowLan          bool
	stateAllowLanMulticast bool

	getPrefsCallback                 preferences.GetPrefsCallback
	disableTotalShieldAsyncCallback  DisableTotalShieldAsyncCallback
	onKillSwitchStateChangedCallback OnKillSwitchStateChangedCallback
	vpnConnectedOrConnectingCallback protocol_types.VpnConnectedCallback // whether VPN is connected or connecting
	vpnConnectedCallback             protocol_types.VpnConnectedCallback // whether VPN is in CONNECTED state
	getRestApiHostsCallback          GetRestApiHostsCallback
	isDaemonStoppingCallback         protocol_types.VpnConnectedCallback
)

// Initialize is doing initialization stuff
// Must be called on application start
func Initialize(_getPrefsCallback preferences.GetPrefsCallback, _disableTotalShieldAsyncCallback DisableTotalShieldAsyncCallback,
	_onKillSwitchStateChangedCallback OnKillSwitchStateChangedCallback,
	_vpnConnectedOrConnectingCallback, _vpnConnectedCallback, _isDaemonStoppingCallback protocol_types.VpnConnectedCallback, _getRestApiHostsCallback GetRestApiHostsCallback) error {
	mutex.Lock()
	defer mutex.Unlock()

	onKillSwitchStateChangedCallback = _onKillSwitchStateChangedCallback
	getRestApiHostsCallback = _getRestApiHostsCallback

	getPrefsCallback = _getPrefsCallback
	disableTotalShieldAsyncCallback = _disableTotalShieldAsyncCallback

	vpnConnectedOrConnectingCallback = _vpnConnectedOrConnectingCallback
	vpnConnectedCallback = _vpnConnectedCallback

	isDaemonStoppingCallback = _isDaemonStoppingCallback

	return implInitialize()
}

// SetEnabled - change firewall state
func SetEnabled(enable, canReconfigureOtherVpns bool) (err error) {
	if enable && isDaemonStoppingCallback() {
		return log.ErrorFE("error - can't enable the firewall when daemon is stopping")
	}

	mutex.Lock()
	defer mutex.Unlock()

	if enable {
		log.Info("Enabling...")
	} else {
		log.Info("Disabling...")
	}

	if err = implSetEnabled(enable, false, false, false, canReconfigureOtherVpns); err != nil {
		return log.ErrorFE("failed to change firewall state : %w", err)
	}

	if enable {
		// To fulfill such flow (example): FWEnable -> Connected -> FWDisable -> FWEnable
		// Here we should notify that client is still connected
		// We must not do it in Paused state!
		clientAddr := connectedClientInterfaceIP
		clientAddrIPv6 := connectedClientInterfaceIPv6
		if clientAddr != nil && !isClientPaused {
			e := implClientConnected(clientAddr, clientAddrIPv6, connectedClientPort, connectedHostIP, connectedHostPort, connectedIsTCP)
			if e != nil {
				log.Error(e)
			}
		}
	}

	return err
}

// DisableUnlessConnectedConnecting will disable firewall logic unless the VPN is connected or connecting
func DisableUnlessConnectedConnecting(canReconfigureOtherVpns bool) (err error) {
	if !vpnConnectedOrConnectingCallback() {
		return SetEnabled(false, canReconfigureOtherVpns)
	} else {
		return nil
	}
}

func ReEnable(canReconfigureOtherVpns bool) error {
	// if enabled, err := GetEnabled(); err != nil {
	// 	return log.ErrorE(fmt.Errorf("failed to check firewall state: %w", err), 0)
	// } else if !enabled {
	// 	log.Info("firewall was not enabled, but disabling-then-enabling anyway")
	// }

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - can't re-enable the firewall when daemon is stopping")
	}

	// GetEnabled() also grabs mutex, so have to wait for it to finish
	mutex.Lock()
	defer mutex.Unlock()

	log.Debug("ReEnable entered")
	defer log.Debug("ReEnable exited")

	return implReEnable(canReconfigureOtherVpns)
}

// CleanupRegistration will completely clean up firewall registation, all of its objects. To be used only during uninstallation.
func CleanupRegistration() (err error) {
	mutex.Lock()
	defer mutex.Unlock()

	if err = implSetEnabled(false, false, false, false, getPrefsCallback().PermissionReconfigureOtherVPNs); err != nil {
		return log.ErrorE(fmt.Errorf("failed to disable firewall: %w", err), 0)
	}

	if err = implCleanupRegistration(); err != nil {
		return log.ErrorE(fmt.Errorf("implCleanupRegistration() failed: %w", err), 0)
	}

	return nil
}

// SetPersistent - set persistent firewall state and enable it if necessary
func SetPersistent(persistent bool) (err error) {
	mutex.Lock()
	defer mutex.Unlock()

	log.Info(fmt.Sprintf("Persistent: %t", persistent))

	if err = implSetPersistent(persistent); err != nil { // this will enable firewall, if it's down
		log.Error(err)
	}
	return err
}

// _getEnabledHelper is a helper, it doesn't grab the mutex - parent callers do
func _getEnabledHelper(logState, blockingWait bool) (isEnabled bool, err error) {
	if isEnabled, err = implGetEnabled(blockingWait); err != nil {
		err = log.ErrorFE("Firewall status check error: %w", err)
	}
	if logState {
		log.Info(fmt.Sprintf("isEnabled:%t allowLan:%t allowMulticast:%t totalShieldDeployed:%t blockingWait:%t", isEnabled, stateAllowLan, stateAllowLanMulticast, TotalShieldDeployedState(), blockingWait))
	}

	return isEnabled, err
}

// GetEnabled - get firewall status enabled/disabled
func GetEnabled() (isEnabled bool, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	return _getEnabledHelper(true, false)
}

// Get firewall status without log entry
func GetEnabledNoLogs() (isEnabled bool, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	return _getEnabledHelper(false, false)
}

func GetState() (isEnabled, isLanAllowed, isMulticastAllowed bool, weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	if isEnabled, err = _getEnabledHelper(false, false); err != nil {
		return isEnabled, false, false, false, "", "", "", err
	}

	if weHaveTopFirewallPriority, otherVpnID, otherVpnName, otherVpnDescription, err = implHaveTopFirewallPriority(0); err != nil {
		log.ErrorFE("error checking whether we have top firewall priority: %w", err)
	}

	log.Info(fmt.Sprintf("isEnabled:%t topFirewallPri:%t allowLan:%t allowMulticast:%t totalShieldDeployed:%t", isEnabled, weHaveTopFirewallPriority, stateAllowLan, stateAllowLanMulticast, TotalShieldDeployedState()))

	return isEnabled, stateAllowLan, stateAllowLanMulticast, weHaveTopFirewallPriority, otherVpnID, otherVpnName, otherVpnDescription, err
}

// EnableIfNeeded - atomic operation on firewall.mutex. Will check firewall status and, if disabled, will enable it.
func EnableIfNeeded(rescanForOtherVpns, canReconfigureOtherVpns bool) (err error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	mutex.Lock()
	defer mutex.Unlock()

	if isEnabled, err := _getEnabledHelper(true, false); err != nil {
		return err
	} else if !isEnabled {
		return implSetEnabled(true, false, rescanForOtherVpns, false, canReconfigureOtherVpns)
	}

	return nil
}

// SingleDnsRuleOn - add rule to allow DNS communication with specified IP only
// (usefull for Inverse Split Tunneling feature)
// Returns error if IVPN firewall is enabled.
// As soon as IVPN firewall enables - this rule will be removed
func SingleDnsRuleOn(dnsAddr net.IP) (retErr error) {
	// TODO: Vlad - disabled
	return nil

	mutex.Lock()
	defer mutex.Unlock()
	return implSingleDnsRuleOn(dnsAddr)
}

// SingleDnsRuleOff - remove rule (if exist) to allow DNS communication with specified IP only defined by SingleDnsRuleOn()
// (usefull for Inverse Split Tunneling feature)
func SingleDnsRuleOff() (retErr error) {
	mutex.Lock()
	defer mutex.Unlock()
	return implSingleDnsRuleOff()
}

// ClientPaused saves info about paused state of vpn
func ClientPaused() {
	isClientPaused = true
}

// ClientResumed saves info about resumed state of vpn
func ClientResumed() {
	isClientPaused = false
}

// If Mullvad stays connected, PL Connect has max firewall priority (0xFFFF sublayer weight), and goes from disconnected to connected - then looking up
// hosts immediately after WG connection is established fails. In that case need to fork post-connection rules to run asynchronously 1-2sec later.
func DeployPostConnectionRules(canReconfigureOtherVpns bool) (retErr error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	mutex.Lock()
	defer mutex.Unlock()

	return implDeployPostConnectionRules(canReconfigureOtherVpns)
}

func TotalShieldDeployedState() bool {
	return getPrefsCallback().IsTotalShieldOn && vpnConnectedCallback()
}

func TotalShieldApply() (err error) {
	mutex.Lock()
	defer mutex.Unlock()

	// log.Debug("TotalShieldApply entered")
	// defer log.Debug("TotalShieldApply exited")

	if fwEnabled, err := _getEnabledHelper(true, false); err != nil {
		return err
	} else if !fwEnabled { // if fw is disabled - don't do anything
		return nil
	}

	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	return implTotalShieldApply(false, TotalShieldDeployedState())
}

// ClientConnected - allow communication for local vpn/client IP address
func ClientConnected(clientLocalIPAddress net.IP, clientLocalIPv6Address net.IP, clientPort int, serverIP net.IP, serverPort int, isTCP bool) error {
	mutex.Lock()
	defer mutex.Unlock()
	ClientResumed()

	log.Info("Client connected: ", clientLocalIPAddress)

	connectedClientInterfaceIP = clientLocalIPAddress
	connectedClientInterfaceIPv6 = clientLocalIPv6Address
	connectedClientPort = clientPort
	connectedHostIP = serverIP
	connectedHostPort = serverPort
	connectedIsTCP = isTCP

	err := implClientConnected(clientLocalIPAddress, clientLocalIPv6Address, clientPort, serverIP, serverPort, isTCP)
	if err != nil {
		log.Error(err)
	}
	return err
}

// ClientDisconnected - Remove all hosts exceptions
func ClientDisconnected() error {
	mutex.Lock()
	defer mutex.Unlock()

	log.Debug("ClientDisconnected entered")
	defer log.Debug("ClientDisconnected exited")

	ClientResumed()

	// Remove client interface from exceptions
	if connectedClientInterfaceIP != nil {
		connectedClientInterfaceIP = nil
		connectedClientInterfaceIPv6 = nil
		log.Info("Client disconnected")
		err := implClientDisconnected()
		if err != nil {
			log.Error(err)
		}
		return err
	}
	return nil
}

// AddHostsToExceptions - allow comminication with this hosts
// Note: if isPersistent == false -> all added hosts will be removed from exceptions after client disconnection (after call 'ClientDisconnected()')
// Arguments:
//   - IPs			-	list of IP addresses to ba allowed
//   - onlyForICMP	-	(applicable only for Linux) try add rule to allow only ICMP protocol for this IP
//   - isPersistent	-	keep rule enabled even if VPN disconnected
func AddHostsToExceptions(IPs []net.IP, onlyForICMP bool, isPersistent bool) error {
	// if isPersistent {
	// 	return fmt.Errorf("error - WFP (Windows Filtering Platform) persistence not supported")
	// }

	mutex.Lock()
	defer mutex.Unlock()

	err := implAddHostsToExceptions(IPs, onlyForICMP, isPersistent)
	if err != nil {
		log.Error("Failed to add hosts to exceptions:", err)
	}

	return err
}

func RemoveHostsFromExceptions(IPs []net.IP, onlyForICMP bool, isPersistent bool) error {
	// if isPersistent {
	// 	return fmt.Errorf("error - WFP (Windows Filtering Platform) persistence not supported")
	// }

	mutex.Lock()
	defer mutex.Unlock()

	err := implRemoveHostsFromExceptions(IPs, onlyForICMP, isPersistent)
	if err != nil {
		log.Error("Failed to remove hosts from exceptions:", err)
	}

	return err
}

// AllowLAN - allow/forbid LAN communication
func AllowLAN(allowLan bool, allowLanMulticast bool) error {
	mutex.Lock()
	defer mutex.Unlock()

	stateAllowLan = allowLan
	stateAllowLanMulticast = allowLanMulticast

	log.Info(fmt.Sprintf("allowLan:%t allowMulticast:%t", allowLan, allowLanMulticast))

	err := implAllowLAN(allowLan, allowLanMulticast)
	if err != nil {
		log.Error(err)
	}
	return err
}

func GetDnsInfo() (dns.DnsSettings, bool) {
	mutex.Lock()
	defer mutex.Unlock()

	if dnsConfig == nil {
		return dns.DnsSettings{}, false
	}
	return *dnsConfig, true
}

func getDnsIPs() (dnsIPs *[]net.IP) {
	cfg := dnsConfig
	if cfg != nil && cfg.Encryption == dns.EncryptionNone {
		dnsIPs = &cfg.DnsServers
	}
	return dnsIPs
}

// OnChangeDNS - must be called on each DNS change (to update firewall rules according to new DNS configuration)
func OnChangeDNS(newDnsCfg *dns.DnsSettings) error {
	mutex.Lock()
	defer mutex.Unlock()

	if newDnsCfg != nil && newDnsCfg.IsEmpty() {
		newDnsCfg = nil
	}

	if (dnsConfig == nil && newDnsCfg == nil) ||
		(dnsConfig != nil && newDnsCfg != nil && dnsConfig.Equal(*newDnsCfg)) {
		// DNS rule already applied. Do nothing.
		return nil
	}

	var dnsServers *[]net.IP = nil
	if newDnsCfg != nil && newDnsCfg.Encryption == dns.EncryptionNone {
		// for DoH/DoT - no sense to allow DNS port (53)
		dnsServers = &newDnsCfg.DnsServers
	}

	err := implOnChangeDNS(dnsServers)
	if err != nil {
		log.Error(err)
	} else {
		// remember DNS IP
		dnsConfig = newDnsCfg
	}
	return err
}

// SetUserExceptions set ip/mask to be excluded from FW block
// Parameters:
//   - exceptions - comma separated list of IP addresses in format: x.x.x.x[/xx]
func SetUserExceptions(exceptions string, ignoreParseErrors bool) error {
	mutex.Lock()
	defer mutex.Unlock()

	userExceptions = []net.IPNet{}

	splitFunc := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != rune('/') && c != rune('.') && c != rune(':')
	}
	exceptionsArr := strings.FieldsFunc(exceptions, splitFunc)
	for _, exp := range exceptionsArr {
		exp = strings.TrimSpace(exp)

		var err error
		var n *net.IPNet

		if strings.Contains(exp, "/") {
			_, n, err = net.ParseCIDR(exp)
		} else {
			addr := net.ParseIP(exp)
			if addr == nil {
				err = fmt.Errorf("%s not a IP address", exp)
			} else {
				if addr.To4() == nil {
					// IPv6 single address
					_, n, err = net.ParseCIDR(addr.String() + "/128")
				} else {
					// IPv4 single address
					_, n, err = net.ParseCIDR(addr.String() + "/32")
				}
			}
		}
		if err != nil {
			if !ignoreParseErrors {
				return fmt.Errorf("unable to parse firewall exceptions ('%s'): %w", exceptions, err)
			}
			continue
		}
		userExceptions = append(userExceptions, *n)
	}

	return implOnUserExceptionsUpdated()
}

// Is our firewall logic registered at top priority? This is necessary on Windows
func HaveTopFirewallPriority() (weHaveTopFirewallPriority bool, otherVpnID, otherVpnName, otherVpnDescription string, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	return implHaveTopFirewallPriority(0)
}

func TryReregisterFirewallAtTopPriority(canReconfigureOtherVpns, forceReconfigureFirewall bool) (err error) {
	if isDaemonStoppingCallback() {
		return log.ErrorFE("error - daemon is stopping")
	}

	canReconfigureOtherVpns = canReconfigureOtherVpns || getPrefsCallback().PermissionReconfigureOtherVPNs
	if !canReconfigureOtherVpns {
		return nil
	}

	mutex.Lock()
	defer mutex.Unlock()

	_, err = implReregisterFirewallAtTopPriority( /*canReconfigureOtherVpns,*/ forceReconfigureFirewall)
	return err
}

// GetFirewallBackgroundMonitors  - caller should them all in forked threads
func GetFirewallBackgroundMonitors() (monitors []*srvhelpers.ServiceBackgroundMonitor) {
	return implGetFirewallBackgroundMonitors()
}
