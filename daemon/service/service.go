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

package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/api"
	api_types "github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/oshelpers"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol"
	protocolTypes "github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/dns"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform/filerights"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	"github.com/swapnilsparsh/devsVPN/daemon/service/srverrors"
	"github.com/swapnilsparsh/devsVPN/daemon/service/srvhelpers"
	"github.com/swapnilsparsh/devsVPN/daemon/service/types"
	service_types "github.com/swapnilsparsh/devsVPN/daemon/service/types"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"github.com/swapnilsparsh/devsVPN/daemon/splittun"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn/wireguard"
	"github.com/swapnilsparsh/devsVPN/daemon/wifiNotifier"
)

var log *logger.Logger

func init() {
	log = logger.NewLogger("servc")
}

// RequiredState VPN state which service is going to reach
type RequiredState int

// Requested VPN states
const (
	Disconnect     RequiredState = 0
	Connect        RequiredState = 1
	KeepConnection RequiredState = 2
)

const (
	// SessionCheckInterval - the interval for periodical check session status
	SessionCheckInterval time.Duration = time.Hour * 1
)

type pingSet struct {
	_results_mutex           sync.RWMutex
	_result                  map[string]int //[host]latency
	_singleRequestLimitMutex sync.Mutex
	_notifyClients           bool
}

// Service - PrivateLINE service
type Service struct {
	_daemonStopping atomic.Bool // false from start, will be set to true on daemon shutdown (protocol.Stop())

	_evtReceiver       IServiceEventsReceiver
	_api               *api.API
	_serversUpdater    IServersUpdater
	_netChangeDetector INetChangeDetector
	_wgKeysMgr         IWgKeysManager
	_vpn               vpn.Process
	_preferences       preferences.Preferences
	_connectMutex      sync.Mutex

	// Additional information about current VPN connection: outbound IP addresses, local VPN addresses
	// Use GetVpnSessionInfo()/SetVpnSessionInfo() to access this data
	_vpnSessionInfo      VpnSessionInfo
	_vpnSessionInfoMutex sync.Mutex

	// Required VPN state which service is going to reach (disconnect->keep connection->connect)
	// When KeepConnection - reconnects immediately after disconnection
	_requiredVpnState RequiredState

	// Note: Disconnect() function will wait until VPN fully disconnects
	_done chan struct{}

	// nil - when session checker stopped
	// to stop -> write to channel (it is synchronous channel)
	_sessionCheckerStopChn chan struct{}

	// when true - necessary to update account status as soon as it will be possible (e.g. on firewall disconnected)
	_isNeedToUpdateSessionInfo bool

	_globalEvents <-chan ServiceEventType

	_systemLog chan<- SystemLogMessage

	_pingServers, _pingInternalApiHosts pingSet

	// variables needed for automatic resume
	_pause struct {
		_mutex           sync.Mutex
		_pauseTill       time.Time // time when connection will be resumed automatically (if not paused - will be zero)
		_killSwitchState bool      // killswitch state before pause (to be able to restore it)
	}

	// variables related to connection test (e.g. ports accessibility test)
	_connectionTest connTest

	// Information about all connection settings is stored in the 'preferences' object (s._preferences.LastConnectionParams).
	// When VPN is connected, it contains actual connection data.
	// So, it is not allowed to update LastConnectionParams while connected without reconnection (to avoid inconsistency).
	// We use this object to store connection settings while the VPN is connected (to be able to update LastConnectionParams after disconnection).
	// (UI may send us new connection settings while VPN is connected, e.g., when the user changes connection settings in the UI)
	_tmpParams      types.ConnectionParams
	_tmpParamsMutex sync.Mutex

	_statsCallbacks       protocol.StatsCallbacks
	_vpnConnectedCallback protocolTypes.VpnConnectedCallback

	// connectivityHealthchecksBackgroundMonitor data
	connectivityHealthchecksBackgroundMonitorDef                                *srvhelpers.ServiceBackgroundMonitor
	connectivityHealthchecksRunningMutex, connectivityHealthchecksStopFuncMutex sync.Mutex
	stopPollingConnectivityHealthchecks                                         chan bool
	backendConnectivityCheckState                                               BackendConnectivityCheckState
}

// IsDaemonShuttingDown implements protocol.Service.
func (s *Service) IsDaemonStopping() bool {
	return s._daemonStopping.Load()
}

// MarkDaemonShuttingDown implements protocol.Service.
func (s *Service) MarkDaemonStopping() {
	s._daemonStopping.Store(true)
}

// SetRestApiBackend - send true for development REST API backend, false for production one
func (s *Service) SetRestApiBackend(devEnv bool) error {
	s._api.SetRestApiBackend(devEnv)
	return nil
}

func (s *Service) GetRestApiBackend() (devEnv bool) {
	return s._api.GetRestApiBackend()
}

// VpnSessionInfo - Additional information about current VPN connection
type VpnSessionInfo struct {
	// The outbound IP addresses on the moment BEFORE the VPN connection
	OutboundIPv4 net.IP
	OutboundIPv6 net.IP
	// local VPN addresses (outbound IPs)
	VpnLocalIPv4 net.IP
	VpnLocalIPv6 net.IP
}

// CreateService - service constructor
func CreateService(evtReceiver IServiceEventsReceiver,
	api *api.API,
	updater IServersUpdater,
	netChDetector INetChangeDetector,
	wgKeysMgr IWgKeysManager,
	globalEvents <-chan ServiceEventType,
	systemLog chan<- SystemLogMessage) (*Service, error) {

	if updater == nil {
		return &Service{}, fmt.Errorf("ServersUpdater is not defined")
	}

	serv := &Service{
		_preferences:          *preferences.Create(),
		_evtReceiver:          evtReceiver,
		_api:                  api,
		_serversUpdater:       updater,
		_netChangeDetector:    netChDetector,
		_wgKeysMgr:            wgKeysMgr,
		_globalEvents:         globalEvents,
		_systemLog:            systemLog,
		_vpnConnectedCallback: evtReceiver.LastVpnStateIsConnected,
	}

	// init connectivityHealthchecksBackgroundMonitorDef
	serv.stopPollingConnectivityHealthchecks = make(chan bool, 1)
	serv.connectivityHealthchecksBackgroundMonitorDef = &srvhelpers.ServiceBackgroundMonitor{
		MonitorName:          "connectivityHealthchecksBackgroundMonitor",
		MonitorFunc:          serv.connectivityHealthchecksBackgroundMonitor,
		MonitorEndChan:       serv.stopPollingConnectivityHealthchecks,
		MonitorRunningMutex:  &serv.connectivityHealthchecksRunningMutex,
		MonitorStopFuncMutex: &serv.connectivityHealthchecksStopFuncMutex}

	// register the current service as a 'Connectivity checker' for API object
	serv._api.SetConnectivityChecker(serv)

	if err := serv.init(); err != nil {
		return nil, fmt.Errorf("service initialization error : %w", err)
	}

	return serv, nil
}

func (s *Service) init() error {
	s._pingServers._notifyClients = true
	// s._pingInternalApiHosts._notifyClients = false // false by default

	// Start waiting for IP stack initialization
	//
	// _ipStackInitializationWaiter - channel closes as soon as IP stack initialized OR after timeout
	_ipStackInitializationWaiter := make(chan struct{})
	go func() {
		defer close(_ipStackInitializationWaiter) // ip stack initialized (or timeout)
		log.Info("Waiting for IP stack initialization ...")
		endTime := time.Now().Add(time.Minute * 1)
		for {
			ipv4extAddr, errExt := netinfo.GetOutboundIPPrivateLine(false)
			ipv4IntAddr, errInt := netinfo.GetOutboundIPPrivateLine(true)
			if (!ipv4extAddr.IsUnspecified() && errExt == nil) || (!ipv4IntAddr.IsUnspecified() && errInt == nil) {
				log.Info("IP stack initialized")

				// Save IP addresses of the current outbound interface (can be used, for example, for Split-Tunneling)
				ipInfo := s.GetVpnSessionInfo()
				if ipv4IntAddr != nil {
					ipInfo.OutboundIPv4 = ipv4IntAddr
				} else {
					ipInfo.OutboundIPv4 = ipv4extAddr
				}
				ipInfo.OutboundIPv6 = net.ParseIP(splittun.BlackHoleIPv6)
				s.SetVpnSessionInfo(ipInfo)

				return
			}
			if time.Now().After(endTime) {
				log.Info("WARNING! Timeout waiting for IP stack initialization!")
				return
			}
			time.Sleep(time.Millisecond * 200)
		}
	}()

	// Start periodically updating (downloading) servers in background
	go func() {
		<-_ipStackInitializationWaiter // Wait for IP stack initialization
		if err := s._serversUpdater.StartUpdater(); err != nil {
			log.Error("Failed to start servers-list updater: ", err)
		}
	}()

	if err := s._preferences.LoadPreferences(); err != nil {
		log.ErrorFE("Failed to load service preferences: %w", err)

		log.Warning("Saving default values for preferences")
		s._preferences.SavePreferences()
	}

	// initialize firewall functionality
	if err := firewall.Initialize(s.Preferences, s.disableTotalShieldAsync, s._evtReceiver.OnKillSwitchStateChanged, s.ConnectedOrConnecting,
		s._vpnConnectedCallback, s.IsDaemonStopping, s._api.GetRestApiHosts); err != nil {
		return fmt.Errorf("firewall initialization error : %w", err)
	}

	// initialize dns functionality
	funcGetDnsExtraSettings := func() dns.DnsExtraSettings {
		return dns.DnsExtraSettings{Linux_IsDnsMgmtOldStyle: s._preferences.UserPrefs.Linux.IsDnsMgmtOldStyle}
	}
	if err := dns.Initialize(firewall.OnChangeDNS, funcGetDnsExtraSettings); err != nil {
		log.Error(fmt.Sprintf("failed to initialize DNS : %s", err))
	}

	// initialize split-tunnel functionality
	if err := splittun.Initialize(); err != nil {
		log.Warning(fmt.Errorf("Split-Tunnelling initialization error : %w", err))
	} else {
		go func() {
			<-_ipStackInitializationWaiter // Wait for IP stack initialization
			// apply Split Tunneling configuration
			s.splitTunnelling_ApplyConfig(true)
		}()
	}

	// Logging mus be already initialized (by launcher). Do nothing here.
	// Init logger (if not initialized before)
	//logger.Enable(s._preferences.IsLogging)

	// firewall initial values
	if err := firewall.AllowLAN(s._preferences.IsFwAllowLAN, s._preferences.IsFwAllowLANMulticast); err != nil {
		log.Error("Failed to initialize firewall with AllowLAN preference value: ", err)
	}

	//log.Info("Applying firewal exceptions (user configuration)")
	if err := firewall.SetUserExceptions(s._preferences.FwUserExceptions, true); err != nil {
		log.Error("Failed to apply firewall exceptions: ", err)
	}

	if s._preferences.IsFwPersistent {
		log.Info("Enabling firewall (persistent configuration)")
		if err := firewall.SetPersistent(true); err != nil {
			log.Error("Failed to enable firewall: ", err)
		}
	}

	// start WireGuard keys rotation
	if err := s._wgKeysMgr.Init(s); err != nil {
		log.Error("Failed to initialize WG keys rotation:", err)
	} else {

		go func() {
			<-_ipStackInitializationWaiter // Wait for IP stack initialization

			if err := s._wgKeysMgr.StartKeysRotation(); err != nil {
				log.Error("Failed to start WG keys rotation:", err)
			}
		}()
	}

	// if err := s.initWiFiFunctionality(); err != nil {
	// 	log.Error("Failed to init WiFi functionality:", err)
	// }

	// Start session status checker
	go func() {
		<-_ipStackInitializationWaiter // Wait for IP stack initialization
		s.startSessionChecker()
	}()

	s.updateAPIAddrInFWExceptions()
	// servers updated notifier
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in Servers update notifier!: ", r)
				log.Error(string(debug.Stack()))
				if err, ok := r.(error); ok {
					log.ErrorTrace(err)
				}
			}
		}()

		log.Info("Servers update notifier started")
		for {
			// wait for 'servers updated' event
			<-s._serversUpdater.UpdateNotifierChannel()
			// notify clients
			if svrs, err := s.ServersList(); svrs != nil && err == nil {
				s._evtReceiver.OnServersUpdated(svrs)
				// update firewall rules: notify firewall about new IP addresses of IVPN API
				s.updateAPIAddrInFWExceptions()
			}
		}
	}()

	// 'Auto-connect on launch' functionality: auto-connect if necessary
	// 'trusted-wifi' functionality: auto-connect if necessary
	go func() {
		<-_ipStackInitializationWaiter // Wait for IP stack initialization
		s.autoConnectIfRequired(OnDaemonStarted, nil)
	}()

	// Start processing power events in separate routine (Windows)
	s.startProcessingPowerEvents()

	return nil
}

// UnInitialise - function prepares to daemon stop (Stop/Disable everything)
// - disconnect VPN (if connected)
// - disable Split Tunnel mode
// - etc. ...
func (s *Service) UnInitialise() error {
	return s.unInitialise(false)
}

// unInitialise - stop service on logout or daemon is going to stop
// - disconnect VPN (if connected)
// - enable Split Tunnel mode
// - etc. ...
func (s *Service) unInitialise(isLogout bool) error {
	log.Info(fmt.Sprintf("Uninitialising service... isLogout=%t", isLogout))
	var retErr error
	updateRetErr := func(e error) {
		if retErr != nil {
			retErr = fmt.Errorf("%w | error=%w", retErr, e)
		} else {
			retErr = e
		}
	}
	// Disconnect VPN
	if err := s.Disconnect(); err != nil {
		log.Error(err)
		updateRetErr(err)
	}

	// If not logging out - disable firewall. If logging out - parent callers will conditionally disable it.
	if !isLogout {
		if err := firewall.SetEnabled(false); err != nil {
			log.ErrorFE("error disabling firewall: %w", err)
			updateRetErr(err)
		}
	}

	// Run or re-run VPN coexistence clean-up tasks, just in case
	if err := firewall.DisableCoexistenceWithOtherVpns(); err != nil {
		log.ErrorFE("error firewall.DisableCoexistenceWithOtherVpns(): %w", err)
		updateRetErr(err)
	}

	// Disable Split Tunnel
	if err := splittun.Reset(); err != nil {
		err = log.ErrorFE("error splittun.Reset(): %w", err)
		updateRetErr(err)
	}
	// Split tunnel enabled by default, out of the box
	log.Debug("service.go unInitialise() calling splittun.ApplyConfig() with empty splittun.ConfigAddresses")
	if err := splittun.ApplyConfig(true, true, false, false, false, splittun.ConfigAddresses{}, []string{}); err != nil {
		err = log.ErrorFE("error splittun.ApplyConfig(): %w", err)
		updateRetErr(err)
	}

	return retErr
}

// IsConnectivityBlocked - returns nil if connectivity NOT blocked
func (s *Service) IsConnectivityBlocked() error {
	// preferences := s._preferences
	// if !preferences.IsFwAllowApiServers &&
	// 	preferences.Session.IsLoggedIn() &&
	// 	(!s.ConnectedOrConnecting() || s.IsPaused()) {
	// 	enabled, err := s.FirewallEnabled()
	// 	if err != nil {
	// 		return fmt.Errorf("access to privateLINE servers is blocked: %w", err)
	// 	}
	// 	if enabled {
	// 		return fmt.Errorf("access to privateLINE servers is blocked (check privateLINE Connect Firewall settings)")
	// 	}
	// }

	// In principle, connectivity to Wireguard and API servers is never expected to be blocked in privateLINE - both are available over the public internet
	return nil
}

func (s *Service) GetVpnSessionInfo() VpnSessionInfo {
	s._vpnSessionInfoMutex.Lock()
	defer s._vpnSessionInfoMutex.Unlock()
	return s._vpnSessionInfo
}

func (s *Service) SetVpnSessionInfo(i VpnSessionInfo) {
	s._vpnSessionInfoMutex.Lock()
	defer s._vpnSessionInfoMutex.Unlock()
	s._vpnSessionInfo = i
}

func (s *Service) updateAPIAddrInFWExceptions() {
	svrs, err := s.ServersList()
	if err != nil {
		return
	}

	ivpnAPIAddr := svrs.Config.API.IPAddresses

	if len(ivpnAPIAddr) <= 0 {
		return
	}

	apiAddrs := make([]net.IP, 0, len(ivpnAPIAddr))
	for _, ipStr := range ivpnAPIAddr {
		apiIP := net.ParseIP(ipStr)
		if apiIP != nil {
			apiAddrs = append(apiAddrs, apiIP)
		}
	}

	if len(apiAddrs) > 0 {
		const onlyForICMP = false
		const isPersistent = true
		// const isPersistent = false // TODO FIXME: Vlad - changed to false, can't have WFP persistent anything in MVP
		prefs := s.Preferences()
		if prefs.IsFwAllowApiServers {
			firewall.AddHostsToExceptions(apiAddrs, onlyForICMP, isPersistent)
		} else {
			firewall.RemoveHostsFromExceptions(apiAddrs, onlyForICMP, isPersistent)
		}
	}
}

// ServersList returns servers info
// (if there is a cached data available - will be returned data from cache)
func (s *Service) ServersList() (*api_types.ServersInfoResponse, error) {
	return s._serversUpdater.GetServers()
}

func (s *Service) findOpenVpnHost(hostname string, ip net.IP, svrs []api_types.OpenvpnServerInfo) (api_types.OpenVPNServerHostInfo, error) {
	if ((len(hostname) > 0) || (ip != nil && !ip.IsUnspecified())) && svrs != nil {
		for _, svr := range svrs {
			for _, host := range svr.Hosts {
				if (len(hostname) <= 0 || !strings.EqualFold(host.Hostname, hostname)) && (ip == nil || ip.IsUnspecified() || !ip.Equal(net.ParseIP(host.EndpointIP))) {
					continue
				}
				return host, nil
			}
		}
	}

	return api_types.OpenVPNServerHostInfo{}, fmt.Errorf(fmt.Sprintf("host '%s' not found", hostname))
}

// ServersListForceUpdate returns servers list info.
// The daemon will make request to update servers from the backend.
// The cached data will be ignored in this case.
func (s *Service) ServersListForceUpdate() (*api_types.ServersInfoResponse, error) {
	return s._serversUpdater.GetServersForceUpdate()
}

// APIRequest do custom request to API
func (s *Service) APIRequest(apiAlias string, ipTypeRequired protocolTypes.RequiredIPProtocol) (responseData []byte, err error) {

	if ipTypeRequired == protocolTypes.IPv6 {
		// IPV6-LOC-200 - IVPN Apps should request only IPv4 location information when connected  to the gateway, which doesn’t support IPv6
		vpn := s._vpn
		if vpn != nil && !vpn.IsPaused() && !vpn.IsIPv6InTunnel() {
			return nil, fmt.Errorf("no IPv6 support inside tunnel for current connection")
		}
	}

	return s._api.DoRequestByAlias(apiAlias, ipTypeRequired)
}

// GetDisabledFunctions returns info about functions which are disabled
// Some functionality can be not accessible
// It can happen, for example, if some external binaries not installed
// (e.g. obfsproxy or WireGuard on Linux)
func (s *Service) GetDisabledFunctions() protocolTypes.DisabledFunctionality {
	var ovpnErr, obfspErr, v2rayErr, wgErr, splitTunErr, splitTunInversedErr error

	if err := filerights.CheckFileAccessRightsExecutable(platform.OpenVpnBinaryPath()); err != nil {
		ovpnErr = fmt.Errorf("OpenVPN binary: %w", err)
	}

	if err := filerights.CheckFileAccessRightsExecutable(platform.ObfsproxyStartScript()); err != nil {
		obfspErr = fmt.Errorf("obfsproxy binary: %w", err)
	}

	if err := filerights.CheckFileAccessRightsExecutable(platform.V2RayBinaryPath()); err != nil {
		v2rayErr = fmt.Errorf("V2Ray binary: %w", err)
	} else if platform.V2RayConfigFile() == "" {
		v2rayErr = fmt.Errorf("V2Ray config file path not defined")
	}

	if err := filerights.CheckFileAccessRightsExecutable(platform.WgBinaryPath()); err != nil {
		wgErr = fmt.Errorf("WireGuard binary: %w", err)
	} else {
		if err := filerights.CheckFileAccessRightsExecutable(platform.WgToolBinaryPath()); err != nil {
			wgErr = fmt.Errorf("WireGuard tools binary: %w", err)
		}
	}

	// returns non-nil error object if Split-Tunneling functionality not available
	splitTunErr, splitTunInversedErr = splittun.GetFuncNotAvailableError()

	if errors.Is(ovpnErr, os.ErrNotExist) {
		ovpnErr = fmt.Errorf("%w. Please install OpenVPN", ovpnErr)
	}
	if errors.Is(obfspErr, os.ErrNotExist) {
		obfspErr = fmt.Errorf("%w. Please install obfsproxy binary", obfspErr)
	}
	if errors.Is(wgErr, os.ErrNotExist) {
		wgErr = fmt.Errorf("%w. Please install WireGuard", wgErr)
	}

	var ret protocolTypes.DisabledFunctionality

	if wgErr != nil {
		ret.WireGuardError = wgErr.Error()
	}
	if ovpnErr != nil {
		ret.OpenVPNError = ovpnErr.Error()
	}
	if obfspErr != nil {
		ret.ObfsproxyError = obfspErr.Error()
	}
	if v2rayErr != nil {
		ret.V2RayError = v2rayErr.Error()
	}
	if splitTunErr != nil {
		ret.SplitTunnelError = splitTunErr.Error()
	}
	if splitTunInversedErr != nil {
		ret.SplitTunnelInverseError = splitTunInversedErr.Error()
	}

	ret.Platform = s.implGetDisabledFuncForPlatform()

	return ret
}

func (s *Service) IsCanConnectMultiHop() error {
	return s._preferences.Account.IsCanConnectMultiHop()
}

func (s *Service) reconnect() error {
	if s.IsDaemonStopping() {
		log.ErrorFE("error - daemon is stopping")
		return nil
	}

	// Just call disconnect
	// The reconnection will be performed automatically in method 'keepConnection(...)'
	// (according to s._requiredVpnState value == KeepConnection)
	return s.disconnect()
}

// Disconnect disconnect vpn
func (s *Service) Disconnect() error {
	s._requiredVpnState = Disconnect
	// Resume connection (but do not notify "Connection resumed" status)
	if err := s.resume(); err != nil {
		log.Error("Resume failed:", err)
	}
	return s.disconnect()
}

func (s *Service) disconnect() error {
	vpn := s._vpn
	if vpn == nil {
		return nil
	}

	done := s._done
	if s._requiredVpnState == KeepConnection {
		log.Info("Disconnecting (going to reconnect)...")
	} else {
		log.Info("Disconnecting...")
	}

	// stop all service background monitors 1st thing - as the iptables-legacy one is prone to lengthy timeouts (2-3min) on xtables lock
	for _, serviceBackgroundMonitor := range s.listAllServiceBackgroundMonitors() {
		log.Debug("forking StopServiceBackgroundMonitor() for '", serviceBackgroundMonitor.MonitorName, "' from disconnect()")
		go serviceBackgroundMonitor.StopServiceBackgroundMonitor() // async, as iptables-legacy one sleeps for 5s between each polling loop iteration
	}

	// stop detections for routing changes
	s._netChangeDetector.UnInit()

	// stop VPN
	if err := vpn.Disconnect(); err != nil {
		return fmt.Errorf("failed to disconnect VPN: %w", err)
	}

	// wait for stop
	if done != nil {
		<-done
	}

	return nil
}

// ConnectedOrConnecting returns 'true' if VPN is connected or connecting (if VPN process exists)
func (s *Service) ConnectedOrConnecting() bool {
	// TODO: It seems this needs to be reworked.
	// The 's._vpn' can be temporarily nil during reconnection (see keepConnection() function).
	return s._vpn != nil
}

// ConnectedType returns connected VPN type (only if VPN connected!)
func (s *Service) ConnectedType() (isConnected bool, connectedVpnType vpn.Type) {
	vpnObj := s._vpn
	if vpnObj == nil {
		return false, 0
	}
	return true, vpnObj.Type()
}

// FirewallEnabled returns firewall state (enabled\disabled)
// (in use, for example, by WireGuard keys manager, to know is it have sense to make API requests.)
func (s *Service) FirewallEnabled() (bool, error) {
	return firewall.GetEnabled()
}

// Pause pause vpn connection
func (s *Service) Pause(durationSeconds uint32) error {
	vpn := s._vpn
	if vpn == nil {
		return fmt.Errorf("VPN not connected")
	}

	if durationSeconds <= 0 {
		return fmt.Errorf("the duration of the pause has not been specified")
	}

	defer s._evtReceiver.OnVpnPauseChanged()

	s._pause._mutex.Lock()
	defer s._pause._mutex.Unlock()

	fwStatus, err := s.KillSwitchState()
	if err != nil {
		return fmt.Errorf("failed to check KillSwitch status: %w", err)
	}
	s._pause._killSwitchState = fwStatus.IsEnabled
	if fwStatus.IsEnabled && !fwStatus.IsPersistent {
		log.Error("error - disabling the firewall because IsPersistent=false")
		if err := s.SetKillSwitchState(false); err != nil {
			return err
		}
	}

	log.Info("Pausing...")
	firewall.ClientPaused()

	if err = vpn.Pause(); err != nil {
		return err
	}

	// set pause time (to indicate that connection is paused)
	s._pause._pauseTill = time.Now().Add(time.Second * time.Duration(durationSeconds))
	log.Info(fmt.Sprintf("Paused on %v (till %v)", time.Second*time.Duration(durationSeconds), s._pause._pauseTill.Format(time.Stamp)))

	// Update SplitTunnel state (if enabled)
	prefs := s.Preferences()
	if !prefs.IsTotalShieldOn {
		if err := s.splitTunnelling_ApplyConfig(true); err != nil {
			log.Error(err)
		}
	}

	// Pause resumer: Every second checks if it is time to resume VPN connection.
	// Info: We can not use 'time.AfterFunc()' because
	// it does not take into account the time when the system was in sleep mode.
	go func() {
		defer log.Info("Resumed")
		for {
			time.Sleep(time.Second * 1)

			if !s.IsPaused() {
				s._pause._pauseTill = time.Time{} // reset pause time (to indicate that connection is not paused, just in case)
				break
			} else {
				// Note! In order to avoid any potential issues with location or changes with system clock, we must use "monotonic clock" time (Unix()).
				if time.Now().Unix()-s.PausedTill().Unix() >= 0 {
					log.Info(fmt.Sprintf("Automatic resuming after %v ...", time.Second*time.Duration(durationSeconds)))

					// For situations when the system suspended, it can happen that network interfaces are not ready yet.
					// Waiting here to IPv4 interface will be ready.
					var logMesTime time.Time
					for {
						_, err4 := netinfo.GetOutboundIP(false)
						if !s.IsPaused() || err4 == nil {
							break
						}
						if time.Since(logMesTime) > time.Second*15 {
							log.Info("Resume delayed: IPv4 interface not ready yet")
							logMesTime = time.Now()
						}
						time.Sleep(time.Millisecond * 500)
					}

					// Resume connection
					if err := s.Resume(); err != nil {
						log.Error(fmt.Errorf("Resume failed: %w", err))
					}
					break
				}
			}
		}
	}()

	return nil
}

// Resume resume vpn connection
func (s *Service) Resume() error {
	defer s._evtReceiver.OnVpnPauseChanged()

	vpn := s._vpn
	if vpn == nil || !vpn.IsPaused() {
		return fmt.Errorf("VPN not paused")
	}

	if err := s.resume(); err != nil {
		return err
	}

	// Update SplitTunnel state (if enabled)
	prefs := s.Preferences()
	if !prefs.IsTotalShieldOn {
		if err := s.splitTunnelling_ApplyConfig(true); err != nil {
			log.Error(err)
			return err
		}
	}
	return nil
}

// Resume resume vpn connection
func (s *Service) resume() error {
	s._pause._mutex.Lock()
	defer s._pause._mutex.Unlock()
	s._pause._pauseTill = time.Time{} // reset pause time (to indicate that connection is not paused)

	vpn := s._vpn
	if vpn == nil {
		return nil
	}
	if !vpn.IsPaused() {
		return nil
	}

	log.Info("Resuming...")
	firewall.ClientResumed()
	if err := vpn.Resume(); err != nil {
		return err
	}

	fwStatus, err := s.KillSwitchState()
	if err != nil {
		log.Error(fmt.Errorf("failed to check KillSwitch status: %w", err))
	} else {
		if !fwStatus.IsPersistent && fwStatus.IsEnabled != s._pause._killSwitchState {
			if err := s.SetKillSwitchState(s._pause._killSwitchState); err != nil {
				log.Error("failed to restore KillSwitch status: %w", err)
			}
		}
	}

	return nil
}

// IsPaused returns 'true' if current vpn connection is in paused state
func (s *Service) IsPaused() bool {
	vpn := s._vpn
	if vpn == nil {
		return false
	}

	return vpn.IsPaused() && !s.PausedTill().IsZero()
}

func (s *Service) PausedTill() time.Time {
	return s._pause._pauseTill
}

func (s *Service) saveDefaultDnsParams(dnsCfg dns.DnsSettings, antiTrackerCfg types.AntiTrackerMetadata) (retErr error) {
	defaultParams := s.GetConnectionParams()

	if defaultParams.ManualDNS.Equal(dnsCfg) && defaultParams.Metadata.AntiTracker.Equal(antiTrackerCfg) {
		return nil
	}

	// save DNS and AntiTracker default metadata
	defaultParams.ManualDNS = dnsCfg
	defaultParams.Metadata.AntiTracker = antiTrackerCfg

	return s.setConnectionParams(defaultParams)
}

// GetActiveDNS() returns DNS active settings for current VPN connection:
// - if 'antiTracker' is enabled - returns DNS of AntiTracker server
// - else if manual DNS is defined - returns manual DNS
// - else returns default DNS configuration for current VPN connection
// *Note! If VPN disconnected - returns empty data
func (s *Service) GetActiveDNS() (dnsCfg dns.DnsSettings, err error) {
	vpnObj := s._vpn
	if vpnObj == nil {
		return dns.DnsSettings{}, nil //VPN DISCONNECTED
	}

	_, _, manualDns, err := s.GetDefaultManualDnsParams()
	if err != nil {
		return dns.DnsSettings{}, err
	}
	if !manualDns.IsEmpty() {
		return manualDns, nil
	}

	return dns.DnsSettingsCreate(vpnObj.DefaultDNS()), nil
}

// GetDefaultManualDnsParams returns default manual DNS parameters
// Returns:
//
//	manualDnsCfg - default manual DNS parameters
//	antiTrackerCfg - default AntiTracker parameters
//	realDnsValue - real DNS value (if 'antiTracker' is enabled - it will contain DNS of AntiTracker server)
func (s *Service) GetDefaultManualDnsParams() (manualDnsCfg dns.DnsSettings, antiTrackerCfg types.AntiTrackerMetadata, realDnsValue dns.DnsSettings, err error) {
	defaultParams := s.GetConnectionParams()

	manualDnsCfg = defaultParams.ManualDNS
	realDnsValue = defaultParams.ManualDNS
	antiTrackerCfg = defaultParams.Metadata.AntiTracker

	// if antiTrackerCfg.Enabled {
	// 	realDnsValue, err = s.getAntiTrackerDns(antiTrackerCfg.Hardcore, antiTrackerCfg.AntiTrackerBlockListName)
	// }

	return manualDnsCfg, antiTrackerCfg, realDnsValue, err
}

// SetManualDNS update default DNS parameters AND apply new DNS value for current VPN connection
// If 'antiTracker' is enabled - the 'dnsCfg' will be ignored
func (s *Service) SetManualDNS(dnsCfg dns.DnsSettings, antiTracker types.AntiTrackerMetadata) (changedDns dns.DnsSettings, retErr error) {
	prefs := s.Preferences()
	if !dnsCfg.IsEmpty() || antiTracker.Enabled {
		if prefs.IsInverseSplitTunneling() && prefs.SplitTunnelAnyDns {
			return dns.DnsSettings{}, fmt.Errorf("custom DNS or AntiTracker cannot be enabled while allowing all DNS for Inverse Split Tunnel mode; please block non-IVPN DNS first in the Inverse Split Tunnel configuration")
		}
	}

	isChanged := false
	defer func() {
		if isChanged {
			// Apply Firewall rule (for Inverse Split Tunnel): allow DNS requests only to IVPN servers or to manually defined server
			if err := s.splitTunnelling_ApplyConfig(true); err != nil {
				log.Error(err)
			}
		}
	}()

	// Update default metadata
	defaultParams := s.GetConnectionParams()
	// save DNS and AntiTracker default metadata
	if !defaultParams.ManualDNS.Equal(dnsCfg) {
		defaultParams.ManualDNS = dnsCfg
		isChanged = true
	}
	// if !defaultParams.Metadata.AntiTracker.Equal(antiTracker) {
	// 	at, err := s.normalizeAntiTrackerBlockListName(antiTracker)
	// 	if err != nil {
	// 		return changedDns, err
	// 	}
	// 	defaultParams.Metadata.AntiTracker = at
	// 	isChanged = true
	// }
	if isChanged {
		s.setConnectionParams(defaultParams)
	}

	// Get anti-tracker DNS settings
	changedDns = dnsCfg
	// if antiTracker.Enabled {
	// 	atDns, err := s.getAntiTrackerDns(antiTracker.Hardcore, antiTracker.AntiTrackerBlockListName)
	// 	if err != err {
	// 		return dns.DnsSettings{}, err
	// 	}
	// 	changedDns = atDns
	// }

	vpn := s._vpn
	if vpn == nil {
		// no active VPN connection
		return changedDns, nil
	}

	if dnsCfg.IsEmpty() && !antiTracker.Enabled {
		return dns.DnsSettings{}, vpn.ResetManualDNS()
	}
	return changedDns, vpn.SetManualDNS(changedDns)
}

func (s *Service) GetManualDNSStatus() dns.DnsSettings {
	return s.GetConnectionParams().ManualDNS
}

// TODO: Vlad - disabling AntiTracker functionality for now
/*

func (s *Service) GetAntiTrackerStatus() types.AntiTrackerMetadata {
	// Get AntiTracker DNS settings. If error - use default date and ignore error
	retAtMetadata, err := s.normalizeAntiTrackerBlockListName(s.GetConnectionParams().Metadata.AntiTracker)
	if err != nil {
		log.Error(fmt.Sprintf("failed to normalize AntiTracker block list name: %v (using '%s')", err, retAtMetadata.AntiTrackerBlockListName))
	}
	return retAtMetadata
}

// Normze AntiTracker block list name:
// - if antiTrackerPlusList not defined - return default value
// - if antiTrackerPlusList defined - check if it is valid; if not valid - return default value and error
func (s *Service) normalizeAntiTrackerBlockListName(antiTracker types.AntiTrackerMetadata) (types.AntiTrackerMetadata, error) {
	var retError error

	atBlistName := strings.ToLower(strings.TrimSpace(antiTracker.AntiTrackerBlockListName))
	// check if block list name is known
	if atBlistName != "" {
		servers, err := s.ServersList()
		if err == nil {
			for _, atp_svr := range servers.Config.AntiTrackerPlus.DnsServers {
				if strings.ToLower(strings.TrimSpace(atp_svr.Name)) == atBlistName {
					// Block-list name is OK. Just ensure to use correct case
					antiTracker.AntiTrackerBlockListName = strings.TrimSpace(atp_svr.Name)
					return antiTracker, nil
				}
			}
		}

		retError = fmt.Errorf("unexpected DNS block list name: '%s'", antiTracker.AntiTrackerBlockListName)
	}

	// Set default block list name (if empty)
	if tmpDns, err := s.getAntiTrackerDns(antiTracker.Hardcore, ""); err == nil {
		if tmpAt, err := s.getAntiTrackerInfo(tmpDns); err == nil {
			antiTracker.AntiTrackerBlockListName = tmpAt.AntiTrackerBlockListName
		}
	}

	return antiTracker, retError
}

// Get DNS server according to AntiTracker parameters
func (s *Service) getAntiTrackerDns(isHardcore bool, antiTrackerPlusList string) (dnsCfg dns.DnsSettings, err error) {
	defer func() {
		if dnsCfg.IsEmpty() && err == nil {
			err = fmt.Errorf("unable to determine AntiTracker DNS")
		}
	}()
	servers, err := s.ServersList()
	if err != nil {
		return dns.DnsSettings{}, fmt.Errorf("failed to determine AntiTracker parameters: %w", err)
	}

	// AntiTracker Plus list
	atListName := strings.ToLower(strings.TrimSpace(antiTrackerPlusList))
	if len(atListName) == 0 {
		// if block list name not defined - use default AntiTracker block list "Basic"
		atListName = "basic"
	}

	if len(atListName) > 0 {
		for _, atp_svr := range servers.Config.AntiTrackerPlus.DnsServers {
			if strings.ToLower(strings.TrimSpace(atp_svr.Name)) == atListName {
				if isHardcore {
					return dns.DnsSettings{DnsServers: []net.IP{net.ParseIP(atp_svr.Hardcore)}}, nil
				}
				return dns.DnsSettings{DnsServers: []net.IP{net.ParseIP(atp_svr.Normal)}}, nil
			}
		}
	}

	// If AntiTracker Plus block list not found - ignore 'antiTrackerPlusList' and use old-style AntiTracker DNS
	if isHardcore {
		return dns.DnsSettings{DnsServers: []net.IP{net.ParseIP(servers.Config.Antitracker.Hardcore.IP)}}, nil
	}
	return dns.DnsSettings{DnsServers: []net.IP{net.ParseIP(servers.Config.Antitracker.Default.IP)}}, nil
}

// Get AntiTracker info according to DNS settings
func (s *Service) getAntiTrackerInfo(dnsVal dns.DnsSettings) (types.AntiTrackerMetadata, error) {
	if dnsVal.IsEmpty() || dnsVal.Encryption != dns.EncryptionNone {
		return types.AntiTrackerMetadata{}, nil
	}

	servers, err := s.ServersList()
	if err != nil {
		return types.AntiTrackerMetadata{}, fmt.Errorf("failed to determine AntiTracker parameters: %w", err)
	}

	dnsHost := strings.ToLower(strings.TrimSpace(dnsVal.DnsHosts))
	if dnsHost == "" {
		return types.AntiTrackerMetadata{}, nil
	}

	// Check AntiTracker Plus lists
	for _, atp_svr := range servers.Config.AntiTrackerPlus.DnsServers {
		if strings.EqualFold(dnsHost, strings.TrimSpace(atp_svr.Normal)) {
			return types.AntiTrackerMetadata{Enabled: true, Hardcore: false, AntiTrackerBlockListName: atp_svr.Name}, nil
		}
		if strings.EqualFold(dnsHost, strings.TrimSpace(atp_svr.Hardcore)) {
			return types.AntiTrackerMetadata{Enabled: true, Hardcore: true, AntiTrackerBlockListName: atp_svr.Name}, nil
		}
	}

	// Check AntiTracker values
	if strings.EqualFold(dnsHost, strings.TrimSpace(servers.Config.Antitracker.Default.IP)) {
		return types.AntiTrackerMetadata{Enabled: true, Hardcore: false}, nil
	}
	if strings.EqualFold(dnsHost, strings.TrimSpace(servers.Config.Antitracker.Hardcore.IP)) {
		return types.AntiTrackerMetadata{Enabled: true, Hardcore: true}, nil
	}

	return types.AntiTrackerMetadata{}, nil
}
*/

// ////////////////////////////////////////////////////////
// KillSwitch
// ////////////////////////////////////////////////////////
func (s *Service) onKillSwitchStateChanged() {
	s._evtReceiver.OnKillSwitchStateChanged()

	// check if we need try to update account info
	if s._isNeedToUpdateSessionInfo {
		go s.RequestSessionStatus()
	}
}

// ReEnableKillSwitch disable-then-enable kill-switch
func (s *Service) ReEnableKillSwitch() error {
	return firewall.ReEnable()
}

// SetKillSwitchState enable\disable kill-switch
func (s *Service) SetKillSwitchState(isEnabled bool) error {
	if !isEnabled && s._preferences.IsFwPersistent {
		return fmt.Errorf("unable to disable Firewall in 'Persistent' state. Please, disable 'Always-on firewall' first")
	}
	if s.IsPaused() {
		return fmt.Errorf("unable to change the firewall state while connection is paused, please resume the connection first")
	}
	// if isEnabled && s._preferences.IsInverseSplitTunneling() {
	// 	return fmt.Errorf("firewall cannot be enabled while Inverse Split Tunnel is active; please disable Inverse Split Tunnel first")
	// }

	err := firewall.SetEnabled(isEnabled)
	if err == nil {
		s.onKillSwitchStateChanged()
		// If no any clients connected - connection notification will not be passed to user
		// In this case we are trying to save info message into system log
		if !s._evtReceiver.IsClientConnected(false) {
			if isEnabled {
				s.systemLog(Info, "privateLINE Firewall enabled")
			} else {
				s.systemLog(Info, "privateLINE Firewall disabled")
			}
		}
	}
	return err
}

// KillSwitchState returns kill-switch state
func (s *Service) KillSwitchState() (status types.KillSwitchStatus, err error) {
	prefs := s._preferences
	enabled, isLanAllowed, _, weHaveTopFirewallPriority, otherVpnID, otherVpnName, otherVpnDescription, err := firewall.GetState()

	return types.KillSwitchStatus{
		IsEnabled:                 enabled,
		IsPersistent:              prefs.IsFwPersistent,
		IsAllowLAN:                prefs.IsFwAllowLAN,
		IsAllowMulticast:          prefs.IsFwAllowLANMulticast,
		IsAllowApiServers:         prefs.IsFwAllowApiServers,
		UserExceptions:            prefs.FwUserExceptions,
		StateLanAllowed:           isLanAllowed,
		WeHaveTopFirewallPriority: weHaveTopFirewallPriority,
		OtherVpnID:                otherVpnID,
		OtherVpnName:              otherVpnName,
		OtherVpnDescription:       otherVpnDescription,
	}, err
}

// SetKillSwitchIsPersistent change kill-switch value
func (s *Service) SetKillSwitchIsPersistent(isPersistent bool) error {
	// if isPersistent {
	// 	return fmt.Errorf("error - WFP (Windows Filtering Platform) persistence not supported")
	// }

	if s.IsPaused() {
		return fmt.Errorf("unable to change the firewall state while connection is paused, please resume the connection first")
	}

	// if isPersistent && s._preferences.IsInverseSplitTunneling() {
	// 	return fmt.Errorf("firewall cannot be enabled while Inverse Split Tunnel is active; please disable Inverse Split Tunnel first")
	// }

	prefs := s._preferences
	prefs.IsFwPersistent = isPersistent
	s.setPreferences(prefs)

	err := firewall.SetPersistent(isPersistent)
	if err == nil {
		s.onKillSwitchStateChanged()
	}
	return err
}

// SetKillSwitchAllowLAN change kill-switch value
func (s *Service) SetKillSwitchAllowLAN(isAllowLan bool) error {
	return s.setKillSwitchAllowLAN(isAllowLan, s._preferences.IsFwAllowLANMulticast)
}

// SetKillSwitchAllowLANMulticast change kill-switch value
func (s *Service) SetKillSwitchAllowLANMulticast(isAllowLanMulticast bool) error {
	return s.setKillSwitchAllowLAN(s._preferences.IsFwAllowLAN, isAllowLanMulticast)
}

func (s *Service) setKillSwitchAllowLAN(isAllowLan bool, isAllowLanMulticast bool) error {
	prefs := s._preferences
	prefs.IsFwAllowLAN = isAllowLan
	prefs.IsFwAllowLANMulticast = isAllowLanMulticast
	s.setPreferences(prefs)

	err := s.applyKillSwitchAllowLAN(nil)
	if err == nil {
		s.onKillSwitchStateChanged()
	}
	return err
}

func (s *Service) applyKillSwitchAllowLAN(wifiInfoPtr *wifiNotifier.WifiInfo) error {
	log.Debug("applyKillSwitchAllowLAN")
	prefs := s._preferences

	isAllowLAN := prefs.IsFwAllowLAN
	if isAllowLAN && s.isTrustedWifiForcingToBlockLan(wifiInfoPtr) {
		log.Info("Firewall (block LAN): according to configuration for Untrusted WiFi")
		isAllowLAN = false
	}

	return firewall.AllowLAN(isAllowLAN, prefs.IsFwAllowLANMulticast)
}

// KillSwitchReregister try to reregister our firewall logic at top
func (s *Service) KillSwitchReregister(canStopOtherVpn bool) (err error) {
	// If we're connected/connecting/etc. - fork disconnect request.
	// Otherwise, if we're trying to connect VPN and reregister our firewall in parallel - we tend to get errors in firewall.HaveTopFirewallPriority() (looking up meet.privateline.network)
	go s.Disconnect()

	if err = firewall.TryReregisterFirewallAtTopPriority(canStopOtherVpn, false); err != nil {
		return err
	}

	// Vlad - so don't try firewall.DeployPostConnectionRules() here, another VPN connection will take care of that
	// if s.Connected() {
	// 	if haveTopFirewallPriority, _, _, _, err := firewall.HaveTopFirewallPriority(); err != nil {
	// 		return err
	// 	} else if haveTopFirewallPriority {
	// 		return firewall.DeployPostConnectionRules(false) // here meet.privateline.network hostname lookup should succeed, no need to wait in the background
	// 	}
	// }

	return err
}

func (s *Service) SetKillSwitchAllowAPIServers(isAllowAPIServers bool) error {
	if !isAllowAPIServers {
		// Do not allow to disable access to IVPN API server if user logged-out
		// Otherwise, we will not have possibility to login
		session := s.Preferences().Session
		if !session.IsLoggedIn() {
			return srverrors.ErrorNotLoggedIn{}
		}
	}

	prefs := s._preferences
	prefs.IsFwAllowApiServers = isAllowAPIServers
	s.setPreferences(prefs)
	s.onKillSwitchStateChanged()
	s.updateAPIAddrInFWExceptions()
	return nil
}

// SetKillSwitchUserExceptions set ip/mask to be excluded from FW block
// Parameters:
//   - exceptions - comma separated list of IP addresses in format: x.x.x.x[/xx]
func (s *Service) SetKillSwitchUserExceptions(exceptions string, ignoreParsingErrors bool) error {
	prefs := s._preferences
	prefs.FwUserExceptions = exceptions
	s.setPreferences(prefs)

	err := firewall.SetUserExceptions(exceptions, ignoreParsingErrors)
	if err == nil {
		s.onKillSwitchStateChanged()
	}
	return err
}

func (s *Service) KillSwitchCleanup() error {
	err := firewall.CleanupRegistration()
	// don't run onKillSwitchStateChanged() - otherwise it recreates our provider and sublayer
	// if err == nil {
	// 	s.onKillSwitchStateChanged()
	// }
	return err
}

//////////////////////////////////////////////////////////
// PREFERENCES
//////////////////////////////////////////////////////////

// SetPreference set preference value
func (s *Service) SetPreference(key protocolTypes.ServicePreference, val string) (isChanged bool, err error) {
	prefs := s._preferences
	isChanged = false

	switch key {
	case protocolTypes.Prefs_IsEnableLogging:
		if val, err := strconv.ParseBool(val); err == nil {
			isChanged = val != prefs.IsLogging
			prefs.IsLogging = val
			logger.Enable(val)
		}

	case protocolTypes.Prefs_IsAutoconnectOnLaunch:
		if val, err := strconv.ParseBool(val); err == nil {
			isChanged = val != prefs.IsAutoconnectOnLaunch
			prefs.IsAutoconnectOnLaunch = val
		}

	case protocolTypes.Prefs_IsAutoconnectOnLaunch_Daemon:
		if val, err := strconv.ParseBool(val); err == nil {
			if val {
				if e := prefs.LastConnectionParams.CheckIsDefined(); e != nil {
					return false, srverrors.ErrorBackgroundConnectionNoParams{}
				}
			}
			isChanged = val != prefs.IsAutoconnectOnLaunchDaemon
			prefs.IsAutoconnectOnLaunchDaemon = val
		}

	case protocolTypes.Prefs_HealthchecksType:
		if healthchecksType, ok := service_types.HealthcheckTypesByName[val]; ok {
			isChanged = healthchecksType != prefs.HealthchecksType
			prefs.HealthchecksType = healthchecksType
			log.Debug("SetPreference(): val=", val, "; prefs.HealthchecksType=", prefs.HealthchecksType)
		} else {
			return false, log.ErrorFE("invalid HealthchecksType value: %s. Must be one of: Ping, RestApiCall, Disabled", val)
		}

	case protocolTypes.Prefs_PermissionReconfigureOtherVPNs:
		if val, err := strconv.ParseBool(val); err == nil {
			isChanged = val != prefs.PermissionReconfigureOtherVPNs
			prefs.PermissionReconfigureOtherVPNs = val
		} else {
			return false, fmt.Errorf("invalid PermissionReconfigureOtherVPNs value: %t. Must be a boolean", val)
		}

	default:
		log.Warning(fmt.Sprintf("Preference key '%s' not supported", key))
	}

	s.setPreferences(prefs)

	if isChanged {
		log.Info(fmt.Sprintf("(prefs '%s' changed) %s", key, val))
	}

	return isChanged, nil
}

// SetPreference set preference value
func (s *Service) SetUserPreferences(userPrefs preferences.UserPreferences) error {
	// platform-specific check if we can apply this preferences
	if err := s.implIsCanApplyUserPreferences(userPrefs); err != nil {
		return err
	}

	prefs := s._preferences
	prefs.UserPrefs = userPrefs
	s.setPreferences(prefs)

	return nil
}

// Preferences returns preferences
func (s *Service) Preferences() preferences.Preferences {
	return s._preferences
}

// fork it asynchronously only, because firewall.TotalShieldApply() needs to wait for a lot of mutexes
var disableTotalShieldAsyncMutex sync.Mutex // single-instance function
func (s *Service) disableTotalShieldAsync() {
	disableTotalShieldAsyncMutex.Lock()
	defer disableTotalShieldAsyncMutex.Unlock()

	if !s._preferences.IsTotalShieldOn { // if already disabled - nothing to do
		return
	}

	prefs := s._preferences
	prefs.IsTotalShieldOn = false
	s.setPreferences(prefs)

	if err := firewall.TotalShieldApply(); err != nil {
		log.ErrorFE("error firewall.TotalShieldApply(): %w", err)
	}

	// notify clients
	s._evtReceiver.OnSplitTunnelStatusChanged()
}

func (s *Service) ResetPreferences() error {
	s._preferences = *preferences.Create()

	// erase ST config -  split tunnel config by default
	s.SplitTunnelling_SetConfig(true, true, false, false, false, true)
	return nil
}

func (s *Service) GetConnectionParams() types.ConnectionParams {
	return s._preferences.LastConnectionParams
}

func (s *Service) SetConnectionParams(params types.ConnectionParams) error {
	if s.ConnectedOrConnecting() {
		s._tmpParamsMutex.Lock()
		s._tmpParams = params
		s._tmpParamsMutex.Unlock()
		return nil
	}

	prefs := s._preferences

	isOldParamsDefined := prefs.LastConnectionParams.CheckIsDefined() == nil

	retErr := s.setConnectionParams(params)

	if !isOldParamsDefined && prefs.LastConnectionParams.CheckIsDefined() != nil {
		// if it is first initialization of connection parameters - run auto-connection rules
		// (seems, it is first start after app version upgrade)

		prefs := s.Preferences()
		const checkOnlyUiClients = true
		if prefs.Session.IsLoggedIn() && s._evtReceiver.IsClientConnected(checkOnlyUiClients) {
			log.Info("Applying auto-connection rules (reason: first initialization of connection parameters) ...")
			s.autoConnectIfRequired(OnUiClientConnected, nil)
		}
	}

	return retErr
}

func (s *Service) setConnectionParams(params types.ConnectionParams) error {
	prefs := s._preferences

	// TODO: FIXME: Vlad - if we have already stored a Wireguard server config, then used the saved one, don't overwrite it from here
	if len(prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts) >= 0 {
		return nil
	}
	prefs.LastConnectionParams = params
	s.setPreferences(prefs)

	return nil
}

func (s *Service) SetWiFiSettings(params preferences.WiFiParams) error {
	if params.CanApplyInBackground {
		prefs := s._preferences
		if e := prefs.LastConnectionParams.CheckIsDefined(); e != nil {
			return srverrors.ErrorBackgroundConnectionNoParams{}
		}
	}

	// remove duplicate networks from 'trusted' list
	newNets := []preferences.WiFiNetwork{}
	keys := make(map[string]struct{})
	for _, n := range params.Networks {
		if _, exists := keys[n.SSID]; !exists && len(n.SSID) > 0 {
			newNets = append(newNets, n)
			keys[n.SSID] = struct{}{}
		}
	}
	params.Networks = newNets

	// Save settings
	prefs := s._preferences
	prefs.WiFiControl = params
	s.setPreferences(prefs)

	// 'trusted-wifi' functionality: auto-connect if necessary
	s.autoConnectIfRequired(OnWifiChanged, nil)
	return nil
}

//////////////////////////////////////////////////////////
// SPLIT TUNNEL
//////////////////////////////////////////////////////////

func (s *Service) GetInstalledApps(extraArgsJSON string) ([]oshelpers.AppInfo, error) {
	return oshelpers.GetInstalledApps(extraArgsJSON)
}

func (s *Service) GetBinaryIcon(binaryPath string) (string, error) {
	return oshelpers.GetBinaryIconBase64(binaryPath)
}

func (s *Service) SplitTunnelling_GetStatus() (protocolTypes.SplitTunnelStatus, error) {
	var prefs = s.Preferences()
	runningProcesses, err := splittun.GetRunningApps()
	if err != nil {
		runningProcesses = []splittun.RunningApp{}
	}

	stErr, stInverseErr := splittun.GetFuncNotAvailableError()
	isEnabled := !prefs.IsTotalShieldOn
	if stErr != nil {
		isEnabled = false
	}
	isInversed := prefs.SplitTunnelInversed
	enableAppWhitelist := prefs.EnableAppWhitelist
	isAnyDns := prefs.SplitTunnelAnyDns
	isAllowWhenNoVpn := prefs.SplitTunnelAllowWhenNoVpn
	if stInverseErr != nil {
		isInversed = false
		isAnyDns = false
		isAllowWhenNoVpn = false
	}

	if !prefs.Session.IsLoggedIn() {
		// Total Shield (full tunnel) not applicable when logged out
		// Sending "enabled" status
		isEnabled = true
	}

	ret := protocolTypes.SplitTunnelStatus{
		IsFunctionalityNotAvailable: stErr != nil,
		IsEnabled:                   isEnabled,
		IsAppWhitelistEnabled:       enableAppWhitelist,
		IsInversed:                  isInversed,
		EnableAppWhitelist:          enableAppWhitelist,
		IsAnyDns:                    isAnyDns,
		IsAllowWhenNoVpn:            isAllowWhenNoVpn,
		IsCanGetAppIconForBinary:    oshelpers.IsCanGetAppIconForBinary(),
		SplitTunnelApps:             prefs.SplitTunnelApps,
		RunningApps:                 runningProcesses}

	return ret, nil
}

func (s *Service) splitTunnelCheckConditions(splitTunIsEnabled, splitTunIsInversed bool) (ok bool, err error) {
	return s.implSplitTunnelling_CheckConditions(splitTunIsEnabled, splitTunIsInversed)
}

func (s *Service) SplitTunnelling_SetConfig(isEnabled, isInversed, enableAppWhitelist, isAnyDns, isAllowWhenNoVpn, reset bool) (ret error) {
	// Vlad: for App Whitelist feature we keep inversed mode always on
	isInversed = true

	if reset {
		return s.splitTunnelling_Reset()
	}
	stErr, stInverseErr := splittun.GetFuncNotAvailableError()
	if stErr != nil {
		return stErr
	}
	if isInversed && stInverseErr != nil {
		return stInverseErr
	}

	// Check plan name. Free accounts are not allowed to use Total Shield.
	// if !isEnabled {
	// 	session := s.Preferences().Session
	// 	if !session.IsLoggedIn() {
	// 		return log.ErrorE(errors.New("Total Shield is only available for premium plans. You're not logged in yet, so cannot check your subscription. Please login first."), 0)
	// 	}

	// 	if s.Preferences().PlanName == "" { // if we haven't fetched plan name yet, fetch it now
	// 		if _, _, err := s.SubscriptionData(); err != nil {
	// 			return log.ErrorE(fmt.Errorf("error fetching plan name: %w", err), 0)
	// 		}
	// 		if s.Preferences().PlanName == "" {
	// 			return log.ErrorE(errors.New("error - plan name still empty after calling SubscriptionData()"), 0)
	// 		}
	// 	}

	// 	if s.Preferences().PlanName == "Free" {
	// 		return log.ErrorE(errors.New("Total Shield is only available for premium plans. You can upgrade your subscription at https://privateline.io/#pricing"), 0)
	// 	}
	// }

	// requirements to enable Split Tunnel differ by platform
	if isEnabled && isInversed {
		if splitTunConditionsGood, err := s.splitTunnelCheckConditions(isEnabled, isInversed); err != nil {
			return log.ErrorFE("error checking conditions for Split tunnel: isEnabled=%t isInversed=%t: %w", isEnabled, isInversed, err)
		} else if !splitTunConditionsGood {
			return log.ErrorFE("error - conditions not met for Split tunnel: isEnabled=%t isInversed=%t", isEnabled, isInversed)
		}

		// if we are going to allow any DNS in INVERSE SplitTunneling mode - ensure that custom DNS and AntiTracker is disabled
		if isAnyDns {
			defaultParams := s.GetConnectionParams()
			if defaultParams.Metadata.AntiTracker.Enabled {
				return log.ErrorFE("unable to disable the non-privateLINE DNS blocking feature for Inverse Split Tunnel mode: AntiTracker is currently enabled; please disable both AntiTracker and manually configured DNS settings first")
			}
			if !defaultParams.ManualDNS.IsEmpty() {
				return log.ErrorFE("unable to disable the non-privateLINE DNS blocking feature for Inverse Split Tunnel mode: manual DNS is currently enabled; please disable manually configured DNS settings first")
			}
		}
	}

	prefsOld := s._preferences
	prefs := prefsOld
	prefs.IsTotalShieldOn = !isEnabled
	prefs.SplitTunnelInversed = isInversed
	prefs.EnableAppWhitelist = enableAppWhitelist
	prefs.SplitTunnelAnyDns = isAnyDns
	prefs.SplitTunnelAllowWhenNoVpn = isAllowWhenNoVpn
	s.setPreferences(prefs)

	// ======================== Split Tunnel Service value As Passed from Frontend START ============================
	fmt.Print("\n=======================Split Tunnel Service value As Passed from Frontend START================================\n")
	fmt.Print(isEnabled, isInversed, isAnyDns, isAllowWhenNoVpn, reset)
	fmt.Print("\n========================Split Tunnel Service value As Passed from Frontend END===============================\n")
	// ======================== Split Tunnel Service value As Passed from Frontend END ==============================

	if ret = s.splitTunnelling_ApplyConfig(true); ret != nil {
		ret = log.ErrorFE("failed to apply SplitTunnel configuration, error in s.splitTunnelling_ApplyConfig(): %w", ret)
		// if error - restore old preferences and apply configuration
		s.setPreferences(prefsOld)
		if err := s.splitTunnelling_ApplyConfig(true); err != nil {
			log.ErrorFE("failed to restore SplitTunnel configuration: %w", err)
		}
	}

	return ret
}

func (s *Service) splitTunnelling_Reset() error {
	prefs := s._preferences
	prefs.IsTotalShieldOn = false
	prefs.SplitTunnelInversed = true
	prefs.EnableAppWhitelist = false
	prefs.SplitTunnelAnyDns = false
	prefs.SplitTunnelAllowWhenNoVpn = false
	prefs.SplitTunnelApps = make([]string, 0)
	s.setPreferences(prefs)

	splittun.Reset()

	// Apply configuration
	return s.splitTunnelling_ApplyConfig(true)
}

// splitTunnelling_ApplyConfig() applies the required SplitTunnel configuration based on:
// - current VPN connection state
// - current SplitTunnel config (VPN and default interfaces; InverseSplitTunneling config and splitted apps list)
//
// It is important to call this function after:
// - VPN connection state changed
// - SplitTunnel configuration changed
// - DNS configuration changed (needed for updating Inverse Split Tunnel firewal rule)
//
// applyTotalShieldUnconditionally:
//
//	true - propagate Total Shield setting from preferences to firewall unconditionally (well, if firewall is up); run firewall.TotalShieldApply() synchronously
//	false - fork firewall.ReDetectOtherVpns() asynchronously; instruct it to scan for other VPNs only by interface names
func (s *Service) splitTunnelling_ApplyConfig(applyTotalShieldUnconditionally bool) (retError error) {
	defer func() {
		// notify changed ST configuration status (even if functionality not available)
		s._evtReceiver.OnSplitTunnelStatusChanged()
	}()

	// log.Debug("splitTunnelling_ApplyConfig entered")
	// defer log.Debug("splitTunnelling_ApplyConfig exited")

	if stErr, _ := splittun.GetFuncNotAvailableError(); stErr != nil {
		log.ErrorFE("Split-Tunneling not accessible (not able to connect to a driver or not implemented for current platform: %w", stErr)
		return nil
	}

	prefs := s.Preferences()

	// Vlad: disabling IsLoggedIn check. If the service crashed while in full tunnel, and left the machine w/o default routes,
	// then (if we're not connecting to VPN on start) we absolutely must restore the default routes on start, regardless of the
	// state we're starting from.
	//
	// if !prefs.Session.IsLoggedIn() {
	// 	return srverrors.ErrorNotLoggedIn{}
	// }

	// Network changes detection must be disabled for Inverse SplitTunneling
	// if prefs.IsInverseSplitTunneling() {
	// 	// If inverse SplitTunneling is enabled - stop detection of network changes (if it already started)
	// 	if err := s._netChangeDetector.Stop(); err != nil {
	// 		log.Error(fmt.Sprintf("Unable to stop network changes detection: %v", err.Error()))
	// 	}
	// } else {
	defer func() {
		// If inverse SplitTunneling is disabled - start detection of network changes (if it is not already started)
		if s.ConnectedOrConnecting() {
			if err := s._netChangeDetector.Start(); err != nil {
				log.Error(fmt.Sprintf("Unable to start network changes detection: %v", err.Error()))
			}
		}
	}()
	// }

	// sInf := s.GetVpnSessionInfo()

	var (
		err                        error
		ipv4Endpoint, ipv6Endpoint net.IP
		endpointIP                 string
		servers                    *api_types.ServersInfoResponse
	)

	if len(prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts) > 0 {
		endpointIP = prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts[0].EndpointIP
	} else { // if we didn't receive Wireguard .conf from the server yet (i.e. if the device is not registered, if we're logged out), then use endpoint from servers.conf
		servers, err = s._serversUpdater.GetServers()
		if err != nil {
			return fmt.Errorf("error in GetServers(): %w", err)
		}
		endpointIP = servers.WireguardServers[0].Hosts[0].EndpointIP
	}

	if ipv4Endpoint = net.ParseIP(endpointIP); ipv4Endpoint == nil {
		return fmt.Errorf("error net.ParseIP(%s)", endpointIP)
	}

	// TODO: Vlad - since we don't have any IPv6 endpoint for our Wireguard VPN, hardcoding a blackhole address here
	if ipv6Endpoint = net.ParseIP(splittun.BlackHoleIPv6); ipv6Endpoint == nil {
		return fmt.Errorf("error net.ParseIP(%s)", splittun.BlackHoleIPv6)
	}

	// addressesCfg := splittun.ConfigAddresses{
	// 	IPv4Tunnel: sInf.VpnLocalIPv4,
	// 	IPv4Public: sInf.OutboundIPv4,
	// 	IPv6Tunnel: sInf.VpnLocalIPv6,
	// 	IPv6Public: sInf.OutboundIPv6,

	// 	IPv4Endpoint: ipv4Endpoint,
	// 	IPv6Endpoint: ipv6Endpoint,
	// }

	// Apply Firewall rule (for Inverse Split Tunnel): allow DNS requests only to IVPN servers or to manually defined server
	if err := firewall.SingleDnsRuleOff(); err != nil { // disable custom DNS rule (if exists)
		log.Error(err)
	}
	isVpnConnected := s.ConnectedOrConnecting() && !s.IsPaused()
	if isVpnConnected && prefs.IsInverseSplitTunneling() && !prefs.SplitTunnelAnyDns {
		dnsCfg, err := s.GetActiveDNS() // returns nil when VPN not connected
		if err != nil {
			return fmt.Errorf("failed to apply the firewall rule to allow DNS requests only to the IVPN server: %w", err)
		}
		if !dnsCfg.IsEmpty() {
			log.Debug("isVpnConnected && prefs.IsInverseSplitTunneling() && !prefs.SplitTunnelAnyDns - so applying SingleDnsRuleOn()")
			if err := firewall.SingleDnsRuleOn(dnsCfg.DnsServers[0]); err != nil {
				return fmt.Errorf("failed to apply the firewall rule to allow DNS requests only to the IVPN server: %w", err)
			}
		}
	}

	// Apply Split-Tun config
	// if runtime.GOOS == "windows" {
	// log.Debug("splitTunnelling_ApplyConfig calling firewall.TotalShieldApply() with prefs.IsTotalShieldOn=", prefs.IsTotalShieldOn)
	// return firewall.TotalShieldApply()
	// } else {
	// 	return splittun.ApplyConfig(prefs.IsSplitTunnel, prefs.IsInverseSplitTunneling(), prefs.EnableAppWhitelist, prefs.SplitTunnelAllowWhenNoVpn, isVpnConnected, addressesCfg, prefs.SplitTunnelApps)
	// }

	if applyTotalShieldUnconditionally {
		return firewall.TotalShieldApply() // synchronously
	} else {
		go firewall.ReDetectOtherVpns(true, true, true) // scan for other VPNs only by interface names, asynchronously; force redetection
	}

	return nil
}

func (s *Service) SplitTunnelling_AddApp(exec string) (cmdToExecute string, isAlreadyRunning bool, err error) {
	// if !s._preferences.IsSplitTunnel {
	// 	return "", false, fmt.Errorf("unable to run application in Split Tunnel environment: Split Tunnel is disabled")
	// }
	// apply ST configuration after function ends
	defer s.splitTunnelling_ApplyConfig(true)
	return s.implSplitTunnelling_AddApp(exec)
}

func (s *Service) SplitTunnelling_RemoveApp(pid int, exec string) (err error) {
	// apply ST configuration after function ends
	defer s.splitTunnelling_ApplyConfig(true)
	return s.implSplitTunnelling_RemoveApp(pid, exec)
}

// Inform the daemon about started process in ST environment
// Parameters:
// pid 			- process PID
// exec 		- Command executed in ST environment (e.g. binary + arguments)
//
//	(identical to SplitTunnelAddApp.Exec and SplitTunnelAddAppCmdResp.Exec)
//
// cmdToExecute - Shell command used to perform this operation
func (s *Service) SplitTunnelling_AddedPidInfo(pid int, exec string, cmdToExecute string) error {
	// notify changed ST configuration status
	defer s._evtReceiver.OnSplitTunnelStatusChanged()
	return s.implSplitTunnelling_AddedPidInfo(pid, exec, cmdToExecute)
}

//////////////////////////////////////////////////////////
// SESSIONS
//////////////////////////////////////////////////////////

func (s *Service) setCredentials(accountInfo preferences.AccountStatus, accountID, session, deviceName, vpnUser, vpnPass, wgPublicKey, wgPrivateKey, wgLocalIP string, wgKeyGenerated int64, wgPreSharedKey string, deviceID string) error {
	// save session info
	s._preferences.SetSession(accountInfo,
		accountID,
		session,
		deviceName,
		vpnUser,
		vpnPass,
		wgPublicKey,
		wgPrivateKey,
		wgLocalIP,
		wgPreSharedKey,
		deviceID)

	// manually set info about WG keys timestamp
	if wgKeyGenerated > 0 {
		s._preferences.Session.WGKeyGenerated = time.Unix(wgKeyGenerated, 0)
		s._preferences.SavePreferences()
	}

	// notify clients about session update
	s._evtReceiver.OnServiceSessionChanged()

	// start session checker
	s.startSessionChecker()

	// start WireGuard keys rotation
	if err := s._wgKeysMgr.StartKeysRotation(); err != nil {
		log.Error(fmt.Sprintf("Unable to start WireGuard keys rotation: %v", err.Error()))
	}

	return nil
}

// SessionNew creates new session
func (s *Service) SessionNew(emailOrAcctID string, password string, deviceName string, stableDeviceID, notifyClientsOnSessionDelete, disableFirewallOnExit, disableFirewallOnErrorOnly bool) (
	apiCode int,
	apiErrorMsg string,
	accountInfo preferences.AccountStatus,
	rawResponse string,
	err error) {

	if disableFirewallOnExit || disableFirewallOnErrorOnly {
		defer func() {
			if disableFirewallOnExit || (disableFirewallOnErrorOnly && err != nil) {
				s.SetKillSwitchState(false)
			}
		}()
	}

	// 	try to enable the firewall, need VPN coexistence logic up - otherwise our API calls may not go through
	if err := firewall.EnableIfNeeded(); err != nil {
		return 0, "", preferences.AccountStatus{}, "", log.ErrorFE("error in firewall.EnableIfNeeded: %w", err)
	}
	// TODO: Vlad - disabling old IVPN logic that deals with API servers as exceptions
	// // Temporary allow API server access (If Firewall is enabled)
	// // Otherwise, there will not be any possibility to Login (because all connectivity is blocked)
	// fwStatus, _ := s.KillSwitchState()
	// if fwStatus.IsEnabled && !fwStatus.IsAllowApiServers {
	// 	s.SetKillSwitchAllowAPIServers(true)
	// }
	// defer func() {
	// 	if fwStatus.IsEnabled && !fwStatus.IsAllowApiServers {
	// 		// restore state for 'AllowAPIServers' configuration (previously, was enabled)
	// 		s.SetKillSwitchAllowAPIServers(false)
	// 	}
	// }()

	// delete current session (if exists)
	if helpers.IsAValidAccountID(s.Preferences().Session.AccountID) { // if we have stored an account ID - try to logout
		isCanDeleteSessionLocally := true
		if err := s.SessionDelete(isCanDeleteSessionLocally, notifyClientsOnSessionDelete, false); err != nil {
			log.Error("Creating new session -> Failed to delete active session: ", err)
		}
	}

	// Generate keys for Key Encapsulation Mechanism using post-quantum cryptographic algorithms
	// var kemKeys api_types.KemPublicKeys
	// kemHelper, err := kem.CreateHelper(platform.KemHelperBinaryPath(), kem.GetDefaultKemAlgorithms())
	// if err != nil {
	// 	log.Error("Failed to generate KEM keys: ", err)
	// } else {
	// 	kemKeys.KemPublicKey_Kyber1024, err = kemHelper.GetPublicKey(kem.AlgName_Kyber1024)
	// 	if err != nil {
	// 		log.Error(err)
	// 	}
	// 	kemKeys.KemPublicKey_ClassicMcEliece348864, err = kemHelper.GetPublicKey(kem.AlgName_ClassicMcEliece348864)
	// 	if err != nil {
	// 		log.Error(err)
	// 	}
	// }

	log.Info("Logging in...")
	defer func() {
		if err != nil {
			log.Debug("================================ Error Reached ================================", err)
			log.Debug("================================ API Code: ================================", apiCode)

			var customMessage string
			switch apiCode {
			case 426:
			case 412:
				log.Debug("================================ "+strconv.Itoa(apiCode)+": ================================", err)
				customMessage = fmt.Sprintf("We are sorry - we are unable to add an additional device to your account, because you already registered a "+
					"maximum of %d devices possible under your current subscription. You can go to your device list on our website "+
					"(https://account.privateline.io/pl-connect/page/1) and unregister some of your existing devices from your account, or you can upgrade"+
					" your subscription at https://privateline.io/order in order to be able to use more devices. %s",
					s._preferences.Account.DeviceLimit, err)
			default:
				log.Debug("================================ Default error ================================", err)
				customMessage = fmt.Sprintf("Logging in - FAILED: %s", err)
			}

			log.Warning(customMessage)
			log.Error("Logging in - FAILED: ", err)
		} else {
			log.Info("Logging in - SUCCESS")
		}
	}()

	var (
		publicKey  string
		privateKey string

		wgPresharedKey        string
		sessionNewSuccessResp *api_types.SessionNewResponse
		errorLimitResp        *api_types.SessionNewErrorLimitResponse
		apiErr                *api_types.APIErrorResponse
		connectDevSuccessResp *api_types.ConnectDeviceResponse

		deviceID string
	)

	for {
		// generate new keys for WireGuard
		publicKey, privateKey, err = wireguard.GenerateKeys(platform.WgToolBinaryPath())
		if err != nil {
			log.Warning(fmt.Sprintf("Failed to generate wireguard keys for new session: %s", err.Error()))
		}

		apiCode = 0
		// TODO: Vlad - right now the production REST API deskapi.privateline.io/user/login/quick-auth is broken, for some account IDs it works only with "a-" prefix and for some it only works without. So trying both.
		sessionNewSuccessResp, errorLimitResp, apiErr, rawResponse, err = s._api.SessionNew(emailOrAcctID, password, false)
		if apiErr != nil && apiErr.HttpStatusCode == 400 {
			sessionNewSuccessResp, errorLimitResp, apiErr, rawResponse, err = s._api.SessionNew(emailOrAcctID, password, true)
		}

		if apiErr != nil {
			apiCode = apiErr.HttpStatusCode
		}

		if err != nil {
			// if SessionsLimit response
			if errorLimitResp != nil {
				accountInfo = s.createAccountStatus(errorLimitResp.SessionLimitData)
				return apiCode, apiErr.Message, accountInfo, rawResponse, err
			}

			// in case of other API error
			if apiErr != nil {
				return apiCode, apiErr.Message, accountInfo, rawResponse, err
			}

			// not API error
			return apiCode, "", accountInfo, rawResponse, err
		}

		if sessionNewSuccessResp == nil {
			return apiCode, "", accountInfo, rawResponse, fmt.Errorf("unexpected error when creating a new session")
		}

		//the /user/login API does not return the KEM ciphers yet
		// if kemHelper != nil {
		// 	if len(sessionNewSuccessResp.WireGuard.KemCipher_Kyber1024) == 0 && len(sessionNewSuccessResp.WireGuard.KemCipher_ClassicMcEliece348864) == 0 {
		// 		log.Warning("The server did not respond with KEM ciphers. The WireGuard PresharedKey has not been initialized!")
		// 	} else {
		// 		if err := kemHelper.SetCipher(kem.AlgName_Kyber1024, sessionNewSuccessResp.WireGuard.KemCipher_Kyber1024); err != nil {
		// 			log.Error(err)
		// 		}
		// 		if err := kemHelper.SetCipher(kem.AlgName_ClassicMcEliece348864, sessionNewSuccessResp.WireGuard.KemCipher_ClassicMcEliece348864); err != nil {
		// 			log.Error(err)
		// 		}

		// 		wgPresharedKey, err = kemHelper.CalculatePresharedKey()
		// 		if err != nil {
		// 			log.Error(fmt.Sprintf("Failed to decode KEM ciphers! (%s). Retry Log-in without WireGuard PresharedKey...", err))
		// 			kemHelper = nil
		// 			kemKeys = api_types.KemPublicKeys{}
		// 			if err := s.SessionDelete(true); err != nil {
		// 				log.Error("Creating new session (retry 2) -> Failed to delete active session: ", err)
		// 			}
		// 			continue
		// 		}
		// 	}
		// }
		break
	}

	if stableDeviceID { // generate the stable (anonymized) device ID, and device name based on it
		if deviceID, err = helpers.StableMachineID(); err != nil {
			return 0, "", accountInfo, rawResponse, fmt.Errorf("failed to generate stable machine ID: %w", err)
		}
	} else { // generate a random device ID
		// Max random value, a 80-bits integer, i.e 2^80 - 1
		max := new(big.Int)
		max.Exp(big.NewInt(2), big.NewInt(80), nil).Sub(max, big.NewInt(1))

		// Generate a cryptographically strong pseudo-random between 0 - max
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return 0, "", accountInfo, rawResponse, fmt.Errorf("failed to generate random machine ID: %w", err)
		}

		// String representation of n in base 16
		deviceID = n.Text(16)
	}
	if deviceName == "" { // if no device name specified, use an auto-generated one
		deviceName = "PL Connect - " + deviceID[:8]
	}

	// now do the Connect Device API call
	connectDevSuccessResp, apiErr, rawResponse, err = s._api.ConnectDevice(deviceID, deviceName, publicKey, sessionNewSuccessResp.Data.Token)

	apiCode = 0
	if apiErr != nil {
		apiCode = apiErr.HttpStatusCode
	}

	if err != nil {
		// in case of other API error
		if apiErr != nil {
			return apiCode, apiErr.Message, accountInfo, rawResponse, err
		}
		log.Error("rawResponse: " + rawResponse)

		// not API error
		return apiCode, "", accountInfo, rawResponse, err
	}

	if connectDevSuccessResp == nil {
		return apiCode, "", accountInfo, rawResponse, fmt.Errorf("unexpected error when registering a device")
	}

	localIP := strings.Split(connectDevSuccessResp.Data[0].Interface.Address, "/")[0]
	if strings.HasSuffix(localIP, ".0") || strings.HasSuffix(localIP, ".0.1") {
		s.SessionDelete(true, true, true) // logout
		return 0, "", preferences.AccountStatus{}, "", log.ErrorFE("Error - got assigned an invalid IP address '%s' when registering a device. Please try "+
			"logging in again later. Please email support@privateline.io about this problem.", localIP)
	}

	// get account status info
	// accountInfo = s.createAccountStatus(sessionNewSuccessResp.ServiceStatus)

	// we must not save the account password to settings.json on disk
	s.setCredentials(accountInfo,
		emailOrAcctID,
		sessionNewSuccessResp.Data.Token,
		deviceName,
		emailOrAcctID,
		"",
		publicKey,
		privateKey,
		localIP,
		0,
		wgPresharedKey,
		deviceID)

	endpointPortStr := strings.Split(connectDevSuccessResp.Data[1].Peer.Endpoint, ":")[1]
	endpointPort, err := strconv.Atoi(endpointPortStr)
	if err != nil {
		log.Error(fmt.Sprintf("Error parsing endpoint port '%s' as number: %v", endpointPortStr, err))
		return apiCode, "", accountInfo, "", err
	}
	hostValue := api_types.WireGuardServerHostInfo{
		HostInfoBase: api_types.HostInfoBase{
			EndpointIP:   strings.Split(connectDevSuccessResp.Data[1].Peer.Endpoint, ":")[0],
			EndpointPort: endpointPort,
		},
		LocalIP:    localIP,
		PublicKey:  connectDevSuccessResp.Data[1].Peer.PublicKey,
		DnsServers: connectDevSuccessResp.Data[0].Interface.DNS,
		AllowedIPs: connectDevSuccessResp.Data[1].Peer.AllowedIPs,
	}

	// propagate the Wireguard device configuration we received to Preferencese
	prefs := s._preferences

	prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts = []api_types.WireGuardServerHostInfo{hostValue}
	prefs.LastConnectionParams.WireGuardParameters.Port.Port = endpointPort

	if runtime.GOOS == "linux" { // Manual DNS setting still needed on Linux. Cannot pass "DNS = ..." in wg.conf, because of https://bugs.launchpad.net/ubuntu/+source/wireguard/+bug/1992491
		var dnsServers []net.IP
		for _, dnsSrvString := range strings.Split(hostValue.DnsServers, ",") {
			dnsServers = append(dnsServers, net.ParseIP(strings.TrimSpace(dnsSrvString)))
		}
		prefs.LastConnectionParams.ManualDNS = dns.DnsSettings{DnsServers: dnsServers}
	} else { // Windows works fine with "DNS = ..." in wgprivateline.conf
		// if err = dns.DeleteManual(nil, nil); err != nil {
		// 	log.Error(fmt.Errorf("error dns.DeleteManual(): %w", err))
		// }
		prefs.LastConnectionParams.ManualDNS = dns.DnsSettings{}
	}

	log.Info(fmt.Sprintf("(logging in) WG keys updated (%s:%s; psk:%v)", localIP, publicKey, len(wgPresharedKey) > 0))

	// init to Total Shield off by default
	prefs.IsTotalShieldOn = false
	// // and allow all apps into enclave by default
	// prefs.EnableAppWhitelist = false

	// propagate our prefs changes to Preferences and to settings.json
	s.setPreferences(prefs)

	log.Info(fmt.Sprintf("(logging in) WG keys updated (%s:%s; psk:%v)", localIP, publicKey, len(wgPresharedKey) > 0))

	// Apply SplitTunnel configuration. It is applicable for Inverse mode of SplitTunnel
	if err := s.splitTunnelling_ApplyConfig(true); err != nil {
		log.Error(fmt.Errorf("splitTunnelling_ApplyConfig failed: %v", err))
		return apiCode, "", accountInfo, "", err
	}

	return apiCode, "", accountInfo, rawResponse, nil
}

// TODO FIXME: Vlad - merge with SessionNew() into a single login pipeline, there's a lot of shared code that was copy-pasted
func (s *Service) SsoLogin(code string, sessionCode string, disableFirewallOnExit, disableFirewallOnErrorOnly bool) (
	apiCode int,
	apiErrorMsg string,
	rawResponse *api_types.SsoLoginResponse,
	err error) {

	if disableFirewallOnExit || disableFirewallOnErrorOnly {
		defer func() {
			if disableFirewallOnExit || (disableFirewallOnErrorOnly && err != nil) {
				s.SetKillSwitchState(false)
			}
		}()
	}

	// 	try to enable the firewall, need VPN coexistence logic up - otherwise our API calls may not go through
	if err := firewall.EnableIfNeeded(); err != nil {
		return 0, "", nil, log.ErrorFE("error in firewall.EnableIfNeeded: %w", err)
	}
	// TODO: Vlad - disabling old IVPN logic that deals with API servers as exceptions
	// // Temporary allow API server access (If Firewall is enabled)
	// // Otherwise, there will not be any possibility to Login (because all connectivity is blocked)
	// fwStatus, _ := s.KillSwitchState()
	// if fwStatus.IsEnabled && !fwStatus.IsAllowApiServers {
	// 	s.SetKillSwitchAllowAPIServers(true)
	// }
	// defer func() {
	// 	if fwStatus.IsEnabled && !fwStatus.IsAllowApiServers {
	// 		// restore state for 'AllowAPIServers' configuration (previously, was enabled)
	// 		s.SetKillSwitchAllowAPIServers(false)
	// 	}
	// }()

	// delete current session (if exists)
	if helpers.IsAValidAccountID(s.Preferences().Session.AccountID) { // if we have stored an account ID - try to logout
		isCanDeleteSessionLocally := true
		if err := s.SessionDelete(isCanDeleteSessionLocally, true, false); err != nil {
			log.Error("Creating new session -> Failed to delete active session: ", err)
		}
	}

	defer func() {
		if err != nil {
			log.Debug("sso error ----> ", err, "sso error code -----> ", apiCode)
			var customMessage string
			switch apiCode {
			case 426:
				customMessage = fmt.Sprintf("We are sorry - we are unable to add an additional device to your account, because you already registered a maximum of N devices possible under your current subscription. You can go to your device list on our website (https://account.privateline.io/pl-connect/page/1) and unregister some of your existing devices from your account, or you can upgrade your subscription at https://privateline.io/order in order to be able to use more devices. %s", err)
			case 412:
				customMessage = fmt.Sprintf("We are sorry - your free account only allows to use one device. You can upgrade your subscription at https://privateline.io/order in order to be able to use more devices. %s", err)
			default:
				customMessage = fmt.Sprintf("Logging in - FAILED: %s", err)
			}

			log.Warning(customMessage)
			log.Error("Logging in - FAILED: ", err)
		} else {
			log.Info("Logging in - SUCCESS")
		}
	}()

	var (
		publicKey  string
		privateKey string

		wgPresharedKey        string
		apiErr                *api_types.APIErrorResponse
		connectDevSuccessResp *api_types.ConnectDeviceResponse

		deviceID string
	)

	for {
		// generate new keys for WireGuard
		publicKey, privateKey, err = wireguard.GenerateKeys(platform.WgToolBinaryPath())
		if err != nil {
			log.Warning(fmt.Sprintf("Failed to generate wireguard keys for new session: %s", err.Error()))
		}

		rawResponse, err = s._api.SsoLogin(code, sessionCode)

		apiCode = 0
		if err != nil {
			return 400, "", rawResponse, err
		}

		break
	}

	// generate a random device ID
	// Max random value, a 80-bits integer, i.e 2^80 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(80), nil).Sub(max, big.NewInt(1))

	// Generate a cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, "", rawResponse, fmt.Errorf("failed to generate random machine ID: %w", err)
	}

	// String representation of n in base 16
	deviceID = n.Text(16)
	deviceName := "PL Connect - " + deviceID[:8]

	logger.Debug(deviceID, deviceName)

	// now do the Connect Device API call
	connectRawresponse := ""
	connectDevSuccessResp, apiErr, connectRawresponse, err = s._api.ConnectDevice(deviceID, deviceName, publicKey, rawResponse.AccessToken)
	logger.Debug("connectRawresponse ---> ", connectRawresponse)

	apiCode = 0
	if apiErr != nil {
		apiCode = apiErr.HttpStatusCode
	}

	if err != nil {
		// in case of other API error
		if apiErr != nil {
			return apiCode, apiErr.Message, rawResponse, err
		}
		// not API error
		return apiCode, "", rawResponse, err
	}

	if connectDevSuccessResp == nil {
		return apiCode, "", rawResponse, fmt.Errorf("unexpected error when registering a device")
	}

	localIP := strings.Split(connectDevSuccessResp.Data[0].Interface.Address, "/")[0]
	if strings.HasSuffix(localIP, ".0.0") || strings.HasSuffix(localIP, ".0.1") {
		s.SessionDelete(true, true, true) // logout
		return 0, "", nil, log.ErrorFE("Error - got assigned an invalid IP address '%s' when registering a device. Please try "+
			"logging in again later. Please email support@privateline.io about this problem.", localIP)
	}

	// get account status info
	// accountInfo = s.createAccountStatus(sessionNewSuccessResp.ServiceStatus)

	// we must not save the account password to settings.json on disk
	accountInfo := preferences.AccountStatus{}
	s.setCredentials(
		accountInfo,
		code,
		rawResponse.AccessToken,
		deviceName,
		code,
		"",
		publicKey,
		privateKey,
		localIP,
		0,
		wgPresharedKey,
		deviceID)

	endpointPortStr := strings.Split(connectDevSuccessResp.Data[1].Peer.Endpoint, ":")[1]
	endpointPort, err := strconv.Atoi(endpointPortStr)
	if err != nil {
		log.Error(fmt.Sprintf("Error parsing endpoint port '%s' as number: %v", endpointPortStr, err))
		return apiCode, "", rawResponse, err
	}
	hostValue := api_types.WireGuardServerHostInfo{
		HostInfoBase: api_types.HostInfoBase{
			EndpointIP:   strings.Split(connectDevSuccessResp.Data[1].Peer.Endpoint, ":")[0],
			EndpointPort: endpointPort,
		},
		LocalIP:    localIP,
		PublicKey:  connectDevSuccessResp.Data[1].Peer.PublicKey,
		DnsServers: connectDevSuccessResp.Data[0].Interface.DNS,
		AllowedIPs: connectDevSuccessResp.Data[1].Peer.AllowedIPs,
	}

	// propagate the Wireguard device configuration we received to Preferences
	prefs := s._preferences

	prefs.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts = []api_types.WireGuardServerHostInfo{hostValue}
	prefs.LastConnectionParams.WireGuardParameters.Port.Port = endpointPort

	if runtime.GOOS == "linux" { // Manual DNS setting still needed on Linux. Cannot pass "DNS = ..." in wg.conf, because of https://bugs.launchpad.net/ubuntu/+source/wireguard/+bug/1992491
		var dnsServers []net.IP
		for _, dnsSrvString := range strings.Split(hostValue.DnsServers, ",") {
			dnsServers = append(dnsServers, net.ParseIP(strings.TrimSpace(dnsSrvString)))
		}
		prefs.LastConnectionParams.ManualDNS = dns.DnsSettings{DnsServers: dnsServers}
	} else { // Windows works fine with "DNS = ..." in wgprivateline.conf
		// if err = dns.DeleteManual(nil, nil); err != nil {
		// 	log.Error(fmt.Errorf("error dns.DeleteManual(): %w", err))
		// }
		prefs.LastConnectionParams.ManualDNS = dns.DnsSettings{}
	}

	log.Info(fmt.Sprintf("(logging in) WG keys updated (%s:%s; psk:%v)", localIP, publicKey, len(wgPresharedKey) > 0))

	// init to Total Shield off by default
	prefs.IsTotalShieldOn = false

	// propagate our prefs changes to Preferences and to settings.json
	s.setPreferences(prefs)

	log.Info(fmt.Sprintf("(logging in) WG keys updated (%s:%s; psk:%v)", localIP, publicKey, len(wgPresharedKey) > 0))

	// Apply SplitTunnel configuration. It is applicable for Inverse mode of SplitTunnel
	if err := s.splitTunnelling_ApplyConfig(true); err != nil {
		log.Error(fmt.Errorf("splitTunnelling_ApplyConfig failed: %v", err))
		return apiCode, "", rawResponse, err
	}

	return apiCode, "", rawResponse, nil
}

// @@@@@@@  END ==============================================================================================================

func (s *Service) MigrateSsoUser() (
	apiCode int,
	resp *api_types.MigrateSsoUserResponse,
	err error) {

	prefs := s.Preferences()

	// must be logged in
	session := prefs.Session
	if !session.IsLoggedIn() {
		log.Error("we're not logged in yet, so not doing SSO user migration")
		return apiCode, nil, srverrors.ErrorNotLoggedIn{}
	}

	if resp, apiCode, err = s._api.MigrateSsoUser(prefs.Session.Session); err != nil {
		return apiCode, nil, err
	} else if !resp.Status {
		return 0, nil, log.ErrorFE("error - migrateSsoUser request failed. Message: '%s'", resp.Message)
	} else if !helpers.IsAValidAccountID(resp.Data.Username) {
		return 0, nil, log.ErrorFE("error - returned account ID '%s' does not match the expected account ID format", resp.Data.Username)
	}

	prefs.Session.AccountID = resp.Data.Username  // success
	if prefs.Session.Session != resp.Data.Token { // if the backend REST API returned a different session token (expected), then update it in prefs
		// log.Debug(fmt.Sprintf("warning - session arg '%s' != returned resp.Data.Token '%s'", prefs.Session.Session, resp.Data.Token))
		prefs.Session.Session = resp.Data.Token
	}
	s.setPreferences(prefs)

	return apiCode, resp, err
}

func (s *Service) AccountInfo() (
	apiCode int,
	apiErrorMsg string,
	accountStatus preferences.AccountStatus,
	rawResponse string,
	err error) {
	// TODO FIXME: Swapnil, Vlad: this function is a stub for now
	log.Debug("================================ AccountInfo function Reached ================================")
	return 200, "", s.Preferences().Account, "FIXME stub", nil
}

func (s *Service) ProfileData() (
	apiCode int,
	response *api_types.ProfileDataResponse,
	err error) {
	var (
		profileDataResponse *api_types.ProfileDataResponse
	)
	// Not querying Profile Data if we're not logged in yet
	session := s.Preferences().Session
	if !session.IsLoggedIn() {
		log.Error("we're not logged in yet, so not querying Profile Data (/user/profile API)")
		return apiCode, nil, srverrors.ErrorNotLoggedIn{}
	}

	profileDataResponse, apiCode, err = s._api.ProfileData(s.Preferences().Session.Session)
	return apiCode, profileDataResponse, err
}

func (s *Service) DeviceList(Search string, Page int, Limit int, DeleteId int) (
	apiCode int,
	response *api_types.DeviceListResponse,
	err error) {
	var (
		deviceListResponse *api_types.DeviceListResponse
	)
	// Not querying Device List if we're not logged in yet
	session := s.Preferences().Session
	if !session.IsLoggedIn() {
		log.Error("we're not logged in yet, so not querying Device List (/user/devices API)")
		return apiCode, nil, srverrors.ErrorNotLoggedIn{}
	}

	deviceListResponse, err = s._api.DeviceList(s.Preferences().Session.Session, Search, Page, Limit, DeleteId)
	return apiCode, deviceListResponse, err
}

func (s *Service) SubscriptionData() (
	apiCode int,
	response *api_types.SubscriptionDataResponse,
	err error) {
	var (
		subscriptionDataResponse *api_types.SubscriptionDataResponse
	)
	// Not querying Subscription Data if we're not logged in yet
	session := s.Preferences().Session
	if !session.IsLoggedIn() {
		log.Error("we're not logged in yet, so not querying Subscription Data (/user/check-subscription API)")
		return apiCode, nil, srverrors.ErrorNotLoggedIn{}
	}

	if subscriptionDataResponse, apiCode, err = s._api.SubscriptionData(s.Preferences().Session.Session); err == nil {
		s._preferences.PlanName = subscriptionDataResponse.Plan.Name // save subscription plan name
	}
	return apiCode, subscriptionDataResponse, err
}

// SessionDelete removes session info and
func (s *Service) SessionDelete(isCanDeleteSessionLocally, notifyClientsOnSessionChange, disableFirewallOnExit bool) error {
	return s.logOut(true, isCanDeleteSessionLocally, notifyClientsOnSessionChange, disableFirewallOnExit) // send sessionNeedToDeleteOnBackend=true
}

// logOut performs log out from current session
// 1) if 'sessionNeedToDeleteOnBackend' == false: the app not trying to make API request
//	  the session info just erasing locally
//    (this is useful for the situations when we already know that session is not available on backend anymore)
// 2) if 'sessionNeedToDeleteOnBackend' == true (and 'isCanDeleteSessionLocally' == false): app is trying to make API request to logout correctly
//	  in case if API request failed the function returns error (session keeps not logged out)
// 3) if 'isCanDeleteSessionLocally' == true (and 'sessionNeedToDeleteOnBackend' == true): app is trying to make API request to logout correctly
//	  in case if API request failed we just erasing session info locally (no errors returned)

func (s *Service) logOut(sessionNeedToDeleteOnBackend, isCanDeleteSessionLocally, notifyClientsOnSessionChange, disableFirewallOnExit bool) (retErr error) {
	// Stop service:
	// - disconnect VPN (if connected)
	// - disable Split Tunnel mode
	// - etc. ...
	if err := s.unInitialise(true); err != nil {
		log.Error(err)
	}

	defer func() {
		if disableFirewallOnExit { // conditionally disable firewall on exit
			if err := firewall.SetEnabled(false); err != nil {
				retErr = log.ErrorFE("error disabling firewall in logOut: %w", err)
			}
		}
		s._evtReceiver.OnSplitTunnelStatusChanged()
	}()

	// stop session checker (use goroutine to avoid deadlocks)
	go s.stopSessionChecker()

	// stop WG keys rotation
	s._wgKeysMgr.StopKeysRotation()

	if sessionNeedToDeleteOnBackend {
		// 	try to enable the firewall, need VPN coexistence logic up - otherwise our API calls may not go through
		if err := firewall.EnableIfNeeded(); err != nil {
			log.ErrorFE("error in firewall.EnableIfNeeded: %w", err)
		}
		// TODO: Vlad - disabling old IVPN logic that deals with API servers as exceptions
		// Temporary allow API server access (If Firewall is enabled)
		// Otherwise, there will not be any possibility to Login (because all connectivity is blocked)
		// if fwStatus.IsEnabled && !fwStatus.IsAllowApiServers {
		// 	s.SetKillSwitchAllowAPIServers(true)
		// }
		// defer func() {
		// 	if fwStatus.IsEnabled && !fwStatus.IsAllowApiServers {
		// 		// restore state for 'AllowAPIServers' configuration (previously, was enabled)
		// 		s.SetKillSwitchAllowAPIServers(false)
		// 	}
		// }()

		session := s.Preferences().Session
		if session.IsLoggedIn() {
			log.Info("Logging out")
			err := s._api.SessionDelete(session.Session, s.Preferences().Session.WGPublicKey)
			if err != nil {
				log.Info(fmt.Errorf("error logging out: %w", err))
				if !isCanDeleteSessionLocally {
					return err // do not allow to logout if failed to delete session on backend
				}
			} else {
				log.Info("Logging out: done")
			}
		}
	}

	s._preferences.SetSession(preferences.AccountStatus{}, "", "", "", "", "", "", "", "", "", "")
	log.Info("Logged out locally")

	// notify clients about session update
	if notifyClientsOnSessionChange {
		s._evtReceiver.OnServiceSessionChanged()
	}

	return nil
}

func (s *Service) OnSessionNotFound() {
	// Logging out now
	log.Info("Session not found. Logging out.")
	needToDeleteOnBackend := false
	canLogoutOnlyLocally := true
	notifyClientsOnSessionChange := true
	disableFirewallOnExit := true
	s.logOut(needToDeleteOnBackend, canLogoutOnlyLocally, notifyClientsOnSessionChange, disableFirewallOnExit)
}

func (s *Service) OnSessionStatus(sessionToken string, sessionData preferences.SessionMutableData) {
	// save last known info about account status
	s._preferences.UpdateSessionData(sessionData)
	// notify about account status
	s._evtReceiver.OnSessionStatus(sessionToken, sessionData)
}

func (s *Service) CheckBackendConnectivity() (success bool, err error) {
	// Enable one of implementations

	// log.Debug("s.Preferences().HealthchecksType = ", s.Preferences().HealthchecksType)

	switch s.Preferences().HealthchecksType {
	case types.HealthchecksType_Ping: // Healthchecks implementation via pinging API backend servers
		return s.PingInternalApiHosts()
	case types.HealthchecksType_RestApiCall: // Healthchecks implementation using REST API calls
		return s._api.PublicGetPlans()
	default:
		return true, nil
	}
}

// RequestSessionStatus receives session status
func (s *Service) RequestSessionStatus() (
	apiCode int,
	apiErrorMsg string,
	sessionToken string,
	sessionStatus preferences.SessionMutableData,
	err error) {

	session := s.Preferences().Session
	if !session.IsLoggedIn() {
		return apiCode, "", "", sessionStatus, srverrors.ErrorNotLoggedIn{}
	}

	// TODO: Vlad - disabling /session/status API calls
	return 0, "/session/status request skipped", "", sessionStatus, fmt.Errorf("/session/status request skipped")

	// if no connectivity - skip request (and activate _isWaitingToUpdateAccInfoChan)
	if err := s.IsConnectivityBlocked(); err != nil {
		s._isNeedToUpdateSessionInfo = true
		return apiCode, "", "", sessionStatus, fmt.Errorf("session status request skipped (%w)", err)
	}
	// defer: ensure s._isWaitingToUpdateAccInfoChan is empty
	defer func() {
		s._isNeedToUpdateSessionInfo = false
	}()

	log.Info("Requesting session status...")
	stat, apiErr, err := s._api.SessionStatus(session.Session)
	log.Info("Session status request: done")

	currSession := s.Preferences().Session
	if currSession.Session != session.Session {
		// It could happen that logout\login was performed during the session check
		// Ignoring result if there is already a new session
		log.Info("Ignoring requested session status result. Local session already changed.")
		return apiCode, "", "", sessionStatus, srverrors.ErrorNotLoggedIn{}
	}

	if stat != nil {
		sessionStatus.Account = s.createAccountStatus(stat.ServiceStatus)
		sessionStatus.DeviceName = stat.DeviceName
	}

	apiCode = 0
	if apiErr != nil {
		apiCode = apiErr.HttpStatusCode
		// Session not found - can happens when user forced to logout from another device
		if apiCode == api_types.SessionNotFound {
			s.OnSessionNotFound()
		}
		// save last account info AND notify clients that account not active
		if apiCode == api_types.AccountNotActive {
			sessionStatus.Account.Active = false
			s.OnSessionStatus(session.Session, sessionStatus)
			return apiCode, apiErr.Message, session.Session, sessionStatus, err
		}
	}

	if err != nil {
		if apiErr != nil {
			return apiCode, apiErr.Message, "", sessionStatus, err
		}
		return apiCode, "", "", sessionStatus, err
	}

	if stat == nil {
		return apiCode, "", "", sessionStatus, fmt.Errorf("unexpected error when creating requesting session status")
	}

	// save last account info AND notify about account status
	s.OnSessionStatus(session.Session, sessionStatus)
	return apiCode, "", session.Session, sessionStatus, nil
}

func (s *Service) createAccountStatus(apiResp api_types.ServiceStatusAPIResp) preferences.AccountStatus {
	return preferences.AccountStatus{
		Active:              apiResp.Active,
		ActiveUntil:         apiResp.ActiveUntil,
		CurrentPlan:         apiResp.CurrentPlan,
		PaymentMethod:       apiResp.PaymentMethod,
		IsRenewable:         apiResp.IsRenewable,
		WillAutoRebill:      apiResp.WillAutoRebill,
		IsFreeTrial:         apiResp.IsFreeTrial,
		Capabilities:        apiResp.Capabilities,
		Upgradable:          apiResp.Upgradable,
		UpgradeToPlan:       apiResp.UpgradeToPlan,
		UpgradeToURL:        apiResp.UpgradeToURL,
		DeviceManagement:    apiResp.DeviceManagement,
		DeviceManagementURL: apiResp.DeviceManagementURL,
		DeviceLimit:         apiResp.DeviceLimit}
}

func (s *Service) startSessionChecker() {
	// ensure that session checker is not running
	s.stopSessionChecker()

	session := s.Preferences().Session
	if !session.IsLoggedIn() {
		return
	}

	s._sessionCheckerStopChn = make(chan struct{})
	go func() {
		log.Info("Session checker started")
		defer log.Info("Session checker stopped")

		stopChn := s._sessionCheckerStopChn
		for {
			// check status
			s.RequestSessionStatus()

			// if not logged-in - no sense to check status anymore
			session := s.Preferences().Session
			if !session.IsLoggedIn() {
				return
			}

			// wait for timeout or stop request
			select {
			case <-stopChn:
				return
			case <-time.After(SessionCheckInterval):
			}
		}
	}()
}

func (s *Service) stopSessionChecker() {
	stopChan := s._sessionCheckerStopChn
	s._sessionCheckerStopChn = nil
	if stopChan != nil {
		stopChan <- struct{}{}
	}
}

//////////////////////////////////////////////////////////
// WireGuard keys
//////////////////////////////////////////////////////////

// WireGuardSaveNewKeys saves WG keys
func (s *Service) WireGuardSaveNewKeys(wgPublicKey string, wgPrivateKey string, wgLocalIP string, wgPresharedKey string) {
	s._preferences.UpdateWgCredentials(wgPublicKey, wgPrivateKey, wgLocalIP, wgPresharedKey)

	// notify clients about session (wg keys) update
	s._evtReceiver.OnServiceSessionChanged()

	go func() {
		// reconnect in separate routine (do not block current thread)
		vpnObj := s._vpn
		if vpnObj == nil {
			return
		}
		if vpnObj.Type() != vpn.WireGuard {
			return
		}
		if !s.ConnectedOrConnecting() || (s.ConnectedOrConnecting() && s.IsPaused()) {
			// IMPORTANT! : WireGuard 'pause/resume' state is based on complete VPN disconnection and connection back (on all platforms)
			// If this will be changed (e.g. just changing routing) - it will be necessary to implement reconnection even in 'pause' state
			return
		}
		log.Info("Reconnecting WireGuard connection with new credentials...")
		s.reconnect()
	}()
}

// WireGuardSetKeysRotationInterval change WG key rotation interval
func (s *Service) WireGuardSetKeysRotationInterval(interval int64) {
	// TODO FIXME: Vlad - for now effectively disable updating Wireguard keys, key rotation
	// Set it to 100 years
	interval = 100 * 365 * 86400

	s._preferences.Session.WGKeysRegenInerval = time.Second * time.Duration(interval)
	s._preferences.SavePreferences()

	// restart WG keys rotation
	if err := s._wgKeysMgr.StartKeysRotation(); err != nil {
		log.Error(err)
	}

	// notify clients about session (wg keys) update
	s._evtReceiver.OnServiceSessionChanged()
}

// WireGuardGetKeys get WG keys
func (s *Service) WireGuardGetKeys() (session, wgPublicKey, wgPrivateKey, wgLocalIP string, generatedTime time.Time, updateInterval time.Duration) {
	p := s._preferences

	return p.Session.Session,
		p.Session.WGPublicKey,
		p.Session.WGPrivateKey,
		p.Session.WGLocalIP,
		p.Session.WGKeyGenerated,
		p.Session.WGKeysRegenInerval
}

// WireGuardGenerateKeys - generate new wireguard keys
func (s *Service) WireGuardGenerateKeys(updateIfNecessary bool) error {
	if !s._preferences.Session.IsLoggedIn() {
		return srverrors.ErrorNotLoggedIn{}
	}

	// Update WG keys, if necessary
	var err error
	if updateIfNecessary {
		err = s._wgKeysMgr.UpdateKeysIfNecessary()
	} else {
		err = s._wgKeysMgr.GenerateKeys()
	}
	if err != nil {
		return fmt.Errorf("failed to regenerate WireGuard keys: %w", err)
	}

	return nil
}

// ////////////////////////////////////////////////////////
// Diagnostic
// ////////////////////////////////////////////////////////
func (s *Service) GetDiagnosticLogs() (logActive string, logPrevSession string, extraInfo string, err error) {
	log, log0, err := logger.GetLogText(1024 * 64)
	if err != nil {
		return "", "", "", err
	}

	extraInfo, err1 := s.implGetDiagnosticExtraInfo()
	if err1 != nil {
		extraInfo = fmt.Sprintf("<failed to obtain extra info> : %s : %s", err1.Error(), extraInfo)
	}

	return log, log0, extraInfo, nil
}

func (s *Service) diagnosticGetCommandOutput(command string, args ...string) string {
	outText, outErrText, _, isBufferTooSmall, err := shell.ExecAndGetOutput(nil, 1024*30, "", command, args...)
	ret := fmt.Sprintf("[ $ %s %v ]:\n%s", command, args, outText)
	if isBufferTooSmall {
		ret += "... (buffer too small)"
	}
	if len(outErrText) > 0 {
		ret += "\n [ERROR CHANNEL OUTPUT]: " + outErrText
	}
	if err != nil {
		ret += "\n [ERROR]: " + err.Error()
	}
	return ret
}

func (s *Service) SetStatsCallbacks(callbacks protocol.StatsCallbacks) {
	s._statsCallbacks = callbacks
}

func (s *Service) GetStatsCallbacks() protocol.StatsCallbacks {
	return s._statsCallbacks
}

//////////////////////////////////////////////////////////
// Internal methods
//////////////////////////////////////////////////////////

func (s *Service) setPreferences(p preferences.Preferences) {
	if !reflect.DeepEqual(s._preferences, p) {
		//if s._preferences != p {
		s._preferences = p
		s._preferences.SavePreferences()
	}
}

func (s *Service) listAllServiceBackgroundMonitors() (allBackgroundMonitors []*srvhelpers.ServiceBackgroundMonitor) {
	allBackgroundMonitors = firewall.GetFirewallBackgroundMonitors()
	allBackgroundMonitors = append(allBackgroundMonitors, s.connectivityHealthchecksBackgroundMonitorDef)
	return allBackgroundMonitors
}
