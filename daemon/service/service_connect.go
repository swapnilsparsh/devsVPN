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
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	api_types "github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/obfsproxy"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol"
	"github.com/swapnilsparsh/devsVPN/daemon/service/dns"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform/filerights"
	"github.com/swapnilsparsh/devsVPN/daemon/service/srverrors"
	"github.com/swapnilsparsh/devsVPN/daemon/service/srvhelpers"
	"github.com/swapnilsparsh/devsVPN/daemon/service/types"
	"github.com/swapnilsparsh/devsVPN/daemon/v2r"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn/openvpn"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn/wireguard"
)

type svrConnInfo struct {
	IP             net.IP
	Port           int
	PortType       int // UDP(0), TCP(1)
	V2RayProxyType v2r.V2RayTransportType
}

func (s *Service) ValidateConnectionParameters(params types.ConnectionParams, isCanFix bool) (types.ConnectionParams, error) {
	if params.VpnType == vpn.WireGuard {
		// WireGuard connection parameters
		if len(params.WireGuardParameters.EntryVpnServer.Hosts) <= 0 {
			return params, fmt.Errorf("no hosts defined for WireGuard connection")
		}
		if len(params.WireGuardParameters.MultihopExitServer.Hosts) > 0 {
			if mhErr := s.IsCanConnectMultiHop(); mhErr != nil {
				if !isCanFix {
					return params, mhErr
				}
				log.Info("Multi-Hop connection is not allowed. Using Single-Hop.")
				params.WireGuardParameters.MultihopExitServer = types.MultiHopExitServer_WireGuard{}
			}
		}
	} else {
		// OpenVPN connection parameters
		if len(params.OpenVpnParameters.EntryVpnServer.Hosts) <= 0 {
			return params, fmt.Errorf("no hosts defined for OpenVPN connection")
		}
		if len(params.OpenVpnParameters.MultihopExitServer.Hosts) > 0 {
			if mhErr := s.IsCanConnectMultiHop(); mhErr != nil {
				if !isCanFix {
					return params, mhErr
				}
				log.Info("Multi-Hop connection is not allowed. Using Single-Hop.")
				params.OpenVpnParameters.MultihopExitServer = types.MultiHopExitServer_OpenVpn{}
			}
		}
	}
	return params, nil
}

func (s *Service) Connect(params types.ConnectionParams) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic on connect: " + fmt.Sprint(r))
			log.Error(err)
			log.Error(string(debug.Stack()))
		}
	}()

	// erase temporary connection parameters
	s._tmpParamsMutex.Lock()
	s._tmpParams = types.ConnectionParams{}
	s._tmpParamsMutex.Unlock()
	defer func() {
		s._tmpParamsMutex.Lock()
		defer s._tmpParamsMutex.Unlock()
		// update settings if we received any while VPN was connected
		if s._tmpParams.CheckIsDefined() == nil {
			s.setConnectionParams(s._tmpParams)
		}
	}()

	// keep last used connection params
	s.setConnectionParams(params)

	prefs := s.Preferences()
	canReconfigureOtherVpns := params.CanReconfigureOtherVpnsOnce || prefs.PermissionReconfigureOtherVPNs

	// if account not active (OR subscription expired) - request account status from backend
	if !prefs.Account.Active || time.Now().After(time.Unix(prefs.Account.ActiveUntil, 0)) {
		// update account info
		if _, _, _, _, err := s.RequestSessionStatus(); err == nil {
			// If account info update success: check actual account status
			// If account info update failed: do nothing and continue connecting
			if !prefs.Account.Active {
				if time.Now().After(time.Unix(prefs.Account.ActiveUntil, 0)) {
					return fmt.Errorf("your subscription has expired")
				}
				return fmt.Errorf("your subscription is not active")
			}

		}
	}

	// Normalize hosts list
	// - in case of multiple entry hosts - take one random host from the list
	// - in case of multiple exit hosts - take one random host from the list
	if err := params.NormalizeHosts(); err != nil {
		return fmt.Errorf("failed to normalize hosts: %w", err)
	}

	// ------------------------ Inverse Split Tunnel block start ------------------------
	// if prefs.IsInverseSplitTunneling() {
	// 	if params.FirewallOn || params.FirewallOnDuringConnection {
	// 		log.Info("The Firewall will not be enabled for the current connection because Split Tunnel Inverse mode is active")
	// 		params.FirewallOn = false
	// 		params.FirewallOnDuringConnection = false
	// 	}
	// }
	// ------------------------ Inverse Split Tunnel block end --------------------------

	// ------------------------ V2RAY block start ------------------------
	// 'originalEntryServerInfo' - will contain original info about EntryServer/Port (it is not 'nil' for V2Ray connections).
	//  We need this info to notify correct data about vpn.CONNECTED state: for V2Ray connection the original parameters are overwriten by local V2Ray proxy params ('127.0.0.1:local_port')
	var originalEntryServerInfo *svrConnInfo
	var v2RayWrapper *v2r.V2RayWrapper
	if params.V2Ray() == v2r.QUIC || params.V2Ray() == v2r.TCP {
		disabledFuncs := s.GetDisabledFunctions()
		if len(disabledFuncs.V2RayError) > 0 {
			return fmt.Errorf(disabledFuncs.V2RayError)
		}

		log.Info("Starting V2Ray...")
		// Note! the startV2Ray() modifies original params!
		params, v2RayWrapper, originalEntryServerInfo, err = s.startV2Ray(params, params.V2Ray())
		if err != nil {
			return fmt.Errorf("failed to start V2Ray: %w", err)
		}
		defer func() {
			if v2RayWrapper != nil {
				// stop V2Ray
				if err := v2RayWrapper.Stop(); err != nil {
					log.Error(fmt.Errorf("failed to stop V2Ray: %w", err))
				}
			}
		}()
	}
	// ------------------------ V2RAY block end ------------------------

	// Protocol-specific configurations
	if vpn.Type(params.VpnType) == vpn.OpenVPN {
		// PARAMETERS VALIDATION
		if len(params.OpenVpnParameters.EntryVpnServer.Hosts) < 1 {
			return fmt.Errorf("VPN host not defined")
		}

		// take first host from the list (if multiple hosts were defined, the random one was taken above)
		host := net.ParseIP(params.OpenVpnParameters.EntryVpnServer.Hosts[0].EndpointIP)

		// nothing from supported proxy types should be in this parameter
		proxyType := params.OpenVpnParameters.Proxy.Type
		if len(proxyType) > 0 && proxyType != "http" && proxyType != "socks" {
			proxyType = ""
		}

		// Multi-Hop
		var exitHostValue *api_types.OpenVPNServerHostInfo
		if len(params.OpenVpnParameters.MultihopExitServer.Hosts) > 0 {
			exitHostValue = &params.OpenVpnParameters.MultihopExitServer.Hosts[0]
		}

		// only one-line parameter is allowed
		proxyUsername := strings.Split(params.OpenVpnParameters.Proxy.Username, "\n")[0]
		proxyPassword := strings.Split(params.OpenVpnParameters.Proxy.Password, "\n")[0]

		// CONNECTION
		// OpenVPN connection parameters
		var connectionParams openvpn.ConnectionParams
		if exitHostValue != nil {
			// Check is it allowed to connect multihop
			if mhErr := s.IsCanConnectMultiHop(); mhErr != nil {
				return mhErr
			}

			// Multi-Hop
			connectionParams = openvpn.CreateConnectionParams(
				exitHostValue.Hostname,
				params.OpenVpnParameters.Port.Protocol > 0, // is TCP
				exitHostValue.EndpointPort,
				host,
				proxyType,
				net.ParseIP(params.OpenVpnParameters.Proxy.Address),
				params.OpenVpnParameters.Proxy.Port,
				proxyUsername,
				proxyPassword)
		} else {
			// Single-Hop
			connectionParams = openvpn.CreateConnectionParams(
				"",
				params.OpenVpnParameters.Port.Protocol > 0, // is TCP
				params.OpenVpnParameters.Port.Port,
				host,
				proxyType,
				net.ParseIP(params.OpenVpnParameters.Proxy.Address),
				params.OpenVpnParameters.Proxy.Port,
				proxyUsername,
				proxyPassword)
		}

		if v2RayWrapper != nil {
			// if V2Ray enabled - ignore obfsproxy option
			params.OpenVpnParameters.Obfs4proxy = obfsproxy.Config{}
		}

		return s.connectOpenVPN(originalEntryServerInfo, connectionParams, params.ManualDNS, params.Metadata.AntiTracker, params.FirewallOn, params.FirewallOnDuringConnection, params.OpenVpnParameters.Obfs4proxy, v2RayWrapper, canReconfigureOtherVpns)

	} else if vpn.Type(params.VpnType) == vpn.WireGuard {
		if len(params.WireGuardParameters.EntryVpnServer.Hosts) < 1 {
			return fmt.Errorf("VPN host not defined")
		}

		// take first host from the list (if multiple hosts were defined, the random one was taken above)
		hostValue := params.WireGuardParameters.EntryVpnServer.Hosts[0]

		// Multi-Hop
		var exitHostValue *api_types.WireGuardServerHostInfo
		if len(params.WireGuardParameters.MultihopExitServer.Hosts) > 0 {
			exitHostValue = &params.WireGuardParameters.MultihopExitServer.Hosts[0]
		}

		// prevent user-defined data injection: ensure that nothing except the base64 public key will be stored in the configuration
		if !helpers.ValidateBase64(hostValue.PublicKey) {
			return fmt.Errorf("WG public key is not base64 string")
		}

		hostLocalIP := net.ParseIP(strings.Split(hostValue.LocalIP, "/")[0])
		ipv6Prefix := ""
		if params.IPv6 {
			ipv6Prefix = strings.Split(hostValue.IPv6.LocalIP, "/")[0]
		}

		var connectionParams wireguard.ConnectionParams
		if exitHostValue != nil {
			// Check is it allowed to connect multihop
			if mhErr := s.IsCanConnectMultiHop(); mhErr != nil {
				return mhErr
			}

			// Multi-Hop
			connectionParams = wireguard.CreateConnectionParams(
				exitHostValue.Hostname,
				exitHostValue.EndpointPort,
				net.ParseIP(hostValue.EndpointIP),
				exitHostValue.PublicKey,
				hostLocalIP,
				ipv6Prefix,
				params.WireGuardParameters.Mtu,
				exitHostValue.DnsServers,
				exitHostValue.AllowedIPs,
			)
		} else {
			// Single-Hop
			connectionParams = wireguard.CreateConnectionParams(
				"",
				hostValue.EndpointPort,
				net.ParseIP(hostValue.EndpointIP),
				hostValue.PublicKey,
				hostLocalIP,
				ipv6Prefix,
				params.WireGuardParameters.Mtu,
				hostValue.DnsServers,
				hostValue.AllowedIPs,
			)
		}

		return s.connectWireGuard(originalEntryServerInfo, connectionParams, params.ManualDNS, params.Metadata.AntiTracker, params.FirewallOn, params.FirewallOnDuringConnection, v2RayWrapper, canReconfigureOtherVpns)
	}

	return fmt.Errorf("unexpected VPN type to connect (%v)", params.VpnType)
}

// connectOpenVPN start OpenVPN connection
func (s *Service) connectOpenVPN(originalEntryServerInfo *svrConnInfo, connectionParams openvpn.ConnectionParams, manualDNS dns.DnsSettings, antiTracker types.AntiTrackerMetadata, firewallOn bool, firewallDuringConnection bool, obfsproxyConfig obfsproxy.Config, v2rayWrapper *v2r.V2RayWrapper, canReconfigureOtherVpns bool) error {

	createVpnObjfunc := func() (vpn.Process, error) {
		prefs := s.Preferences()

		// checking if functionality accessible
		disabledFuncs := s.GetDisabledFunctions()
		if len(disabledFuncs.OpenVPNError) > 0 {
			return nil, fmt.Errorf(disabledFuncs.OpenVPNError)
		}
		if obfsproxyConfig.IsObfsproxy() && len(disabledFuncs.ObfsproxyError) > 0 {
			return nil, fmt.Errorf(disabledFuncs.ObfsproxyError)
		}

		connectionParams.SetCredentials(prefs.Session.OpenVPNUser, prefs.Session.OpenVPNPass)

		openVpnExtraParameters := ""
		// read user-defined extra parameters for OpenVPN configuration (if exists)
		extraParamsFile := platform.OpenvpnUserParamsFile()

		if helpers.FileExists(extraParamsFile) {
			if err := filerights.CheckFileAccessRightsConfig(extraParamsFile); err != nil {
				log.Info("NOTE! User-defined OpenVPN parameters are ignored! %w", err)
				os.Remove(extraParamsFile)
			} else {
				// read file line by line
				openVpnExtraParameters = func() string {
					var allParams strings.Builder

					file, err := os.Open(extraParamsFile)
					if err != nil {
						log.Error(err)
						return ""
					}
					defer file.Close()

					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := scanner.Text()
						line = strings.TrimSpace(line)
						if len(line) <= 0 {
							continue
						}
						if strings.HasPrefix(line, "#") {
							continue // comment
						}
						if strings.HasPrefix(line, ";") {
							continue // comment
						}
						allParams.WriteString(line + "\n")
					}

					if err := scanner.Err(); err != nil {
						log.Error(fmt.Sprintf("Failed to parse '%s': %s", extraParamsFile, err))
						return ""
					}
					return allParams.String()
				}()

				if len(openVpnExtraParameters) > 0 {
					log.Info(fmt.Sprintf("WARNING! User-defined OpenVPN parameters loaded from file '%s'!", extraParamsFile))
				}
			}
		}

		// initialize obfsproxy parameters
		obfsParams := openvpn.ObfsParams{Config: obfsproxyConfig}
		if obfsParams.Config.IsObfsproxy() {
			svrs, err := s.ServersList()
			if err != nil {
				return nil, fmt.Errorf("failed to initialize obfsproxy configuration: %w", err)
			}

			if connectionParams.IsMultihop() {
				// find host by hostname
				host, err := s.findOpenVpnHost(connectionParams.GetMultihopExitHostName(), nil, svrs.OpenvpnServers)
				if err != nil {
					return nil, fmt.Errorf("failed to initialize obfsproxy configuration: %w", err)
				}

				switch obfsParams.Config.Version {
				case obfsproxy.OBFS3:
					obfsParams.RemotePort = host.Obfs.Obfs3MultihopPort
				case obfsproxy.OBFS4:
					obfsParams.RemotePort = host.Obfs.Obfs4MultihopPort
					obfsParams.Obfs4Key = host.Obfs.Obfs4Key
				default:
					return nil, fmt.Errorf("failed to initialize obfsproxy configuration: unsupported obfs version: %d", obfsParams.Config.Version)
				}
			} else {
				switch obfsParams.Config.Version {
				case obfsproxy.OBFS3:
					obfsParams.RemotePort = svrs.Config.Ports.Obfs3.Port
				case obfsproxy.OBFS4:
					{
						// find host by host ip
						host, err := s.findOpenVpnHost("", connectionParams.GetHostIp(), svrs.OpenvpnServers)
						if err != nil {
							return nil, fmt.Errorf("failed to initialize obfsproxy configuration: %w", err)
						}

						obfsParams.RemotePort = svrs.Config.Ports.Obfs4.Port
						obfsParams.Obfs4Key = host.Obfs.Obfs4Key
					}
				default:
					return nil, fmt.Errorf("failed to initialize obfsproxy configuration: unsupported obfs version: %d", obfsParams.Config.Version)
				}
			}

		}

		// creating OpenVPN object
		vpnObj, err := openvpn.NewOpenVpnObject(
			platform.OpenVpnBinaryPath(),
			platform.OpenvpnConfigFile(),
			"",
			obfsParams,
			openVpnExtraParameters,
			connectionParams)

		if err != nil {
			return nil, fmt.Errorf("failed to create new openVPN object: %w", err)
		}
		return vpnObj, nil
	}

	return s.keepConnection(originalEntryServerInfo, createVpnObjfunc, manualDNS, antiTracker, firewallOn, firewallDuringConnection, v2rayWrapper, canReconfigureOtherVpns)
}

// connectWireGuard start WireGuard connection
func (s *Service) connectWireGuard(originalEntryServerInfo *svrConnInfo, connectionParams wireguard.ConnectionParams, manualDNS dns.DnsSettings, antiTracker types.AntiTrackerMetadata, firewallOn bool, firewallDuringConnection bool, v2rayWrapper *v2r.V2RayWrapper, canReconfigureOtherVpns bool) error {
	// stop active connection (if exists)
	if err := s.Disconnect(); err != nil {
		return fmt.Errorf("failed to connect. Unable to stop active connection: %w", err)
	}

	// checking if functionality accessible
	disabledFuncs := s.GetDisabledFunctions()
	if len(disabledFuncs.WireGuardError) > 0 {
		return fmt.Errorf(disabledFuncs.WireGuardError)
	}

	// Update WG keys, if necessary
	err := s.WireGuardGenerateKeys(true)
	if err != nil {
		// If new WG keys regeneration failed but we still have active keys - keep connecting
		// (this could happen, for example, when FW is enabled and we even not tried to make API request)
		// Return error only if the keys had to be regenerated more than 3 days ago.
		_, activePublicKey, _, _, lastUpdate, interval := s.WireGuardGetKeys()

		if len(activePublicKey) > 0 && lastUpdate.Add(interval).Add(time.Hour*24*3).After(time.Now()) {
			// continue connection
			log.Warning(fmt.Errorf("WG KEY generation failed (%w). But we keep connecting (will try to regenerate it next 3 days)", err))
		} else {
			return err
		}
	}

	createVpnObjfunc := func() (vpn.Process, error) {
		session := s.Preferences().Session

		if !session.IsWGCredentialsOk() {
			return nil, fmt.Errorf("WireGuard credentials are not defined (please, regenerate WG credentials or re-login)")
		}

		localip := net.ParseIP(session.WGLocalIP)
		if localip == nil {
			return nil, fmt.Errorf("error updating WG connection preferences (failed parsing local IP for WG connection)")
		}
		connectionParams.SetCredentials(session.Session, session.WGPrivateKey, session.WGPublicKey, session.WGPresharedKey, localip)

		vpnObj, err := wireguard.NewWireGuardObject(
			platform.WgBinaryPath(),
			platform.WgToolBinaryPath(),
			platform.WGConfigFilePath(),
			connectionParams,
			s._statsCallbacks)

		if err != nil {
			return nil, fmt.Errorf("failed to create new WireGuard object: %w", err)
		}
		return vpnObj, nil
	}

	return s.keepConnection(originalEntryServerInfo, createVpnObjfunc, manualDNS, antiTracker, firewallOn, firewallDuringConnection, v2rayWrapper, canReconfigureOtherVpns)
}

func (s *Service) keepConnection(originalEntryServerInfo *svrConnInfo, createVpnObj func() (vpn.Process, error), initialManualDNS dns.DnsSettings, initialAntiTracker types.AntiTrackerMetadata, firewallOn bool, firewallDuringConnection bool, v2rayWrapper *v2r.V2RayWrapper, canReconfigureOtherVpns bool) (retError error) {
	prefs := s.Preferences()
	if !prefs.Session.IsLoggedIn() {
		return srverrors.ErrorNotLoggedIn{}
	}

	defer func() {
		// If no any clients connected - disconnection notification will not be passed to user
		// In this case we are trying to save message into system log
		if !s._evtReceiver.IsClientConnected(false) {
			if retError != nil {
				s.systemLog(Error, "Failed to connect VPN: "+retError.Error())
			} else {
				s.systemLog(Info, "VPN disconnected")
			}
		}
	}()

	// save initial DNS configuration
	s.saveDefaultDnsParams(initialManualDNS, initialAntiTracker)

	// Not necessary to keep connection until we are not connected
	// So just 'Connect' required for now
	s._requiredVpnState = Connect

	// no delay before first reconnection
	delayBeforeReconnect := 0 * time.Second

	s._evtReceiver.OnVpnStateChanged_SaveStateEarly(vpn.NewStateInfo(vpn.CONNECTING, "Connecting"), true)
	for {
		// create new VPN object
		vpnObj, err := createVpnObj()
		if err != nil {
			return fmt.Errorf("failed to create VPN object: %w", err)
		}

		lastConnectionTryTime := time.Now()

		// get actual DNS configuration
		manualDns, antitracker, _, err := s.GetDefaultManualDnsParams()
		if err != nil {
			return fmt.Errorf("failed to get DNS settings: %w", err)
		}

		prefs = s.Preferences()
		// isInverseSplitTun := prefs.IsInverseSplitTunneling()

		// start connection
		connErr := s.connect(originalEntryServerInfo,
			vpnObj,
			manualDns,
			antitracker,
			firewallOn,               /* && !isInverseSplitTun */
			firewallDuringConnection, /* && !isInverseSplitTun */
			v2rayWrapper,
			canReconfigureOtherVpns || s._preferences.PermissionReconfigureOtherVPNs)
		if connErr != nil {
			log.Error(fmt.Sprintf("Connection error: %s", connErr))
			if s._requiredVpnState == Connect {
				// throw error only on first try to connect
				// if we were already connected (_requiredVpnState==KeepConnection) - ignore error and try to reconnect
				return connErr
			}
		}

		// retry, if reconnection requested
		if s._requiredVpnState == KeepConnection {
			// notifying clients about reconnection
			s._evtReceiver.OnVpnStateChanged_SaveStateEarly(vpn.NewStateInfo(vpn.RECONNECTING, "Reconnecting due to disconnection"), true)

			// no delay before reconnection (if last connection was long time ago)
			if time.Now().After(lastConnectionTryTime.Add(time.Second * 30)) {
				delayBeforeReconnect = 0
			}
			// no delay before reconnection if reconnection was requested by VPN object
			if connErr != nil {
				var reconnectReqErr *vpn.ReconnectionRequiredError
				if errors.As(connErr, &reconnectReqErr) {
					log.Info("VPN object requested re-connection")
					delayBeforeReconnect = 0
				}
			}

			if delayBeforeReconnect > 0 {
				log.Info(fmt.Sprintf("Reconnecting (pause %s)...", delayBeforeReconnect))
				// do delay before next reconnection
				pauseTill := time.Now().Add(delayBeforeReconnect)
				for time.Now().Before(pauseTill) && s._requiredVpnState != Disconnect {
					time.Sleep(time.Millisecond * 10)
				}
			} else {
				log.Info("Reconnecting...")
			}

			if s._requiredVpnState == KeepConnection {
				// consecutive re-connections has delay 5 seconds
				delayBeforeReconnect = time.Second * 5
				continue
			}
		}

		// stop loop
		break
	}

	return nil
}

// Connect connect vpn.
//   - Param 'originalEntryServerInfo' - contains original info about EntryServer/Port (it is not 'nil' for V2Ray connections).
//     We need this info to notify correct data about vpn.CONNECTED state: for V2Ray connection the original parameters are overwriten by local V2Ray proxy params ('127.0.0.1:local_port')
//   - Param 'firewallOn' - unconditionally reenable firewall before connection (if true - the parameter 'firewallDuringConnection' will be ignored).
//   - Param 'firewallDuringConnection' - unconditionally reenable firewall before connection, and disable after disconnection
func (s *Service) connect(originalEntryServerInfo *svrConnInfo, vpnProc vpn.Process, manualDNS dns.DnsSettings, antiTracker types.AntiTrackerMetadata, firewallOn bool, firewallDuringConnection bool, v2rayWrapper *v2r.V2RayWrapper, canReconfigureOtherVpns bool) (err error) {
	var connectRoutinesWaiter sync.WaitGroup

	// stop active connection (if exists)
	if err := s.disconnect(); err != nil {
		return fmt.Errorf("failed to connect. Unable to stop active connection: %w", err)
	}

	// check session status each disconnection (asynchronously, in separate goroutine)
	defer func() { go s.RequestSessionStatus() }()

	s._connectMutex.Lock()
	defer s._connectMutex.Unlock()

	s._done = make(chan struct{}, 1)
	defer func() {
		// notify: connection stopped
		done := s._done
		s._done = nil
		if done != nil {
			done <- struct{}{}
			// Closing channel
			// Note: reading from empty or closed channel will not lead to deadlock (immediately returns zero value)
			close(done)
		}
	}()

	log.Info("Connecting...")

	// save vpn object
	s._vpn = vpnProc

	// Firewall must be enabled before starting VPN connection, required for VPN coexistence.
	// Unconditionally run disable-then-enable, even if firewall was disabled before (this is to clean out old rules).
	// Must run it after s._vpn is set, so that firewall will know to enable Total Shield, if needed.
	log.Info("Initializing firewall")
	if firewallOn || firewallDuringConnection {
		if err := s.ReEnableKillSwitch(canReconfigureOtherVpns); err != nil {
			return log.ErrorFE("Failed to reenable firewall: %w", err)
		}
	}

	internalStateChan := make(chan vpn.StateInfo, 1)
	stopChannel := make(chan bool, 1)

	// fwInitState := false
	// finalize everything
	defer func() {
		if r := recover(); r != nil {
			log.Error("Panic on VPN connection: ", r)
			log.Error(string(debug.Stack()))
			if err, ok := r.(error); ok {
				log.ErrorTrace(err)
			}
		}

		// Ensure that routing-change detector is stopped (we do not need it when VPN disconnected)
		s._netChangeDetector.UnInit()

		// ensure firewall removed rules for DNS
		firewall.OnChangeDNS(nil)

		// notify firewall that client is disconnected
		err := firewall.ClientDisconnected()
		if err != nil {
			log.Error("(stopping) error on notifying FW about disconnected client:", err)
		}

		// notify routines to stop
		close(stopChannel)

		// resetting manual DNS (if it is necessary)
		err = vpnProc.ResetManualDNS()
		if err != nil {
			log.Error("(stopping) error resetting manual DNS: ", err)
		}

		// Need to wait for all connectRoutinesWaiter routines to end before disabling firewall, because implFirewallBackgroundMonitor() can reenable it.
		connectRoutinesWaiter.Wait()

		// when we were requested to enable firewall for this connection
		// And initial FW state was disabled - we have to disable it back
		// if firewallDuringConnection && !fwInitState {
		if !firewallOn && firewallDuringConnection { // per firewallOn, firewallDuringConnection description
			if err = s.SetKillSwitchState(false, canReconfigureOtherVpns); err != nil {
				log.ErrorFE("(stopping) failed to disable firewall: %w", err)
			}
		}

		// Forget VPN object
		s._vpn = nil

		// Notify Split-Tunneling module about disconnected VPN status. Firewall will know the VPN state via vpnConnectedCallback()
		s.splitTunnelling_ApplyConfig(true)

		log.Info("VPN process stopped")
	}()

	// Signaling when the default routing is NOT over the 'interfaceToProtect' anymore
	routingChangeChan := make(chan struct{}, 1)
	// Signaling when there were some routing changes but 'interfaceToProtect' is still is the default route
	routingUpdateChan := make(chan struct{}, 1)

	destinationIpAddresses := make([]net.IP, 0)
	// Add VPN server IP to firewall exceptions
	destinationIpAddresses = append(destinationIpAddresses, vpnProc.DestinationIP())

	if v2rayWrapper != nil {
		// Configure firewall to allow V2Ray remote IP
		v2RayRemoteHost, _, err := v2rayWrapper.GetRemoteEndpoint()
		if err != nil {
			return fmt.Errorf("failed to get V2Ray remote endpoint: %w", err)
		}
		destinationIpAddresses = append(destinationIpAddresses, v2RayRemoteHost)
	}

	// if firewall background monitors are available on the platform - start them all in the background
	for _, firewallBackgroundMonitor := range firewall.GetFirewallBackgroundMonitors() {
		connectRoutinesWaiter.Add(1)
		go func(fbm *srvhelpers.ServiceBackgroundMonitor) {
			defer func() {
				go fbm.StopServiceBackgroundMonitor() // async, as iptables-legacy one sleeps for 5s between each polling loop iteration
				connectRoutinesWaiter.Done()
			}()

			go fbm.MonitorFunc()
			log.Debug("Monitor '", fbm.MonitorName, "' started")

			<-stopChannel // triggered when the stopChannel is closed
		}(firewallBackgroundMonitor)
	}

	// goroutine: process + forward VPN state change
	connectRoutinesWaiter.Add(1)
	go func() {
		log.Info("VPN state forwarder started")
		defer func() {
			log.Info("VPN state forwarder stopped")
			connectRoutinesWaiter.Done()
		}()

		var state vpn.StateInfo
		for isRuning := true; isRuning; {
			select {
			case state = <-internalStateChan:

				// store info about current time
				state.Time = time.Now().Unix()
				// store info about VPN connection type
				state.VpnType = vpnProc.Type()

				// 'originalEntryServerInfo' contains original info about EntryServer/Port (it is not 'nil' for V2Ray connections).
				// We need this info to notify correct data about vpn.CONNECTED state: for V2Ray connection the original parameters are overwriten by local V2Ray proxy params ('127.0.0.1:local_port')
				if state.State == vpn.CONNECTED && originalEntryServerInfo != nil {
					state.ServerIP = originalEntryServerInfo.IP     // because state.ServerIP contains "127.0.0.1" which is not informative for the client
					state.ServerPort = originalEntryServerInfo.Port // because state.ServerPort contains local port (port of local V2Ray proxy)
					state.IsTCP = originalEntryServerInfo.PortType > 0
					state.V2RayProxy = originalEntryServerInfo.V2RayProxyType
				}

				//  using the inline function to process state. It is required for a correct functioning of the "defer" statement
				func() {
					// do not forget to forward state to 'stateChan'
					s._evtReceiver.OnVpnStateChanged_SaveStateEarly(state, false) // we need to save it early, so that firewall Total Shield logic will know VPN is CONNECTED
					defer s._evtReceiver.OnVpnStateChanged_ProcessSavedState()

					log.Info(fmt.Sprintf("State: %v", state))
					go s._evtReceiver.OnKillSwitchStateChanged(false) // re-notify clients abt VPN coexistence status on state change

					// internally process VPN state change
					switch state.State {

					case vpn.RECONNECTING:
						// Disable routing-change detector when reconnecting
						s._netChangeDetector.UnInit()

						// Add host IP to firewall exceptions
						// Some OS-specific implementations (e.g. macOS) can remove server host from firewall rules after connection established
						// We have to allow it's IP to be able to reconnect
						const onlyForICMP = false
						const isPersistent = false
						err := firewall.AddHostsToExceptions(destinationIpAddresses, onlyForICMP, isPersistent)
						if err != nil {
							log.Error("Unable to add host to firewall exceptions:", err.Error())
						}

					case vpn.INITIALISED:
						// start routing change detection
						// if netInterface, err := netinfo.InterfaceByIPAddr(state.ClientIP); err != nil {
						// 	log.Error(fmt.Sprintf("Unable to initialize routing change detection. Failed to get interface '%s'", state.ClientIP.String()))
						// } else {
						//if err := s._netChangeDetector.Init(routingChangeChan, routingUpdateChan, netInterface, s.splitTunnelling_ApplyConfig); err != nil {
						if err := s._netChangeDetector.Init(routingChangeChan, routingUpdateChan, nil, s.splitTunnelling_ApplyConfig, s.Preferences); err != nil {
							log.Error(fmt.Errorf("failed to init route change detection: %w", err))
						}
						// if s._preferences.IsInverseSplitTunneling() {
						// 	// Inversed split-tunneling: disable monitoring of the default route to the VPN server.
						// 	// Note: the monitoring must be enabled as soon as the inverse split-tunneling is disabled!
						// 	log.Info("Disabled the monitoring of the default route to the VPN server due to Inverse Split-Tunnel")
						// } else {
						log.Info("Starting route change detection")
						if err := s._netChangeDetector.Start(); err != nil {
							log.Error(fmt.Errorf("failed to start route change detection: %w", err))
						}
						// }
						// }

					case vpn.CONNECTED:
						// since we are connected - keep connection (reconnect if unexpected disconnection)
						if s._requiredVpnState == Connect {
							s._requiredVpnState = KeepConnection
							// log.Debug("set s._requiredVpnState = KeepConnection")
						}

						// If no any clients connected - connection notification will not be passed to user
						// In this case we are trying to save info message into system log
						if !s._evtReceiver.IsClientConnected(false) {
							s.systemLog(Info, "VPN connected")
						}

						// Inform firewall about client local IP
						firewall.ClientConnected(
							state.ClientIP, state.ClientIPv6,
							state.ClientPort,
							state.ServerIP, state.ServerPort,
							state.IsTCP)

						// Ensure firewall is configured to allow DNS communication
						// At this moment, firewall must be already configured for custom DNS
						// but if it still has no rule - apply DNS rules for default DNS
						if _, isInitialized := firewall.GetDnsInfo(); !isInitialized {
							d := dns.DnsSettingsCreate(vpnProc.DefaultDNS())
							firewall.OnChangeDNS(&d)
						}

						// save ClientIP/ClientIPv6 into vpn-session-info
						sInfo := s.GetVpnSessionInfo()
						sInfo.VpnLocalIPv4 = state.ClientIP
						sInfo.VpnLocalIPv6 = state.ClientIPv6
						s.SetVpnSessionInfo(sInfo)

						// Notify Split-Tunneling module about VPN state CONNECTED. Firewall will know the VPN state via vpnConnectedCallback()
						// It is important to call it after 's._vpn' initialised. So ST functionality will be correctly informed about 'VPN connected' status
						s.splitTunnelling_ApplyConfig(true)

						// Run at the end, as meet.privateline.network lookup fails if it's called too soon after WG connects. Run asynchronously.
						go firewall.DeployPostConnectionRules(canReconfigureOtherVpns || s._preferences.PermissionReconfigureOtherVPNs)

						// Finally start the connectivityHealthchecksBackgroundMonitor
						connectRoutinesWaiter.Add(1)
						go func(chbm *srvhelpers.ServiceBackgroundMonitor) {
							defer func() {
								log.Debug("forking chbm.StopServiceBackgroundMonitor() from 'Finally start the connectivityHealthchecksBackgroundMonitor' block")
								go chbm.StopServiceBackgroundMonitor() // async
								connectRoutinesWaiter.Done()
							}()

							go chbm.MonitorFunc()
							log.Debug("Monitor '", chbm.MonitorName, "' started")

							<-stopChannel // triggered when the stopChannel is closed
						}(s.connectivityHealthchecksBackgroundMonitorDef)

					default:
					}
				}()

			case <-stopChannel: // triggered when the stopChannel is closed
				isRuning = false
			}
		}
	}()

	// receiving routing change notifications
	connectRoutinesWaiter.Add(1)
	go func() {
		log.Info("Route change receiver started")
		defer func() {
			log.Info("Route change receiver stopped")
			connectRoutinesWaiter.Done()
		}()

		for isRuning := true; isRuning; {
			select {
			case <-routingChangeChan: // routing changed (the default routing is NOT over the 'interfaceToProtect' anymore)
				if s._vpn.IsPaused() {
					log.Info("Route change ignored due to Paused state.")
				} else {
					// Disconnect (client will request then reconnection, because of unexpected disconnection)
					// reconnect in separate routine (do not block current thread)
					go func() {
						defer func() {
							if r := recover(); r != nil {
								log.Error("PANIC Route change receiver: ", r)
								log.Error(string(debug.Stack()))
							}
						}()

						log.Info("Route change detected. Reconnecting...")
						s.reconnect()
					}()

					isRuning = false
				}
			case <-routingUpdateChan: // there were some routing changes but 'interfaceToProtect' is still is the default route
				// If V2Ray is in use - we must update route to V2Ray server each time when default gateway IP was chnaged
				if v2rayWrapper != nil {
					if err := v2rayWrapper.UpdateMainRoute(); err != nil {
						log.Error(err)
					}
				}
				s._vpn.OnRoutingChanged()
				go func() {
					// Ensure that current DNS configuration is correct. If not - it re-apply the required configuration.
					// Currently, it is in use for macOS - like a DNS change monitor.
					err := dns.UpdateDnsIfWrongSettings()
					if err != nil {
						log.Error(fmt.Errorf("failed to update DNS settings: %w", err))
					}
				}()
			case <-stopChannel: // triggered when the stopChannel is closed
				isRuning = false
			}
		}
	}()

	// Check that firewall is enabled (this check necessary only on Windows)
	if runtime.GOOS == "windows" {
		if killSwitchState, err := s.KillSwitchState(); err != nil {
			return log.ErrorFE("error checking firewall status: %w", err)
		} else if !killSwitchState.IsEnabled {
			return log.ErrorE(errors.New("error - firewall must be enabled by now"), 0)
		}
	}

	// Check whether this device registration is active
	if deviceFound, err := s._api.CheckDeviceID(s._preferences.Session.Session, s._preferences.Session.WGPublicKey); err != nil {
		log.ErrorFE("error checking device ID: %w", err) // continue, try to connect anyway
	} else if !deviceFound { // this device not registered, report up - upper callers will logout and attempt to re-login
		return &protocol.ErrorDeviceNotFound
	}

	// Initialize VPN: ensure everything is prepared for a new connection
	// (e.g. correct OpenVPN version or a previously started WireGuard service is stopped)
	log.Info("Initializing connection...")
	if err := vpnProc.Init(); err != nil {
		return fmt.Errorf("failed to initialize VPN object: %w", err)
	}

	// Split-Tunnelling: Checking default outbound IPs
	// (note: it is important to call this code after 'vpnProc.Init()')
	var sInfo VpnSessionInfo
	sInfo.OutboundIPv4, err = netinfo.GetOutboundIP(false)
	if err != nil {
		log.Warning(fmt.Errorf("failed to detect outbound IPv4 address: %w", err))
	}
	sInfo.OutboundIPv6, err = netinfo.GetOutboundIP(true)
	if err != nil {
		log.Warning(fmt.Errorf("failed to detect outbound IPv6 address: %w", err))
	}
	s.SetVpnSessionInfo(sInfo)

	// log.Info("Initializing firewall")
	// // ensure firewall has no rules for DNS
	// firewall.OnChangeDNS(nil)

	// firewallOn - enable firewall before connection (if true - the parameter 'firewallDuringConnection' will be ignored)
	// firewallDuringConnection - enable firewall before connection and disable after disconnection (has effect only if Firewall not enabled before)
	/*
		if firewallOn {
			enabled, err := firewall.GetEnabled()
			if err != nil {
				log.Error("Failed to check firewall state:", err.Error())
				return err
			}
			if !enabled {
				if err := s.SetKillSwitchState(true); err != nil {
					log.Error("Failed to enable firewall:", err.Error())
					return err
				}
			}
		} else if firewallDuringConnection {
			// in case to enable FW for this connection parameter:
			// - check initial FW state
			// - if it disabled - enable it (will be disabled on disconnect)
			enabled, err := firewall.GetEnabled()
			if err != nil {
				log.Error("Failed to check firewall state:", err.Error())
				return err
			}
			fwInitState := enabled
			if !fwInitState {
				if err := s.SetKillSwitchState(true); err != nil {
					log.Error("Failed to enable firewall:", err.Error())
					return err
				}
			}
		}
	*/

	// Add host IP to firewall exceptions
	const onlyForICMP = false
	const isPersistent = false
	err = firewall.AddHostsToExceptions(destinationIpAddresses, onlyForICMP, isPersistent)
	if err != nil {
		log.Error("Failed to start. Unable to add hosts to firewall exceptions:", err.Error())
		return err
	}

	log.Info("Initializing DNS")

	// Re-initialize DNS configuration according to user settings
	// It is applicable, for example for Linux: when the user changed DNS management style
	if err := dns.ApplyUserSettings(); err != nil {
		return err
	}

	// set manual DNS
	if _, err = s.SetManualDNS(manualDNS, antiTracker); err != nil {
		err = fmt.Errorf("failed to set DNS: %w", err)
		log.Error(err.Error())
		return err
	}

	log.Info("Starting VPN process")
	// connect: start VPN process and wait until it finishes
	err = vpnProc.Connect(internalStateChan)
	if err != nil {
		err = fmt.Errorf("connection error: %w", err)
		log.Error(err.Error())
		return err
	}

	return nil
}

// startV2Ray start V2Ray connection
// Please refer to the v2r.V2RayConfig (in v2r/config.go) struct for more information about the V2Ray data flow and configuration
func (s *Service) startV2Ray(params types.ConnectionParams, v2RayType v2r.V2RayTransportType) (
	updatedParams types.ConnectionParams,
	v2RayWrapper *v2r.V2RayWrapper,
	originalEntryServerInfo *svrConnInfo,
	err error) {

	if v2RayType != v2r.QUIC && v2RayType != v2r.TCP {
		return params, nil, nil, nil
	}

	svrs, err := s.ServersList()
	if err != nil {
		return params, nil, nil, err
	}
	outboundUserId := svrs.Config.Ports.V2Ray.ID

	v2RayOutboundType := v2r.QUIC
	if v2RayType == v2r.TCP {
		v2RayOutboundType = v2r.TCP
	}

	remoteSvrDnsName := ""

	outboundTlsSvrName := ""
	outboundIp := ""
	outboundPort, isTcpOutboundPort := params.Port()

	if v2RayType == v2r.QUIC && isTcpOutboundPort {
		return params, nil, nil, fmt.Errorf("not acceptable port type for V2Ray-QUIC connection (UDP is expected)")
	}
	if v2RayType == v2r.TCP && !isTcpOutboundPort {
		return params, nil, nil, fmt.Errorf("not acceptable port type for V2Ray-TCP connection (TCP is expected)")
	}

	if outboundPort == 0 {
		// the preferred (but not mandatory) ports for outbound connection are:
		// - 80 for HTTP/VMess/TCP
		// - 443 for HTTPS/VMess/QUIC
		// (but it can be any other normal port which applicable for the selected VPN type)
		outboundPort = 443
		if v2RayOutboundType == v2r.TCP {
			outboundPort = 80
		}
	}

	var inboundPortsApplicable []api_types.PortInfoBase

	inboundIp := ""  // for Single-Hop: host IP; for Multi-Hop: exit host IP
	inboundPort := 0 // for Single-Hop: internal V2Ray port; for Multi-Hop: exit host port

	// isTcpLocalPort - is the local port type (TCP or UDP) of local V2Ray proxy: the inbound port type  ([VPN-server PROTOCOL]) should be similar to the local port type.
	// In fact, it is VPN connection type:
	// -	WireGuard uses only UDP;
	// -	for OpenVPN we use UDP because it is preffered (but TCP is also acceptable)
	isTcpLocalPort := false // use UDP for all VPN types

	requiredLocalPortTypeStr := "tcp"
	if !isTcpLocalPort {
		requiredLocalPortTypeStr = "udp"
	}

	switch params.VpnType {
	case vpn.OpenVPN:
		outboundIp = params.OpenVpnParameters.EntryVpnServer.Hosts[0].V2RayHost
		remoteSvrDnsName = params.OpenVpnParameters.EntryVpnServer.Hosts[0].DnsName
		if len(params.OpenVpnParameters.MultihopExitServer.Hosts) > 0 {
			// OpenVPN Multi-Hop
			inboundIp = params.OpenVpnParameters.MultihopExitServer.Hosts[0].EndpointIP
			inboundPortsApplicable = []api_types.PortInfoBase{{Type: strings.ToUpper(requiredLocalPortTypeStr), Port: outboundPort}}
		} else {
			// OpenVPN Single-Hop
			inboundIp = params.OpenVpnParameters.EntryVpnServer.Hosts[0].EndpointIP
			inboundPortsApplicable = svrs.Config.Ports.V2Ray.OpenVPN // for Single-Hop connections we use internal V2Ray ports for inbound connections
		}
	case vpn.WireGuard:
		outboundIp = params.WireGuardParameters.EntryVpnServer.Hosts[0].V2RayHost
		remoteSvrDnsName = params.WireGuardParameters.EntryVpnServer.Hosts[0].DnsName
		if len(params.WireGuardParameters.MultihopExitServer.Hosts) > 0 {
			// WireGuard Multi-Hop
			inboundIp = params.WireGuardParameters.MultihopExitServer.Hosts[0].EndpointIP
			inboundPortsApplicable = []api_types.PortInfoBase{{Type: strings.ToUpper(requiredLocalPortTypeStr), Port: outboundPort}}
		} else {
			// WireGuard Single-Hop
			inboundIp = params.WireGuardParameters.EntryVpnServer.Hosts[0].EndpointIP
			inboundPortsApplicable = svrs.Config.Ports.V2Ray.WireGuard // for Single-Hop connections we use internal V2Ray ports for inbound connections
		}
	}

	// TlsServerName required for QUIC connection
	outboundTlsSvrName = strings.Replace(remoteSvrDnsName, "ivpn.net", "inet-telecom.com", 1)

	// Filter PORTS: TCP or UDP: the inbound port type should be similat to the local port type
	var inboundPortsFiltered []api_types.PortInfoBase
	for _, port := range inboundPortsApplicable {
		pTypeStr := strings.TrimSpace(strings.ToLower(port.Type))
		if requiredLocalPortTypeStr == pTypeStr || (!isTcpLocalPort && pTypeStr == "") {
			inboundPortsFiltered = append(inboundPortsFiltered, port)
		}
	}
	if len(inboundPortsFiltered) == 0 {
		return params, nil, nil, fmt.Errorf("failed to start: no V2Ray '%s' ports for the speified VPN type", requiredLocalPortTypeStr)
	}

	// If there are more than one inbound port - select random one
	if len(inboundPortsFiltered) > 0 {
		inboundPort = inboundPortsFiltered[0].Port
		if rnd, err := rand.Int(rand.Reader, big.NewInt(int64(len(inboundPortsFiltered)))); err == nil {
			inboundPort = inboundPortsFiltered[rnd.Int64()].Port
		}
	} else {
		return params, nil, nil, fmt.Errorf("failed to start: no V2Ray inbound ports defined")
	}

	// Start V2Ray process
	v, err := v2r.Start(platform.V2RayBinaryPath(), platform.V2RayConfigFile(),
		isTcpLocalPort,
		v2RayOutboundType, // QUIC uses UDP outbound port; TCP uses TCP outbound port
		outboundIp, outboundPort,
		inboundIp, inboundPort,
		outboundUserId,
		outboundTlsSvrName)
	if err != nil {
		return params, nil, nil, fmt.Errorf("failed to start v2ray: %w", err)
	}

	v2rayLocalPort, _, err := v.GetLocalPort()
	if err != nil {
		v.Stop()
		return params, nil, nil, fmt.Errorf("failed to get V2Ray local port: %w", err)
	}

	// ------------------------------------------------------------
	// Update the original connection parameters with the settings required for the V2Ray connection
	// ------------------------------------------------------------
	updatedParams = params
	origEntrySvr := &svrConnInfo{V2RayProxyType: v2RayType}
	if vpn.Type(params.VpnType) == vpn.OpenVPN {

		// set OpenVPN protocol (udp/tcp) according to the local V2Ray port type
		updatedParams.OpenVpnParameters.Port.Protocol = 0
		if isTcpLocalPort {
			updatedParams.OpenVpnParameters.Port.Protocol = 1
		}

		// We have to return the original information about EntryServer
		origEntrySvr.IP = net.ParseIP(params.OpenVpnParameters.EntryVpnServer.Hosts[0].EndpointIP)
		origEntrySvr.Port = params.OpenVpnParameters.Port.Port
		origEntrySvr.PortType = params.OpenVpnParameters.Port.Protocol

		// Specify connection parameters to local V2Ray proxy
		updatedParams.OpenVpnParameters.EntryVpnServer.Hosts[0].EndpointIP = "127.0.0.1"
		updatedParams.OpenVpnParameters.Port.Port = v2rayLocalPort

		// for Multi-Hop connections
		if len(params.OpenVpnParameters.MultihopExitServer.Hosts) > 0 {
			// Data flow: Outbound(EntryServer:V2Ray) -> Inbound(ExitServer:OpenVPN)
			// For V2Ray connections we ignore port-based multihop configuration. Use default ports instead.
			updatedParams.OpenVpnParameters.MultihopExitServer.Hosts[0].EndpointPort = v2rayLocalPort
		}

	} else if vpn.Type(params.VpnType) == vpn.WireGuard {

		// We have to return the original information about EntryServer
		origEntrySvr.IP = net.ParseIP(params.WireGuardParameters.EntryVpnServer.Hosts[0].EndpointIP)
		origEntrySvr.Port = params.WireGuardParameters.Port.Port
		origEntrySvr.PortType = params.WireGuardParameters.Port.Protocol

		// Specify connection parameters to local V2Ray proxy
		updatedParams.WireGuardParameters.EntryVpnServer.Hosts[0].EndpointIP = "127.0.0.1"
		updatedParams.WireGuardParameters.Port.Port = v2rayLocalPort

		// for Multi-Hop connections
		if len(params.WireGuardParameters.MultihopExitServer.Hosts) > 0 {
			// Data flow: Outbound(EntryServer:V2Ray) -> Inbound(ExitServer:WireGuard)
			// Since the first WG server is the ExitServer - we have to use it's public key in the WireGuard configuration
			updatedParams.WireGuardParameters.EntryVpnServer.Hosts[0].PublicKey = params.WireGuardParameters.MultihopExitServer.Hosts[0].PublicKey
			// For V2Ray connections we ignore port-based multihop configuration. Use default ports instead.
			updatedParams.WireGuardParameters.MultihopExitServer.Hosts[0].EndpointPort = v2rayLocalPort
		}
	}
	// ------------------------------------------------------------

	return updatedParams, v, origEntrySvr, nil
}
