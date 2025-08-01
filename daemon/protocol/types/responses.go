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

package types

import (
	"fmt"

	"github.com/swapnilsparsh/devsVPN/daemon/api/types"
	api_types "github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/obfsproxy"
	"github.com/swapnilsparsh/devsVPN/daemon/service/dns"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	service_types "github.com/swapnilsparsh/devsVPN/daemon/service/types"
	"github.com/swapnilsparsh/devsVPN/daemon/v2r"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
)

var log *logger.Logger

func init() {
	log = logger.NewLogger("prttyp")
}

type ErrorType int

const (
	ErrorUnknown                   ErrorType = iota
	ErrorParanoidModePasswordError ErrorType = iota
)

// ErrorResp response of error
type ErrorResp struct {
	CommandBase
	ErrorMessage string
	ErrorTitle   string
	ErrorType    ErrorType
}

func (e ErrorResp) Error() string {
	return e.ErrorMessage
}

// ErrorRespDelayed - error info which had happened in the past
type ErrorRespDelayed struct {
	ErrorResp
}

// EmptyResp empty response on request
type EmptyResp struct {
	CommandBase
}

// ServiceExitingResp service is going to exit response
type ServiceExitingResp struct {
	CommandBase
}

type DisabledFunctionalityLinux struct {
	// If not empty - it is not possible to use the old way of DNS management
	// (which is based on a direct change of '/etc/resolv.conf')
	// For example: It could be because of snap environment (it does not allow to modify '/etc/resolv.conf')
	DnsMgmtOldResolvconfError string

	// If not empty - it is not possible to use modern way of DNS management
	// (based on communicationd with 'resolved' using 'resolvectl')
	// There could be different reasons of it:
	//	- there is no 'resolvectl' binary on target system
	//	- 'resolvectl' initialisation try was failed
	DnsMgmtNewResolvectlError string
}

type DisabledFunctionalityForPlatform struct {
	// Linux specific functionality which is disabled
	Linux DisabledFunctionalityLinux

	// Windows ...

	// macOS ...
}

// DisabledFunctionality Some functionality can be not accessible
// It can happen, for example, if some external binaries not installed
// (e.g. obfsproxy or Wireguard on Linux)
type DisabledFunctionality struct {
	WireGuardError          string // WireGuard is not supported on this platform
	OpenVPNError            string // OpenVPN is not supported on this platform
	ObfsproxyError          string // Obfsproxy is not supported on this platform
	V2RayError              string // V2Ray is not supported on this platform
	SplitTunnelError        string // SplitTunneling is not supported on this platform
	SplitTunnelInverseError string // Inversed SplitTunneling is not supported on this platform

	// Linux specific functionality which is disabled
	Platform DisabledFunctionalityForPlatform
}

type DnsAbilities struct {
	CanUseDnsOverTls   bool
	CanUseDnsOverHttps bool
}

type ParanoidModeStatus struct {
	IsEnabled bool
}

type SettingsResp struct {
	CommandBase

	IsAutoconnectOnLaunch          bool
	IsAutoconnectOnLaunchDaemon    bool
	UserDefinedOvpnFile            string
	UserPrefs                      preferences.UserPreferences
	WiFi                           preferences.WiFiParams
	IsLogging                      bool
	AntiTracker                    service_types.AntiTrackerMetadata
	HealthchecksType               string
	PermissionReconfigureOtherVPNs bool

	// TODO: implement the rest of daemon settings
	IsFwPersistent        bool
	IsFwAllowLAN          bool
	IsFwAllowLANMulticast bool
	IsFwAllowApiServers   bool
	FwUserExceptions      string
	IsSplitTunnel         bool
	SplitTunnelApps       []string
}

// HelloResp response on initial request
type HelloResp struct {
	CommandBase
	Version           string
	ProcessorArch     string
	OsVersion         string
	Session           SessionResp
	DevRestApiBackend bool
	Account           preferences.AccountStatus
	DisabledFunctions DisabledFunctionality
	Dns               DnsAbilities

	// SettingsSessionUUID is unique for Preferences object
	// It allow to detect situations when settings was erased (created new Preferences object)
	SettingsSessionUUID string

	ParanoidMode ParanoidModeStatus

	DaemonSettings SettingsResp
}

// SessionResp information about session
type SessionResp struct {
	AccountID          string
	Session            string
	DeviceName         string
	WgPublicKey        string
	WgLocalIP          string
	WgKeyGenerated     int64 // Unix time
	WgKeysRegenInerval int64 // seconds
	WgUsePresharedKey  bool
}

type TransferredDataResp struct {
	SentData     string
	ReceivedData string
}

type HandshakeResp struct {
	HandshakeTime string
}

// CreateSessionResp create new session info object to send to client
func CreateSessionResp(s preferences.SessionStatus) SessionResp {
	return SessionResp{
		AccountID:          s.AccountID,
		Session:            s.Session,
		DeviceName:         s.DeviceName,
		WgPublicKey:        s.WGPublicKey,
		WgLocalIP:          s.WGLocalIP,
		WgKeyGenerated:     s.WGKeyGenerated.Unix(),
		WgKeysRegenInerval: int64(s.WGKeysRegenInerval.Seconds()),
		WgUsePresharedKey:  len(s.WGPresharedKey) > 0}
}

type ProfileDataResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage error
	Session         SessionResp
	RawResponse     *api_types.ProfileDataResponse
}

type DeviceListResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage error
	Session         SessionResp
	RawResponse     *api_types.DeviceListResponse
}

type SubscriptionDataResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage error
	Session         SessionResp
	RawResponse     *api_types.SubscriptionDataResponse
}

// SessionNewResp - information about created session (or error info)
type SessionNewResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage string
	Session         SessionResp
	Account         preferences.AccountStatus
	RawResponse     string
}
type SsoLoginResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage string
	Session         SessionResp
	RawResponse     *api_types.SsoLoginResponse
}

type MigrateSsoUserResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage error
	AccountID       string
}

type AccountInfo struct {
	CommandBase
	APIStatus       int
	APIErrorMessage string
	Session         SessionResp
	Account         preferences.AccountStatus
	RawResponse     string
}

type SessionStatusResp struct {
	CommandBase
	APIStatus       int
	APIErrorMessage string
	SessionToken    string
	Account         preferences.AccountStatus
	DeviceName      string
}

type AccountInfoResponse struct {
	CommandBase
	APIStatus       int
	APIErrorMessage string
	Session         SessionResp
	AccountStatus   preferences.AccountStatus
	RawResponse     string
}

// KillSwitchStatusResp returns kill-switch status
type KillSwitchStatusResp struct {
	CommandBase
	service_types.KillSwitchStatus
}

type KillSwitchReregisterErrorResp struct {
	CommandBase
	ErrorMessage        string
	OtherVpnUnknownToUs bool
	OtherVpnName        string
	OtherVpnGUID        string
}

// KillSwitchGetIsPestistentResp returns kill-switch persistance status
type KillSwitchGetIsPestistentResp struct {
	CommandBase
	IsPersistent bool
}

// DiagnosticsGeneratedResp returns info from daemon logs
type DiagnosticsGeneratedResp struct {
	CommandBase
	Log0_Old    string // previous daemon session log
	Log1_Active string // active daemon log
	ExtraInfo   string // Extra info for logging (e.g. ifconfig, netstat -nr ... etc.)
}

type DnsStatus struct {
	Dns               dns.DnsSettings
	DnsMgmtStyleInUse dns.DnsMgmtStyle
	AntiTrackerStatus service_types.AntiTrackerMetadata
}

// SetAlternateDNSResp returns status of changing DNS
type SetAlternateDNSResp struct {
	CommandBase
	Dns DnsStatus
}

// DnsPredefinedConfigsResp list of predefined DoH/DoT configurations (if exists)
type DnsPredefinedConfigsResp struct {
	CommandBase
	DnsConfigs []dns.DnsSettings
}

// ConnectedResp notifying about established connection
type ConnectedResp struct {
	CommandBase
	VpnType         vpn.Type
	TimeSecFrom1970 int64
	ClientIP        string
	ClientIPv6      string
	ServerIP        string
	ServerPort      int
	ExitHostname    string // multi-hop exit hostname (e.g. "us-tx1.wg.ivpn.net")
	Dns             DnsStatus
	IsTCP           bool
	Mtu             int                    // (for WireGuard connections)
	V2RayProxy      v2r.V2RayTransportType // applicable only for 'CONNECTED' state
	Obfsproxy       obfsproxy.Config       // applicable only for 'CONNECTED' state (OpenVPN)
	IsPaused        bool                   // When "true" - the actual connection may be "disconnected" (depending on the platform and VPN protocol), but the daemon responds "connected"
	PausedTill      string                 // pausedTill.Format(time.RFC3339)
}

// DisconnectionReason - disconnection reason
type DisconnectionReason int

// Disconnection reason types
const (
	Unknown             DisconnectionReason = iota
	AuthenticationError DisconnectionReason = iota
	DisconnectRequested DisconnectionReason = iota
)

// DisconnectedResp notifying about stopped connetion
type DisconnectedResp struct {
	CommandBase
	Failure           bool
	Reason            DisconnectionReason //int
	ReasonDescription string
	IsStateInfo       bool // if 'true' - it is not an disconneection event, it is just status info "disconnected"
}

// VpnStateResp returns VPN connection state
type VpnStateResp struct {
	CommandBase
	// TODO: remove 'State' field. Use only 'StateVal'
	State               string
	StateVal            vpn.State
	StateAdditionalInfo string
}

// ServerListResp returns list of servers
type ServerListResp struct {
	CommandBase
	VpnServers types.ServersInfoResponse
}

// PingResultType represents information ping TTL for a host (is a part of 'PingServersResp')
type PingResultType struct {
	Host string
	Ping int
}

// PingServersResp returns average ping time for servers
type PingServersResp struct {
	CommandBase
	PingResults []PingResultType
}

// WiFiNetworkInfo - information about WIFI network
type WiFiNetworkInfo struct {
	SSID string
}

func (w WiFiNetworkInfo) GetSSID() string {
	return w.SSID
}

// WiFiAvailableNetworksResp - contains information about available WIFI networks
type WiFiAvailableNetworksResp struct {
	ResponseBase
	Networks []WiFiNetworkInfo
}

func (wl WiFiAvailableNetworksResp) GetNetworks() []WiFiNetworkInfo {
	return wl.Networks
}

func (wl WiFiAvailableNetworksResp) GetSSIDs() []string {
	ret := make([]string, len(wl.Networks))
	for i, n := range wl.Networks {
		ret[i] = n.SSID
	}
	return ret
}

// WiFiCurrentNetworkResp contains the information about currently connected WIFI
type WiFiCurrentNetworkResp struct {
	ResponseBase
	SSID              string
	IsInsecureNetwork bool
}

func (wi WiFiCurrentNetworkResp) GetSSID() string {
	return wi.SSID
}

func (wi WiFiCurrentNetworkResp) GetIsInsecure() bool {
	return wi.IsInsecureNetwork
}

// APIResponse contains the raw data of response to custom API request
type APIResponse struct {
	CommandBase
	APIPath      string
	ResponseData string
	Error        string
}

func (r APIResponse) LogExtraInfo() string {
	if len(r.Error) > 0 {
		return fmt.Sprint(r.APIPath, " Error!")
	}
	return fmt.Sprint(r.APIPath)
}

type CheckAccessiblePortsResponse struct {
	RequestBase
	Ports []api_types.PortInfo
}
