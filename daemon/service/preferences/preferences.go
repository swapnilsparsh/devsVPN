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

package preferences

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"os"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/obfsproxy"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/service/types"
	"github.com/swapnilsparsh/devsVPN/daemon/version"
)

var log *logger.Logger
var mutexRW sync.RWMutex

func init() {
	log = logger.NewLogger("prefs")
}

const (
	// DefaultWGKeysInterval - Default WireGuard keys rotation interval
	//DefaultWGKeysInterval = time.Hour * 24 * 1
	// TODO: FIXME: Vlad - for now effectively disable updating Wireguard keys, key rotation
	// Set it to 100 years
	DefaultWGKeysInterval = time.Hour * 24 * 365 * 100
)

type LinuxSpecificUserPrefs struct {
	// If true - use old style DNS management mechanism
	// by direct modifying file '/etc/resolv.conf'
	IsDnsMgmtOldStyle bool
}

type WindowsSpecificUserPrefs struct {
}

// VPN entry host info in parsed form, ready to be fed to firewall rules on Windows, Linux
type IPAndNetmask struct {
	IP      net.IP
	Netmask net.IP
}
type VpnEntryHostParsed struct {
	VpnEntryHostIP net.IP
	DnsServersIPv4 []net.IP
	AllowedIPs     []IPAndNetmask
}

// UserPreferences - IVPN service preferences which can be exposed to client
type UserPreferences struct {
	// NOTE: update this type when adding new preferences which can be exposed for clients
	// ...

	// The platform-specific preferences
	Linux   LinuxSpecificUserPrefs
	Windows WindowsSpecificUserPrefs
}

// Preferences - IVPN service preferences
type Preferences struct {
	// The daemon version that saved this data.
	// Can be used to determine the format version (e.g., on the first app start after an upgrade).
	Version string
	// SettingsSessionUUID is unique for Preferences object
	// It allow to detect situations when settings was erased (created new Preferences object)
	SettingsSessionUUID      string
	IsLogging                bool
	IsFwPersistent           bool
	IsFwAllowLAN             bool
	IsFwAllowLANMulticast    bool
	IsFwAllowApiServers      bool
	FwUserExceptions         string // Firewall exceptions: comma separated list of IP addresses (masks) in format: x.x.x.x[/xx]
	IsStopOnClientDisconnect bool

	// IsAutoconnectOnLaunch: if 'true' - daemon will perform automatic connection (see 'IsAutoconnectOnLaunchDaemon' for details)
	IsAutoconnectOnLaunch bool
	// IsAutoconnectOnLaunchDaemon:
	//	false - means the daemon applies operation 'IsAutoconnectOnLaunch' only when UI app connected
	//	true - means the daemon applies operation 'IsAutoconnectOnLaunch':
	//		-	when UI app connected
	//		-	after daemon initialization
	//		-	on user session LogOn
	IsAutoconnectOnLaunchDaemon    bool
	HealthchecksType               types.HealthchecksTypeEnum
	PermissionReconfigureOtherVPNs bool

	// split-tunnelling
	IsTotalShieldOn           bool // note that privateLINE definition of Total Shield is the opposite of the IVPN definition of Split Tunnel
	SplitTunnelApps           []string
	SplitTunnelInversed       bool // Inverse Split Tunnel: only 'splitted' apps use VPN tunnel (applicable only when IsSplitTunnel=true). For App Whitelist feature must be always true.
	EnableAppWhitelist        bool // Whether only whitelisted apps are allowed into the enclave (VPN). If false (default), then all apps are allowed into the enclave (VPN tunnel).
	SplitTunnelAnyDns         bool // (only for Inverse Split Tunnel) When false: Allow only DNS servers specified by the IVPN application
	SplitTunnelAllowWhenNoVpn bool // (only for Inverse Split Tunnel) Allow connectivity for Split Tunnel apps when VPN is disabled

	// last known account status
	Session SessionStatus
	Account AccountStatus
	// Subscription data
	PlanName string

	// NOTE: update this type when adding new preferences which can be exposed to clients
	UserPrefs UserPreferences

	LastConnectionParams types.ConnectionParams
	VpnEntryHostsParsed  []*VpnEntryHostParsed
	AllDnsServersIPv4Set mapset.Set[string]

	WiFiControl WiFiParams
}

type GetPrefsCallback func() Preferences

type SessionMutableData struct {
	Account    AccountStatus
	DeviceName string
}

func Create() *Preferences {
	// init default values
	return &Preferences{
		// SettingsSessionUUID is unique for Preferences object
		// It allow to detect situations when settings was erased (created new Preferences object)
		SettingsSessionUUID:            uuid.New().String(),
		IsFwAllowApiServers:            true,
		HealthchecksType:               types.HealthchecksType_Ping,
		PermissionReconfigureOtherVPNs: false,
		WiFiControl:                    WiFiParamsCreate(),
	}
}

// ParseVpnEntryHosts - parse endpoint(s) information once per change, to be reused many times in firewall_windows.go
func (p *Preferences) ParseVpnEntryHosts() {
	p.VpnEntryHostsParsed = make([]*VpnEntryHostParsed, len(p.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts))
	p.AllDnsServersIPv4Set = mapset.NewThreadUnsafeSetWithSize[string](2)

	for idx, vpnEntryHost := range p.LastConnectionParams.WireGuardParameters.EntryVpnServer.Hosts {
		var vpnEntryHostParsed VpnEntryHostParsed

		vpnEntryHostParsed.VpnEntryHostIP = net.ParseIP(vpnEntryHost.EndpointIP).To4()

		vpnEntryHostParsed.DnsServersIPv4 = make([]net.IP, 0, 2)
		for _, dnsSrv := range strings.Split(vpnEntryHost.DnsServers, ",") {
			trimmedDnsSrv := strings.TrimSpace(dnsSrv)
			vpnEntryHostParsed.DnsServersIPv4 = append(vpnEntryHostParsed.DnsServersIPv4, net.ParseIP(trimmedDnsSrv).To4())
			p.AllDnsServersIPv4Set.Add(trimmedDnsSrv)
		}

		vpnEntryHostParsed.AllowedIPs = make([]IPAndNetmask, 0, 6)
		for _, allowedIpCIDR := range strings.Split(vpnEntryHost.AllowedIPs, ",") { // CIDR format like "10.0.0.3/24"
			allowedIpCIDR = strings.TrimSpace(allowedIpCIDR)
			allowedIP, allowedIPNet, err := net.ParseCIDR(allowedIpCIDR)
			if err != nil {
				log.Error("error ParseCIDR '" + allowedIpCIDR + "'")
				continue
			}
			netmaskAsIP := net.IPv4(allowedIPNet.Mask[0], allowedIPNet.Mask[1], allowedIPNet.Mask[2], allowedIPNet.Mask[3])

			vpnEntryHostParsed.AllowedIPs = append(vpnEntryHostParsed.AllowedIPs, IPAndNetmask{allowedIP, netmaskAsIP})
		}

		p.VpnEntryHostsParsed[idx] = &vpnEntryHostParsed
	}
}

// IsInverseSplitTunneling returns:
// 'true' (default behavior) - when the VPN connection should be configured as the default route on a system,
// 'false' - when the default route should remain unchanged	(e.g., for inverse split-tunneling,	when the VPN tunnel is used only by 'split' apps).
func (p *Preferences) IsInverseSplitTunneling() bool {
	if p.IsTotalShieldOn {
		return false
	}

	return p.SplitTunnelInversed
}

// SetSession save account credentials
func (p *Preferences) SetSession(accountInfo AccountStatus,
	accountID string,
	session string,
	deviceName string,
	vpnUser string,
	vpnPass string,
	wgPublicKey string,
	wgPrivateKey string,
	wgLocalIP string,
	wgPreSharedKey string,
	deviceID string) {

	if len(session) == 0 || len(accountID) == 0 {
		p.Account = AccountStatus{}
	} else {
		p.Account = accountInfo
	}

	p.setSession(accountID, session, deviceName, vpnUser, vpnPass, wgPublicKey, wgPrivateKey, wgLocalIP, wgPreSharedKey, deviceID)
	p.SavePreferences()
}

func (p *Preferences) UpdateSessionData(sData SessionMutableData) {
	if len(p.Session.AccountID) == 0 || len(p.Session.Session) == 0 {
		sData = SessionMutableData{}
	}
	p.Account = sData.Account
	p.Session.DeviceName = sData.DeviceName
	p.SavePreferences()
}

// UpdateWgCredentials save wireguard credentials
func (p *Preferences) UpdateWgCredentials(wgPublicKey string, wgPrivateKey string, wgLocalIP string, wgPresharedKey string) {
	p.Session.updateWgCredentials(wgPublicKey, wgPrivateKey, wgLocalIP, wgPresharedKey)
	p.SavePreferences()
}

func (p *Preferences) getTempFilePath() string {
	return platform.SettingsFile() + ".tmp"
}

// SavePreferences saves preferences
func (p *Preferences) SavePreferences() error {
	mutexRW.Lock()
	defer mutexRW.Unlock()

	p.Version = version.Version()

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to save preferences file (json marshal error): %w", err)
	}

	settingsFile := platform.SettingsFile()
	settingsFileMode := os.FileMode(0600) // read\write only for privileged user

	// Save the settings file to a temporary file. This is necessary to prevent data loss in case of a power failure
	// or other system operations that could interrupt the saving process (e.g., a crash or process termination).
	// If the settings file becomes corrupted, the daemon will attempt to restore it from the temporary file.
	settingsFileTmp := p.getTempFilePath()
	if err := helpers.WriteFile(p.getTempFilePath(), data, settingsFileMode); err != nil { // read\write only for privileged user
		return err
	}

	// save settings file
	if err := helpers.WriteFile(settingsFile, data, settingsFileMode); err != nil { // read\write only for privileged user
		return err
	}

	// Remove temp file after successful saving
	os.Remove(settingsFileTmp)

	// also parse VPN entry hosts here, to use as input for firewall rules
	p.ParseVpnEntryHosts()

	return nil
}

// LoadPreferences loads preferences
func (p *Preferences) LoadPreferences() error {
	mutexRW.RLock()
	defer mutexRW.RUnlock()

	funcReadPreferences := func(filePath string) (data []byte, err error) {
		data, err = os.ReadFile(filePath)
		if err != nil {
			return data, log.ErrorFE("failed to read preferences file: %w", err)
		}

		// Parse json into preferences object
		p.AllDnsServersIPv4Set = mapset.NewThreadUnsafeSetWithSize[string](2) // to fix unmarshaling errors
		if err = json.Unmarshal(data, p); err != nil {
			return data, log.ErrorFE("error unmarshaling preferences file: %w", err)
		}
		return data, nil
	}

	data, err := funcReadPreferences(platform.SettingsFile())
	if err != nil {
		log.ErrorFE("failed to read preferences file: %w", err)
		// Try to read from temp file, if exists (this is necessary to prevent data loss in case of a power failure)
		var errTmp error
		if data, errTmp = funcReadPreferences(p.getTempFilePath()); errTmp != nil {
			return err // return original error
		}
		log.Info("Preferences file was restored from temporary file")
	}

	// init WG properties
	if len(p.Session.WGPublicKey) == 0 || len(p.Session.WGPrivateKey) == 0 || len(p.Session.WGLocalIP) == 0 {
		p.Session.WGKeyGenerated = time.Time{}
	}

	if p.Session.WGKeysRegenInerval <= 0 {
		p.Session.WGKeysRegenInerval = DefaultWGKeysInterval
		log.Info(fmt.Sprintf("default value for preferences: WgKeysRegenIntervalDays=%v", p.Session.WGKeysRegenInerval))
	}

	// *** Compatibility with old versions ***

	// Convert parameters from v3.10.23 (and releases older than 2023-05-15)
	// The default antitracker blocklist was "OSID Big". So keep it for old users who upgrade.
	//
	// We are here because the preferences file was exists, so it is not a new installation	(it is upgrade),
	// and if the AntiTrackerBlockListName is empty - it means that it is first upgrade to version which support multiple blocklists.
	if p.LastConnectionParams.Metadata.AntiTracker.AntiTrackerBlockListName == "" {
		log.Info("It looks like this is the first upgrade to the version which supports AntiTracker blocklists. Keep the old default blocklist name 'Oisdbig'.")
		p.LastConnectionParams.Metadata.AntiTracker.AntiTrackerBlockListName = "Oisdbig"
	}

	// Convert parameters from v3.11.15 (and releases older than 2023-08-07)
	if compareVersions(p.Version, "3.11.15") <= 0 {
		// if upgrading from "3.11.15" or older version

		// A new option, WiFiControl.Actions.UnTrustedBlockLan, was introduced.
		// It is 'true' by default. However, older versions did not have this functionality.
		// Therefore, for users upgrading from v3.11.15, it must be disabled.
		p.WiFiControl.Actions.UnTrustedBlockLan = false

		// Obfsproxy configuration was moved to 'LastConnectionParams->OpenVpnParameters' section
		type tmp_type_Settings_v3_11_15 struct {
			Obfs4proxy struct {
				Obfs4Iat obfsproxy.Obfs4IatMode
				Version  obfsproxy.ObfsProxyVersion
			}
		}
		var tmp_Settings_v3_11_15 tmp_type_Settings_v3_11_15
		err = json.Unmarshal(data, &tmp_Settings_v3_11_15)
		if err == nil && tmp_Settings_v3_11_15.Obfs4proxy.Version > obfsproxy.None {
			p.LastConnectionParams.OpenVpnParameters.Obfs4proxy = obfsproxy.Config{
				Version:  tmp_Settings_v3_11_15.Obfs4proxy.Version,
				Obfs4Iat: tmp_Settings_v3_11_15.Obfs4proxy.Obfs4Iat,
			}

		}
	}

	// also parse VPN entry hosts here, to use as input for firewall rules
	p.ParseVpnEntryHosts()

	return nil
}

func (p *Preferences) setSession(accountID string,
	session string,
	deviceName string,
	vpnUser string,
	vpnPass string,
	wgPublicKey string,
	wgPrivateKey string,
	wgLocalIP string,
	wgPreSharedKey string,
	deviceID string) {

	p.Session = SessionStatus{
		AccountID:          strings.TrimSpace(accountID),
		Session:            strings.TrimSpace(session),
		DeviceName:         strings.TrimSpace(deviceName),
		OpenVPNUser:        strings.TrimSpace(vpnUser),
		OpenVPNPass:        strings.TrimSpace(vpnPass),
		WGKeysRegenInerval: p.Session.WGKeysRegenInerval, // keep 'WGKeysRegenInerval' from previous Session object
		DeviceID:           deviceID}

	if p.Session.WGKeysRegenInerval <= 0 {
		p.Session.WGKeysRegenInerval = DefaultWGKeysInterval
	}

	p.Session.updateWgCredentials(wgPublicKey, wgPrivateKey, wgLocalIP, wgPreSharedKey)
}

// compareVersions compares two version strings in the format "XX.XX.XX..."
// and returns -1 if version1 is older, 1 if version1 is newer,
// and 0 if both versions are equal.
func compareVersions(version1, version2 string) int {
	v1Parts := strings.Split(version1, ".")
	v2Parts := strings.Split(version2, ".")

	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		v1Part, _ := strconv.Atoi(v1Parts[i])
		v2Part, _ := strconv.Atoi(v2Parts[i])

		if v1Part < v2Part {
			return -1
		} else if v1Part > v2Part {
			return 1
		}
	}

	if len(v1Parts) < len(v2Parts) {
		return -1
	} else if len(v1Parts) > len(v2Parts) {
		return 1
	}

	return 0
}
