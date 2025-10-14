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

//go:build linux
// +build linux

package dns

import (
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/swapnilsparsh/devsVPN/daemon/service/dns/dnscryptproxy"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
)

// For reference: DNS configuration in Linux
//
//	https://github.com/systemd/systemd/blob/main/docs/RESOLVED-VPNS.md
//	https://blogs.gnome.org/mcatanzaro/2020/12/17/understanding-systemd-resolved-split-dns-and-vpn-configuration/
func isResolveCtlAvail() bool {
	return len(platform.ResolvectlBinPath()) > 0
}

var (
	isResolvectlInUse  bool
	f_implInitialize   func() error
	f_implPause        func(localInterfaceIP net.IP) error
	f_implResume       func(localInterfaceIP net.IP) error
	f_implSetManual    func(dnsCfg DnsSettings, localInterfaceIP net.IP) (dnsInfoForFirewall DnsSettings, retErr error)
	f_implDeleteManual func(localInterfaceIP net.IP) error
)

var (
	isPaused  bool = false
	manualDNS DnsSettings
)

func init() {
	err := fmt.Errorf("DNS functionality not initialised")
	f_implInitialize = func() error { return err }
	f_implPause = func(localInterfaceIP net.IP) error { return err }
	f_implResume = func(localInterfaceIP net.IP) error { return err }
	f_implSetManual = func(dnsCfg DnsSettings, localInterfaceIP net.IP) (DnsSettings, error) { return DnsSettings{}, err }
	f_implDeleteManual = func(localInterfaceIP net.IP) error { return err }
}

// implInitialize doing initialization stuff
// it's called both:
//   - on daemon start
//   - and at the beginning of each connection by Service.connect() in service_connect.go
//
// TODO: Vlad - will we need to reconfigure DNS mgmt to-from old-style and resolvectl in the middle of connection, checked by vpnCoexistence_linux.go?
//   - if yes, we'll need locking
func implInitialize() error {
	if willUseResolvectl, err := WillUseResolvectlForDnsMgmt(); err != nil {
		return log.ErrorFE("error WillUseResolvectl(): %w", err) // TODO: FIXME: Vlad - or just ignore errors and force old-style DNS management on errors?
	} else if willUseResolvectl {
		// new management style: using 'resolvectl'
		f_implInitialize = rctl_implInitialize
		f_implPause = rctl_implPause
		f_implResume = rctl_implResume
		f_implSetManual = rctl_implSetManual
		f_implDeleteManual = rctl_implDeleteManual
		isResolvectlInUse = true
		log.Info("Initialized DNS management: resolvectl in use")
	} else {
		// old management style: direct modifying '/etc/resolv.conf'
		f_implInitialize = rconf_implInitialize
		f_implPause = rconf_implPause
		f_implResume = rconf_implResume
		f_implSetManual = rconf_implSetManual
		f_implDeleteManual = rconf_implDeleteManual
		isResolvectlInUse = false
		log.Info("Initialized old-style DNS management: direct modification of '/etc/resolv.conf'")
	}

	return f_implInitialize()
}

// On Linux we prefer to use resolvectl, if we can - but all the conditions have to be met
func WillUseResolvectlForDnsMgmt() (willUseResolvectl bool, retErr error) {
	if !isResolveCtlAvail() { // do we have resolvectl and does it work?
		// log.Debug("isResolveCtlAvail() == false")
		return false, nil
	}

	if funcGetUserSettings != nil && funcGetUserSettings().Linux_IsDnsMgmtOldStyle { // if old-style DNS management is specified by user preferences - follow that
		log.Debug("Linux_IsDnsMgmtOldStyle == true")
		return false, nil
	}

	fi, err := os.Lstat("/etc/resolv.conf") // check whether /etc/resolv.conf is a file, or symlink, or neither/absent
	if err != nil {
		return false, log.ErrorFE("error os.Lstat /etc/resolv.conf: %w", err)
	}

	switch mode := fi.Mode(); {
	case mode.IsRegular():
		log.Debug("/etc/resolv.conf is a regular file, so use old-style DNS management")
		return false, nil // /etc/resolv.conf is a regular file, so use old-style DNS management
	case mode&fs.ModeSymlink != 0:
		log.Debug("/etc/resolv.conf is a symlink, so use resolvectl")
		return true, nil // TODO: check whether it's a symlink to /run/systemd/resolve/stub-resolv.conf or similar systemd-resolved path
	default:
		return false, fmt.Errorf("error - /etc/resolv.conf has unexpected mode 0x%x", fi.Mode())
	}
}

func implApplyUserSettings() error {
	// checking if the required settings is already initialized
	if willUseResolvectl, err := WillUseResolvectlForDnsMgmt(); err != nil {
		return log.ErrorFE("error WillUseResolvectl(): %w", err)
	} else if willUseResolvectl == isResolvectlInUse {
		return nil // expected configuration already applied
	}

	// if DNS changed to a custom value - we have to restore the original DNS settings before changing the DNS management style
	if !manualDNS.IsEmpty() {
		return fmt.Errorf("unable to apply new DNS management style: DNS currently changed to a custom value")
	}
	return implInitialize() // nothing to do here for current platform
}

func implGetDnsEncryptionAbilities() (dnsOverHttps, dnsOverTls bool, err error) {
	return true, false, nil
}
func implGetPredefinedDnsConfigurations() ([]DnsSettings, error) {
	return []DnsSettings{}, nil
}

func implPause(localInterfaceIP net.IP) error {
	dnscryptproxy.Stop()
	isPaused = true
	return f_implPause(localInterfaceIP)
}

func implResume(defaultDNS DnsSettings, localInterfaceIP net.IP) error {
	isPaused = false

	if !manualDNS.IsEmpty() {
		// set manual DNS (if defined)
		_, err := f_implSetManual(manualDNS, localInterfaceIP)
		return err
	}

	if !defaultDNS.IsEmpty() {
		_, err := f_implSetManual(defaultDNS, localInterfaceIP)
		return err
	}

	return f_implResume(localInterfaceIP)
}

// Set manual DNS.
func implSetManual(dnsCfg DnsSettings, localInterfaceIP net.IP) (dnsInfoForFirewall DnsSettings, retErr error) {
	defer func() {
		if retErr != nil {
			dnscryptproxy.Stop()
		}
	}()

	// keep info about current manual DNS configuration (can be used for pause/resume/restore)
	manualDNS = dnsCfg

	dnscryptproxy.Stop()

	if isPaused {
		// in case of PAUSED state -> just save manualDNS config
		// it will be applied on RESUME
		return dnsCfg, nil
	}

	// start encrypted DNS configuration (if required)
	if !dnsCfg.IsEmpty() && dnsCfg.Encryption != EncryptionNone {
		if err := dnscryptProxyProcessStart(dnsCfg); err != nil {
			return DnsSettings{}, err
		}
		// the local DNS must be configured to the dnscrypt-proxy (localhost)
		dnsCfg = DnsSettings{DnsServers: []net.IP{net.ParseIP("127.0.0.1")}}
	}

	return f_implSetManual(dnsCfg, localInterfaceIP)
}

// DeleteManual - reset manual DNS configuration to default
// 'localInterfaceIP' (obligatory only for Windows implementation) - local IP of VPN interface
func implDeleteManual(localInterfaceIP net.IP) error {
	manualDNS = DnsSettings{}
	dnscryptproxy.Stop()

	if isPaused {
		// in case of PAUSED state -> just save manualDNS config
		// it will be applied on RESUME
		return nil
	}

	return f_implDeleteManual(localInterfaceIP)
}

// UpdateDnsIfWrongSettings - ensures that current DNS configuration is correct. If not - it re-apply the required configuration.
func implUpdateDnsIfWrongSettings() error {
	// Not in use for Linux implementation
	// We are using platform-specific implementation of DNS change monitor for Linux
	return nil
}

func implDnsMgmtStyleInUse() DnsMgmtStyle {
	if isResolvectlInUse {
		return DnsMgmtStyleResolvectl
	} else {
		return DnsMgmtStyleResolveConf
	}
}
