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
	"net"
	"os"
	"regexp"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

// For reference: DNS configuration in Linux
// 	https://github.com/systemd/systemd/blob/main/docs/RESOLVED-VPNS.md
// 	https://blogs.gnome.org/mcatanzaro/2020/12/17/understanding-systemd-resolved-split-dns-and-vpn-configuration/

var (
	rctl_dnsChange_chan_done chan struct{}
	rctl_localInterfaceIp    net.IP
)

func rctl_implInitialize() error {
	rctl_dnsChange_chan_done = make(chan struct{})
	return nil
}

func rctl_implPause(localInterfaceIP net.IP) error {
	rctl_stopDnsChangeMonitor()

	inf, err := netinfo.InterfaceByIPAddr(localInterfaceIP)
	if err != nil {
		return nil // seems the interface not created. Nothing to resume
	}
	localInterfaceName := inf.Name

	binPath := platform.ResolvectlBinPath()
	err = shell.Exec(log, binPath, "domain", localInterfaceName, "")
	if err != nil {
		return rctl_error(err)
	}
	err = shell.Exec(log, binPath, "default-route", localInterfaceName, "false")
	if err != nil {
		return rctl_error(err)
	}

	return nil
}

func rctl_implResume(localInterfaceIP net.IP) error {
	inf, err := netinfo.InterfaceByIPAddr(localInterfaceIP)
	if err != nil {
		return rctl_error(err)
	}
	localInterfaceName := inf.Name

	binPath := platform.ResolvectlBinPath()
	err = shell.Exec(log, binPath, "domain", localInterfaceName, "~.")
	if err != nil {
		return rctl_error(err)
	}
	err = shell.Exec(log, binPath, "default-route", localInterfaceName, "true")
	if err != nil {
		return rctl_error(err)
	}

	rctl_startDnsChangeMonitor()

	return nil
}

// Set manual DNS.
func rctl_implSetManual(dnsCfg DnsSettings, localInterfaceIP net.IP) (dnsInfoForFirewall DnsSettings, retErr error) {
	rctl_stopDnsChangeMonitor() // stop monitoring
	defer func() {
		if retErr == nil {
			rctl_startDnsChangeMonitor() // if success - start monitoring
		}
	}()
	rctl_localInterfaceIp = localInterfaceIP
	return rctl_applySetManual(dnsCfg, localInterfaceIP)
}

func rctl_applySetManual(dnsCfg DnsSettings, localInterfaceIP net.IP) (dnsInfoForFirewall DnsSettings, retErr error) {
	if localInterfaceIP == nil || localInterfaceIP.IsUnspecified() {
		log.Info("'Set DNS' call ignored due to no local address initialized")
		return dnsCfg, nil
	}
	inf, err := netinfo.InterfaceByIPAddr(localInterfaceIP)
	if err != nil {
		return DnsSettings{}, rctl_error(err)
	}
	localInterfaceName := inf.Name

	binPath := platform.ResolvectlBinPath()
	if err = shell.Exec(log, binPath, "default-route", localInterfaceName, "true"); err != nil {
		return DnsSettings{}, rctl_error(err)
	}
	// resolvectl dns wgprivateline <dnsSrv1> <dnsSrv1> ...
	resolvectlDnsCmdArgs := append([]string{"dns", localInterfaceName})
	for _, dnsSrvIP := range dnsCfg.DnsServers {
		resolvectlDnsCmdArgs = append(resolvectlDnsCmdArgs, dnsSrvIP.String())
	}
	if err = shell.Exec(log, binPath, resolvectlDnsCmdArgs...); err != nil {
		return DnsSettings{}, rctl_error(err)
	}
	// resolvectl domain wgprivateline \~domain1 \~domain2 ...
	resolvectlDomainCmdArgs := append([]string{"domain", localInterfaceName}, *platform.PrivatelineInternalDomains()...)
	if err = shell.Exec(log, binPath, resolvectlDomainCmdArgs...); err != nil {
		return DnsSettings{}, rctl_error(err)
	}

	return dnsCfg, nil
}

// DeleteManual - reset manual DNS configuration to default
func rctl_implDeleteManual(localInterfaceIP net.IP) error {
	rctl_stopDnsChangeMonitor()
	return rctl_implPause(localInterfaceIP)
}

func rctl_error(err error) error {
	return fmt.Errorf("failed to change DNS configuration: %w", err)
}

func rctl_stopDnsChangeMonitor() {
	// stop file change monitoring
	select {
	case rctl_dnsChange_chan_done <- struct{}{}:
		break
	default:
		break
	}
}

func rctl_startDnsChangeMonitor() {
	go func() {
		rctl_stopDnsChangeMonitor()

		if rctl_localInterfaceIp.IsUnspecified() || manualDNS.IsEmpty() {
			log.Warning(fmt.Sprintf("unable to start DNS-change monitoring: dns configuration is not defined"))
			return
		}

		// Files to be monitored for changes
		var filesToMonotor = [...]string{"/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}

		w, err := fsnotify.NewWatcher()
		if err != nil {
			log.Error(fmt.Errorf("failed to start DNS-change monitoring (fsnotify error): %w", err))
			return
		}

		log.Info("DNS-change monitoring start")
		defer func() {
			log.Info("DNS-change monitoring stopped")
			w.Close()
		}()

		for {
			// Remove files from monitoring (if they are)
			// We have to remove/add files each time after file change detection
			for _, fpath := range filesToMonotor {
				w.Remove(fpath)
			}
			// Start looking for files change
			isMonitoringStarted := false
			for _, fpath := range filesToMonotor {
				if _, err := os.Stat(fpath); err != nil {
					log.Info(fmt.Sprintf("unable to start file-change monitoring for file '%s': %s", fpath, err.Error()))
				} else {
					err = w.Add(fpath)
					if err != nil {
						log.Error(fmt.Errorf("failed to start file-change monitoring for file '%s'(fsnotify error): %w", fpath, err))
						continue
					}
					isMonitoringStarted = true
				}
			}
			if !isMonitoringStarted {
				log.Warning("DNS-change monitoring NOT started (nothing to monitor)")
				return
			}

			// wait for changes
			var evt fsnotify.Event
			select {
			case evt = <-w.Events:
			case <-rctl_dnsChange_chan_done:
				// monitoring stopped
				return
			}

			// wait 2 seconds for reaction (needed to avoid multiple reactions on the changes in short period of time)
			select {
			case <-time.After(time.Second * 2):
			case <-done:
				// monitoring stopped
				return
			}

			if isPaused {
				continue
			}

			// check is DNS config is OK
			isOk, err := rctl_configOk()
			if err != nil {
				log.Error(fmt.Errorf("DNS-change monitoring failed to check configuration: %w", err))
				continue
			}
			if isOk {
				continue
			}

			log.Info(fmt.Sprintf("DNS-change monitoring: DNS was changed outside [%s]. Restoring ...", evt.String()))
			if _, err = rctl_applySetManual(manualDNS, rctl_localInterfaceIp); err != nil {
				log.Error(rctl_error(err))
			}

		}
	}()
}

// rctl_configOk - returns true if OS DNS configuration ie expected for VPN interface
func rctl_configOk() (bool, error) {
	// Example of 'resolvectl status wgprivateline' output:
	// Link 11 (wgprivateline)
	//	Current Scopes: DNS
	//	Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
	//	Current DNS Server: 10.0.19.2
	//	DNS Servers: 10.0.19.2 10.0.20.2
	//	DNS Domain: privateline.network privateline.io privateline.dev
	if rctl_localInterfaceIp == nil || rctl_localInterfaceIp.IsUnspecified() || manualDNS.IsEmpty() {
		return false, fmt.Errorf("unable to check/compare OS DNS settings for the VPN interface: expected DNS configuration is not defined")
	}

	inf, err := netinfo.InterfaceByIPAddr(rctl_localInterfaceIp)
	if err != nil {
		return false, fmt.Errorf("unable to check/compare OS DNS settings for the VPN interface: %w", err)
	}
	localInterfaceName := inf.Name

	binPath := platform.ResolvectlBinPath()
	outText, _, _, _, _ := shell.ExecAndGetOutput(nil, 1024*5, "", binPath, "status", localInterfaceName)

	// TODO FIXME: Vlad - precompile regex for DNS servers in Preferences
	var dnsServersRegex string
	for _, dnsSrvIP := range manualDNS.DnsServers {
		dnsServersRegex += " " + dnsSrvIP.String()
	}
	// regExpCurDns, err := regexp.Compile(fmt.Sprintf("(?i)[ \t\n\r]+DNS Servers:[ \t]*%s[ \t\n\r]+", manualDNS.DnsServers))
	regExpCurDns, err := regexp.Compile(`(?i)[\s]+DNS Servers:[\s]*` + dnsServersRegex)
	if err != nil {
		return false, err
	}

	return regExpCurDns.MatchString(outText) && platform.PrivatelineInternalDomainsResolvectlRegex.MatchString(outText), nil
}
