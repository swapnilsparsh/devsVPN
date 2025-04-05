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

//go:build darwin && !debug
// +build darwin,!debug

package platform

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/swapnilsparsh/devsVPN/daemon/service/platform/filerights"
)

const (
	serversFileBundled = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/servers.json"
)

func doOsInitForBuild() (warnings []string, errors []error) {
	// macOS-specific variable initialization
	firewallScript = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/firewall.sh"
	dnsScript = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/dns.sh"

	// common variables initialization
	settingsDir := "/Library/Application Support/privateLINE-Connect"
	settingsFile = path.Join(settingsDir, "settings.json")
	serversFile = path.Join(settingsDir, "servers.json")
	openvpnConfigFile = path.Join(settingsDir, "openvpn.cfg")
	openvpnProxyAuthFile = path.Join(settingsDir, "proxyauth.txt")
	wgConfigFilePath = path.Join(settingsDir, "wgprivateline.conf")

	openVpnBinaryPath = "/Applications/privateLINE-Connect.app/Contents/MacOS/openvpn"
	openvpnCaKeyFile = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/ca.crt"
	openvpnTaKeyFile = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/ta.key"
	openvpnUpScript = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/dns.sh -up"
	openvpnDownScript = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/dns.sh -down"

	obfsproxyStartScript = "/Applications/privateLINE-Connect.app/Contents/Resources/obfsproxy/obfs4proxy"

	v2rayBinaryPath = "/Applications/privateLINE-Connect.app/Contents/MacOS/v2ray/v2ray"
	v2rayConfigTmpFile = path.Join(settingsDir, "v2ray.json")

	wgBinaryPath = "/Applications/privateLINE-Connect.app/Contents/MacOS/WireGuard/wireguard-go"
	wgToolBinaryPath = "/Applications/privateLINE-Connect.app/Contents/MacOS/WireGuard/wg"

	dnscryptproxyBinPath = "/Applications/privateLINE-Connect.app/Contents/MacOS/dnscrypt-proxy/dnscrypt-proxy"
	dnscryptproxyConfigTemplate = "/Applications/privateLINE-Connect.app/Contents/Resources/etc/dnscrypt-proxy-template.toml"
	dnscryptproxyConfig = path.Join(settingsDir, "dnscrypt-proxy.toml")

	kemHelperBinaryPath = "/Applications/privateLINE-Connect.app/Contents/MacOS/kem/kem-helper"

	return nil, nil
}

func doInitOperations() (w string, e error) {
	serversFile := ServersFile()
	if _, err := os.Stat(serversFile); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("File '%s' does not exists. Copying from bundle...\n", serversFile)
			// Servers file is not exists on required place
			// Probably, it is first start after clean install
			// Copying it from a bundle
			os.MkdirAll(filepath.Base(serversFile), os.ModePerm)
			if _, err = copyFile(serversFileBundled, serversFile); err != nil {
				return err.Error(), nil
			}
			return "", nil
		}

		return err.Error(), nil
	}
	return "", nil
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	destination.Chmod(filerights.DefaultFilePermissionsForConfig())
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}
