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

package platform

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

var (
	wfpDllPath           string
	nativeHelpersDllPath string
	splitTunDriverPath   string
)

func doInitConstants() {
	doInitConstantsForBuild()

	installDir := getInstallDir()
	if len(servicePortFile) <= 0 {
		servicePortFile = path.Join(installDir, "etc/port.txt")
	} else {
		// debug version can have different port file value
		fmt.Println("!!! WARNING !!! Non-standard service port file: ", servicePortFile)
	}

	logFile = path.Join(installDir, "log/privateline-connect-svc.log")

	openvpnUserParamsFile = path.Join(installDir, "mutable/ovpn_extra_params.txt")
	paranoidModeSecretFile = path.Join(installDir, "etc/eaa") // file located in 'etc' will not be removed during app upgrade

	// Set default MTU to 1280 - minimum value allowed on Windows
	// According to Windows specification: "... For IPv4 the minimum value is 576 bytes. For IPv6 the minimum value is 1280 bytes... "
	wgDefaultMtu = 1280
}

func doOsInit() (warnings []string, errors []error, logInfo []string) {
	SYSTEMROOT := os.Getenv("SYSTEMROOT")
	if len(SYSTEMROOT) > 0 {
		routeCommand = strings.ReplaceAll(path.Join(SYSTEMROOT, "System32", "ROUTE.EXE"), "/", "\\")
	}

	doOsInitForBuild()
	_installDir := getInstallDir()

	_archDir := "x86_64"
	if !Is64Bit() {
		_archDir = "x86"
	}

	if warnings == nil {
		warnings = make([]string, 0)
	}
	if errors == nil {
		errors = make([]error, 0)
	}

	var (
		outErrText       string
		isBufferTooSmall bool
		err              error
	)
	cmdPath := strings.ReplaceAll(path.Join(SYSTEMROOT, "System32", "CMD.EXE"), "/", "\\")
	if osVersion, outErrText, _, isBufferTooSmall, err = shell.ExecAndGetOutput(nil, 1024*30, "", cmdPath, "ver"); err != nil {
		warnings = append(warnings, fmt.Errorf("error getting Windows version: '%s' isBufferTooSmall=%t : %w", outErrText, isBufferTooSmall, err).Error())
	}
	if osVersion == "" {
		osVersion = runtime.GOOS
	}

	// common variables initialization
	settingsDir := getEtcDir()
	settingsDirCommon := getEtcDirCommon()

	if settingsDir != settingsDirCommon {
		fmt.Printf("!!! DEBUG VERSION? !!! extra 'etc' folder    : '%s'\n", settingsDirCommon)
	}

	settingsFile = path.Join(settingsDir, "settings.json")

	serversFile = path.Join(settingsDirCommon, "servers.json")
	openvpnConfigFile = path.Join(settingsDir, "openvpn.cfg")
	openvpnProxyAuthFile = path.Join(settingsDir, "proxyauth.txt")
	wgConfigFilePath = path.Join(settingsDir, "privateLINE.conf") // will be used also for WireGuard service name (e.g. "WireGuardTunnel$privateLINE")

	openVpnBinaryPath = path.Join(_installDir, "OpenVPN", _archDir, "openvpn.exe")
	openvpnCaKeyFile = path.Join(settingsDirCommon, "ca.crt")
	openvpnTaKeyFile = path.Join(settingsDirCommon, "ta.key")
	openvpnUpScript = ""
	openvpnDownScript = ""

	obfsproxyStartScript = path.Join(_installDir, "OpenVPN", "obfsproxy", "obfs4proxy.exe")

	v2rayBinaryPath = path.Join(_installDir, "v2ray", "v2ray.exe")
	v2rayConfigTmpFile = path.Join(settingsDir, "v2ray.json")

	_wgArchDir := "x86_64"
	if _, err := os.Stat(path.Join(_installDir, "WireGuard", _wgArchDir, "wireguard.exe")); err != nil {
		_wgArchDir = "x86"
		if _, err := os.Stat(path.Join(_installDir, "WireGuard", _wgArchDir, "wireguard.exe")); err != nil {
			errors = append(errors, fmt.Errorf("unable to find WireGuard binary: %s ..<x86_64\\x86>", path.Join(_installDir, "WireGuard")))
		}
	}
	wgBinaryPath = path.Join(_installDir, "WireGuard", _wgArchDir, "wireguard.exe")
	wgToolBinaryPath = path.Join(_installDir, "WireGuard", _wgArchDir, "wg.exe")

	plCommsBinaryPath = "privateLINE-Comms.exe"

	dnscryptproxyBinPath = path.Join(_installDir, "dnscrypt-proxy/dnscrypt-proxy.exe")
	dnscryptproxyConfigTemplate = path.Join(settingsDirCommon, "dnscrypt-proxy-template.toml")
	dnscryptproxyConfig = path.Join(_installDir, "dnscrypt-proxy/dnscrypt-proxy.toml")
	dnscryptproxyLog = path.Join(_installDir, "dnscrypt-proxy/dnscrypt-proxy.log")

	kemHelperBinaryPath = path.Join(_installDir, "kem/kem-helper.exe")

	if _, err := os.Stat(wfpDllPath); err != nil {
		errors = append(errors, fmt.Errorf("file not exists: '%s'", wfpDllPath))
	}
	if _, err := os.Stat(nativeHelpersDllPath); err != nil {
		errors = append(errors, fmt.Errorf("file not exists: '%s'", nativeHelpersDllPath))
	}
	if _, err := os.Stat(splitTunDriverPath); err != nil {
		warnings = append(warnings, fmt.Errorf("file not exists: '%s'", splitTunDriverPath).Error())
	}

	return warnings, errors, logInfo
}

func getEtcDir() string {
	return path.Join(getInstallDir(), "etc")
}

func doInitOperations() (w string, e error) {
	return "", nil
}

// WindowsWFPDllPath - Path to Windows DLL with helper methods for WFP (Windows Filtering Platform)
func WindowsWFPDllPath() string {
	return wfpDllPath
}

// WindowsNativeHelpersDllPath - Path to Windows DLL with helper methods (native DNS implementation... etc.)
func WindowsNativeHelpersDllPath() string {
	return nativeHelpersDllPath
}

// WindowsSplitTunnelDriverPath - path to *.sys binary of Split-Tunnel driver
func WindowsSplitTunnelDriverPath() string {
	return splitTunDriverPath
}

func getPLCommsPaths() (plCommsPaths []string, err error) {
	// PL Comms exe has path like:	c:\Users\User\AppData\Local\privateline-comms-desktop\app-1.11.71\privateLINE-Comms.exe

	// %PUBLIC% resolves to c:\Users\Public
	Public := os.Getenv("PUBLIC")
	if len(Public) <= 0 {
		return []string{}, errors.New("error looking up environment variable %PUBLIC%")
	}

	return filepath.Glob(Public + "/../*/AppData/Local/p*-comms-desktop/app-*/*Comms.exe")
}

func implPLOtherAppsToAcceptIncomingConnections() (otherPlApps []string, err error) {
	return getPLCommsPaths()
}
