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

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/hashicorp/go-envparse"
	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

var (
	firewallScript string
	splitTunScript string
	logDir         string = "/var/log/privateline"
	tmpDir         string = "/etc/opt/privateline-connect/mutable"

	// path to 'resolvectl' binary
	resolvectlBinPath string

	// path to the readonly servers.json file bundled into the package
	serversFileBundled string

	resolvectlPlInternalDomains = []string{"~privateline.io", "~privateline.network", "~privateline.dev"}

	PrivatelineInternalDomainsResolvectlRegex = regexp.MustCompile(`(?i)[\s]+DNS Domain:[\s]+~privateline.io[\s]+~privateline.network[\s]+~privateline.dev`)
)

const (
	// Optionally, user can enable the ability to manage the '/etc/resolv.conf' file from SNAP environment.
	// This can be useful in situations where the host machine does not use 'systemd-resolved'.
	// In this case, the daemon may attempt to directly modify this file.
	// Note: This is not recommended!
	// Command for user to connect required slot:   $ sudo snap connect privateline:etc-resolv-conf
	snapPlugNameResolvconfAccess string = "etc-resolv-conf"
	etcOsReleasePath                    = "/etc/os-release"
)

// SnapEnvInfo contains values of SNAP environment variables
// (applicable only if running in SNAP)
// https://snapcraft.io/docs/environment-variables
type SnapEnvInfo struct {
	// Directory where the snap is mounted. This is where all the files in your snap are visible in the filesystem.
	// All of the data in the snap is read-only and cannot be changed.
	SNAP string
	// Directory for system data that is common across revisions of a snap.
	// This directory is owned and writable by root and is meant to be used by background applications (daemons, services).
	// Unlike SNAP_DATA this directory is not backed up and restored across snap refresh and revert operations.
	SNAP_COMMON string
	// Directory for system data of a snap.
	// This directory is owned and writable by root and is meant to be used by background applications (daemons, services).
	// Unlike SNAP_COMMON this directory is backed up and restored across snap refresh and snap revert operations.
	SNAP_DATA string
}

// GetSnapEnvs returns SNAP environment variables (or nil if we are running not in snap)
func GetSnapEnvs() *SnapEnvInfo {
	snap := os.Getenv("SNAP")
	snapCommon := os.Getenv("SNAP_COMMON")
	snapData := os.Getenv("SNAP_DATA")
	if len(snap) == 0 || len(snapCommon) == 0 || len(snapData) == 0 {
		return nil
	}
	if ex, err := os.Executable(); err == nil && len(ex) > 0 {
		if !strings.HasPrefix(ex, snap) {
			// if snap environment - the binary must be located in "$SNAP"
			return nil
		}
	}

	return &SnapEnvInfo{
		SNAP:        snap,
		SNAP_COMMON: snapCommon,
		SNAP_DATA:   snapData,
	}
}

func IsSnapAbleManageResolvconf() (allowed bool, userErrMsgIfNotAllowed string, err error) {
	allowed, err = isSnapPlugConnected(snapPlugNameResolvconfAccess)
	if err != nil {
		return allowed, "", err
	}

	if !allowed {
		userErrMsgIfNotAllowed = fmt.Sprintf(
			"It appears that you are running the privateLINE snap package on a host system that does not utilize the 'systemd-resolved' DNS resolver, which is required.\n\n"+
				"As a workaround, you can grant privateLINE permission to modify '/etc/resolv.conf' directly by using the command:\n'$ sudo snap connect privateline:%s'", snapPlugNameResolvconfAccess)
	}
	return allowed, userErrMsgIfNotAllowed, err
}

func isSnapPlugConnected(plugName string) (bool, error) {
	_, outErrText, exitCode, isBufferTooSmall, err := shell.ExecAndGetOutput(nil, 512, "", "snapctl", "is-connected", plugName)
	if exitCode == 0 {
		return true, nil
	}
	if exitCode < 0 && err != nil {
		return false, fmt.Errorf("error checking connected snap plug: %w", err)
	}
	if len(outErrText) > 0 {
		if isBufferTooSmall {
			outErrText += "..."
		}
		return false, fmt.Errorf(outErrText)
	}
	return false, nil
}

// initialize all constant values (e.g. servicePortFile) which can be used in external projects (i.e., privateline-connect-cli)
func doInitConstants() {
	wgInterfaceName = "wgprivateline"

	openVpnBinaryPath = "/usr/sbin/openvpn"
	routeCommand = "/sbin/ip route"

	// check if we are running in snap environment
	if envs := GetSnapEnvs(); envs != nil {
		// Note! Changing 'tmpDir' value may break upgrade compatibility with old versions (e.g. lose account login information)
		logDir = path.Join(envs.SNAP_COMMON, "/opt/privateline-connect/log")
		tmpDir = path.Join(envs.SNAP_COMMON, "/opt/privateline-connect/mutable")
		openVpnBinaryPath = path.Join(envs.SNAP, openVpnBinaryPath)
	}

	serversFile = path.Join(tmpDir, "servers.json")
	servicePortFile = path.Join(tmpDir, "port.txt")
	paranoidModeSecretFile = path.Join(tmpDir, "eaa")

	logFile = path.Join(logDir, helpers.ServiceName+".log")

	openvpnUserParamsFile = path.Join(tmpDir, "ovpn_extra_params.txt")

	wgDefaultMtu = 1380 // reasonable default for MTU on Linux
}

// TODO FIXME: Vlad: doOsInit() gets called only once on daemon start
//   - likewise here have to re-check before each connection whether we can run resolvectl (after we brought up our firewall rule to allow all port 53 traffic)
//   - also here may be a good place to check whether /etc/resolv.conf is a file or a symlink
func doOsInit() (warnings []string, errors []error, logInfo []string) {
	warnings, errors, logInfo = doOsInitForBuild()

	if errors == nil {
		errors = make([]error, 0)
	}

	if logInfo == nil {
		logInfo = make([]string, 0)
	}

	if warnings == nil {
		warnings = make([]string, 0)
	}

	// get path to resolvectl
	if p, err := exec.LookPath("resolvectl"); err == nil {
		if p, err = filepath.Abs(p); err == nil {
			if err := checkFileAccessRightsExecutable("resolvectlBinPath", p); err != nil {
				warnings = append(warnings, err.Error())
			} else {
				resolvectlBinPath = p
			}
		}
	}
	if len(resolvectlBinPath) > 0 {
		// Check if 'resolvectl status' command works without issues.
		// If there is an issue - probably resolvectl is not applicable for this system
		// (e.g. systemd-resolved service is not configured)
		if err := exec.Command(resolvectlBinPath).Run(); err != nil {
			logInfo = append(logInfo, "'resolvectl' is detected but it is failed to run status command: ", err.Error())
			resolvectlBinPath = ""
		} else {
			logInfo = append(logInfo, "'resolvectl' detected: "+resolvectlBinPath)
		}
	} else {
		logInfo = append(logInfo, "'resolvectl' not detected.")
	}

	if err := checkFileAccessRightsExecutable("firewallScript", firewallScript); err != nil {
		errors = append(errors, err)
	}
	if err := checkFileAccessRightsExecutable("splitTunScript", splitTunScript); err != nil {
		errors = append(errors, err)
	}

	if err := parseOsVersion(); err != nil {
		warnings = append(warnings, fmt.Errorf("error parsing OS version: %w", err).Error())
	}

	return warnings, errors, logInfo
}

func doInitOperations() (w string, e error) {
	serversFile := ServersFile()
	if _, err := os.Stat(serversFile); err != nil {
		if os.IsNotExist(err) {
			if len(serversFileBundled) == 0 {
				return fmt.Sprintf("'%s' not exists and the 'serversFileBundled' path not defined", serversFile), nil
			}

			srcStat, err := os.Stat(serversFileBundled)
			if err != nil {
				return fmt.Sprintf("'%s' not exists and the serversFileBundled='%s' access error: %s", serversFile, serversFileBundled, err.Error()), nil
			}

			fmt.Printf("File '%s' does not exists. Copying from bundle (%s)...\n", serversFile, serversFileBundled)
			// Servers file is not exists on required place
			// Probably, it is first start after clean install
			// Copying it from a bundle
			os.MkdirAll(filepath.Base(serversFile), os.ModePerm)
			if err = helpers.CopyFile(serversFileBundled, serversFile); err != nil {
				return err.Error(), nil
			}

			// keep file mode same as source file
			err = os.Chmod(serversFile, srcStat.Mode())
			if err != nil {
				return err.Error(), nil
			}

			return "", nil
		}

		return err.Error(), nil
	}
	return "", nil
}

// FirewallScript returns path to firewal script
func FirewallScript() string {
	return firewallScript
}

// SplitTunScript returns path to script which control split-tunneling functionality
func SplitTunScript() string {
	return splitTunScript
}

func ResolvectlDetected() bool {
	return resolvectlBinPath != ""
}

func ResolvectlBinPath() string {
	return resolvectlBinPath
}

func implPLOtherAppsToAcceptIncomingConnections() (otherPlApps []string, err error) {
	return []string{}, nil // Vlad - on Linux the list of PL apps is implemented in firewall-helper.sh so far
}

func parseOsVersion() (err error) {
	var (
		etcOsRelease map[string]string
		ok           bool
	)

	if etcOsReleaseFile, err := os.Open(etcOsReleasePath); err != nil {
		return fmt.Errorf("error opening file '%s': %w", etcOsReleasePath, err)
	} else if etcOsRelease, err = envparse.Parse(etcOsReleaseFile); err != nil {
		return fmt.Errorf("error parsing file '%s': %w", etcOsReleasePath, err)
	}

	if osVersion, ok = etcOsRelease["PRETTY_NAME"]; ok {
		return nil
	} else if osVersion, ok = etcOsRelease["NAME"]; ok {
		return nil
	} else {
		osVersion = runtime.GOOS
		return nil
	}
}

// to be used on Linux by command: resolvectl domain wgprivateline \~domain1 \~domain2 ...
func PrivatelineInternalDomains() *[]string {
	return &resolvectlPlInternalDomains
}
