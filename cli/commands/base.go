//
//  IVPN command line interface (CLI)
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the IVPN command line interface.
//
//  The IVPN command line interface is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The IVPN command line interface is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the IVPN command line interface. If not, see <https://www.gnu.org/licenses/>.
//

package commands

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/swapnilsparsh/devsVPN/cli/cliplatform"
	"github.com/swapnilsparsh/devsVPN/cli/protocol"
	apitypes "github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/dns"
	"github.com/swapnilsparsh/devsVPN/daemon/splittun"
	"github.com/swapnilsparsh/devsVPN/daemon/v2r"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
)

var _proto *protocol.Client

// Initialize initializes commands. Must be called before using any command.
func Initialize(proto *protocol.Client) {
	_proto = proto
}

func printAccountInfo(w *tabwriter.Writer, accountID string) *tabwriter.Writer {
	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	if len(accountID) > 0 {
		return w // Do nothing in case of logged in
	}

	fmt.Fprintf(w, "Account\t:\t%v", "Not logged in\n")

	return w
}

func printState(w *tabwriter.Writer, state vpn.State, connected types.ConnectedResp, serverInfo string, exitServerInfo string, helloResp types.HelloResp) *tabwriter.Writer {

	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	stateStr := fmt.Sprintf("%v", state)

	if state == vpn.CONNECTED && connected.IsPaused {
		stateStr = "PAUSED"
		if len(connected.PausedTill) > 0 {
			if t, err := time.Parse(time.RFC3339, connected.PausedTill); err == nil {
				stateStr += fmt.Sprintf(" till %v", t)
			}
		}
	}

	fmt.Fprintf(w, "VPN\t:\t%v\n", stateStr)

	if len(serverInfo) > 0 {
		fmt.Fprintf(w, "\t\t%v\n", serverInfo)
		if len(exitServerInfo) > 0 {
			fmt.Fprintf(w, "\t\t%v (Multi-Hop exit server)\n", exitServerInfo)
		}
	}

	if state != vpn.CONNECTED {
		return w
	}
	since := time.Unix(connected.TimeSecFrom1970, 0)

	protocol := fmt.Sprintf("%v", connected.VpnType)
	if connected.V2RayProxy != v2r.None {
		protocol += fmt.Sprintf(" (V2Ray: VMESS/%s)", connected.V2RayProxy.ToString())
	} else if connected.VpnType == vpn.OpenVPN {
		if connected.Obfsproxy.IsObfsproxy() {
			protocol += fmt.Sprintf(" (Obfsproxy: %s)", connected.Obfsproxy.ToString())
		}
	}

	fmt.Fprintf(w, "    Protocol\t:\t%v\n", protocol)
	fmt.Fprintf(w, "    Local IP\t:\t%v\n", connected.ClientIP)
	if len(connected.ClientIPv6) > 0 {
		fmt.Fprintf(w, "    Local IPv6\t:\t%v\n", connected.ClientIPv6)
	}

	portInfo := ""
	if connected.ServerPort > 0 {
		if connected.IsTCP {
			portInfo += " (TCP:"
		} else {
			portInfo += " (UDP:"
		}
		portInfo += fmt.Sprintf("%d)", connected.ServerPort)
	}
	fmt.Fprintf(w, "    Server IP\t:\t%v%v\n", connected.ServerIP, portInfo)

	fmt.Fprintf(w, "    Connected\t:\t%v\n", since)

	return w
}

func printDNSState(w *tabwriter.Writer, dnsStatus types.DnsStatus, servers *apitypes.ServersInfoResponse) *tabwriter.Writer {
	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	if dnsStatus.AntiTrackerStatus.Enabled {
		fmt.Fprintf(w, "AntiTracker\t:\t%v\n", GetAntiTrackerStatusText(dnsStatus.AntiTrackerStatus))
	} else {
		if dnsStatus.Dns.IsEmpty() {
			fmt.Fprintf(w, "DNS\t:\tDefault (auto)\n")
		} else {
			fmt.Fprintf(w, "DNS\t:\t%v\n", dnsStatus.Dns.InfoString())
			fmt.Fprintf(w, "    Management style\t:\t%v\n", dns.DnsMgmtStyleDescription(dnsStatus.DnsMgmtStyleInUse))
		}
	}

	return w
}

func printRestApiState(w *tabwriter.Writer, usingDevRestApiBackend bool) *tabwriter.Writer {
	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	if !usingDevRestApiBackend {
		fmt.Fprintf(w, "    REST API\t:\t%v\n", "Production (default)")
	} else {
		fmt.Fprintf(w, "    REST API\t:\t%v\n", "Development")
	}

	return w
}

func printFirewallState(w *tabwriter.Writer, isEnabled, isPersistent, isAllowLAN, isAllowMulticast, isAllowApiServers, weHaveTopFirewallPriority bool, userExceptions string, vpnState *vpn.State) *tabwriter.Writer {
	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	fwState := "Disabled"
	if isEnabled {
		fwState = "Enabled"
	}

	extraFwInfo := ""
	if isEnabled && vpnState != nil && *vpnState == vpn.DISCONNECTED {
		extraFwInfo = " (!)"
	}
	fmt.Fprintf(w, "Firewall\t:\t%v%s\n", fwState, extraFwInfo)
	if runtime.GOOS == "windows" {
		fmt.Fprintf(w, "    Have Top Firewall Priority\t:\t%v\n", weHaveTopFirewallPriority)
	}
	if isPersistent {
		fmt.Fprintf(w, "    Persistent\t:\t%v\n", isPersistent)
	}

	if isEnabled {
		if weHaveTopFirewallPriority {
			fmt.Fprintf(w, "    VPN coexistence\t:\tGOOD\n")
		} else {
			fmt.Fprintf(w, "    VPN coexistence\t:\tFAILED\n")
		}

		// fmt.Fprintf(w, "    Allow internet\t:\t%v\n", isAllowLAN)
		// fmt.Fprintf(w, "    Allow LAN\t:\t%v\n", isAllowLAN)
		// fmt.Fprintf(w, "    Allow PL servers\t:\t%v\n", isAllowApiServers)
		// if len(userExceptions) > 0 {
		// 	fmt.Fprintf(w, "    Allow IP masks\t:\t%v\n", userExceptions)
		// }
	}

	return w
}

func printSplitTunState(w *tabwriter.Writer, isShortPrint, isFullPrint, isSplitTunEnabled, isAppWhitelistEnabled, isInversed, isAnyDns, isAllowWhenNoVpn bool, apps []string, runningApps []splittun.RunningApp) *tabwriter.Writer {
	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	if !cliplatform.IsSplitTunSupported() {
		return w
	}

	vpnState, connected, err := _proto.GetVPNState()
	if err != nil {
		_ = fmt.Errorf("error in _proto.GetVPNState(): %w", err)
		return w
	}

	// whether the routing table changes for Total Shield are actually in effect
	vpnActive := vpnState == vpn.CONNECTED && !connected.IsPaused
	totalShieldEffectivelyEnabled := !isSplitTunEnabled && vpnActive

	state := "Enabled"
	// dnsFw := ""
	// allowDefConnectivity := ""
	if isSplitTunEnabled {
		state = "Disabled"
		if isInversed {
			state += " (INVERSE MODE)"

			// if isAnyDns {
			// 	dnsFw = "Allowed (!)"
			// } else {
			// 	dnsFw = "Blocked"
			// }
			// if isAllowWhenNoVpn {
			// 	allowDefConnectivity = "Allowed"
			// } else {
			// 	allowDefConnectivity = "Not allowed"
			// }
		}
	}

	fmt.Fprintf(w, "Total Shield\t:\t%v\n", state)
	// if len(dnsFw) > 0 {
	// 	fmt.Fprintf(w, "    Non-privateLINE DNS\t:\t%v\n", dnsFw)
	// }
	// if len(allowDefConnectivity) > 0 {
	// 	fmt.Fprintf(w, "    No-VPN connectivity\t:\t%v\n", allowDefConnectivity)
	// }

	// if !isSplitTunEnabled {
	var canAccessInternet, canAccessPLServers string
	if totalShieldEffectivelyEnabled {
		canAccessInternet = "no"
	} else {
		canAccessInternet = "yes"
	}
	fmt.Fprintf(w, "    Can access internet\t:\t%s\n", canAccessInternet)
	// fmt.Fprintf(w, "    Can access LAN\t:\t%v\n", true)
	if vpnActive {
		canAccessPLServers = "yes"
	} else {
		canAccessPLServers = "no"
	}
	fmt.Fprintf(w, "    Can access PL servers\t:\t%s\n", canAccessPLServers)

	var isAppWhitelistEnabledStatus string
	if isAppWhitelistEnabled {
		isAppWhitelistEnabledStatus = "Enabled"
	} else {
		isAppWhitelistEnabledStatus = "Disabled"
	}
	fmt.Fprintf(w, "App Whitelist\t:\t%s\n", isAppWhitelistEnabledStatus)
	if !isAppWhitelistEnabled {
		return w
	}

	if !isShortPrint {
		for i, path := range apps {
			if i == 0 {
				fmt.Fprintf(w, "    Whitelisted apps\t:\t%v\n", path)
			} else {
				fmt.Fprintf(w, "\t\t%v\n", path)
			}
		}

		sort.Slice(runningApps, func(i, j int) bool {
			return runningApps[i].Pid < runningApps[j].Pid
		})

		isFirstLineShown := false
		for _, exec := range runningApps {
			if exec.Pid != exec.ExtIvpnRootPid {
				continue
			}

			cmd := exec.ExtModifiedCmdLine
			if len(cmd) <= 0 {
				cmd = exec.Cmdline
			}
			if !isFirstLineShown {
				isFirstLineShown = true
				fmt.Fprintf(w, "    Running commands\t:\t[pid:%d] %s\n", exec.Pid, cmd)
			} else {
				fmt.Fprintf(w, "\t\t[pid:%d] %s\n", exec.Pid, cmd)
			}
		}

		if isFullPrint {
			regexpBinaryArgs := regexp.MustCompile("(\".*\"|\\S*)(.*)")
			funcTruncateCmdStr := func(cmd string, maxLenSoftLimit int) string {
				cols := regexpBinaryArgs.FindStringSubmatch(cmd)
				if len(cols) != 3 {
					return cmd
				}
				ret := cols[1] // bin

				args := cmd[len(ret):]
				if len(ret) < maxLenSoftLimit && len(args) > 0 {
					ret += " " + args
					if len(ret) > maxLenSoftLimit {
						ret = ret[:maxLenSoftLimit] + "..."
					}
				}
				return ret
				//cols := regexpBinaryArgs.FindStringSubmatch(cmd)
				//if len(cols) != 3 {
				//	return cmd
				//}
				//ret := cols[1] // bin
				//args := strings.Split(cols[2], " ")
				//for _, arg := range args {
				//	if len(arg) <= 0 {
				//		continue
				//	}
				//	if len(ret)+len(arg) <= maxLenSoftLimit {
				//		ret += " " + arg
				//	} else {
				//		ret += "..."
				//		break
				//	}
				//}
				//return ret
			}

			if len(runningApps) > 0 {
				fmt.Fprintf(w, "    All running processes\t:\t\n")

				for _, exec := range runningApps {
					detachedProcWarning := ""
					if exec.ExtIvpnRootPid <= 0 {
						detachedProcWarning = "*"
					}

					fmt.Fprintf(w, "      [pid:%d ppid:%d exe:%s]%s %s\n", exec.Pid, exec.Ppid, exec.Exe, detachedProcWarning, funcTruncateCmdStr(exec.Cmdline, 60))
				}
			}
		}
	}

	return w
}

func printParanoidModeState(w *tabwriter.Writer, helloResp types.HelloResp) *tabwriter.Writer {
	if w == nil {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}

	pModeStatusText := "Disabled"
	if helloResp.ParanoidMode.IsEnabled {
		pModeStatusText = "Enabled"
	}
	fmt.Fprintf(w, "EAA\t:\t%s\n", pModeStatusText)

	return w
}
