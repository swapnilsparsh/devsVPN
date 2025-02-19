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
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/swapnilsparsh/devsVPN/cli/flags"
	"github.com/swapnilsparsh/devsVPN/cli/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/srverrors"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
	"golang.org/x/term"
)

type CmdLogout struct {
	flags.CmdInfo
	disableFirewall            bool
	resetAppSettingsToDefaults bool
}

func (c *CmdLogout) Init() {
	c.Initialize("logout", "Logout from this device (if logged-in)")
	c.BoolVar(&c.disableFirewall, "firewall_off", false, "Turn Firewall off (do not prompt about enabled Firewall)")
	c.BoolVar(&c.resetAppSettingsToDefaults, "reset_settings", false, "Reset application settings to defaults")
}

func (c *CmdLogout) Run() error {
	return doLogout(c.disableFirewall, c.resetAppSettingsToDefaults)
}

// ----------------------------------------------------------------------------------------
type CmdLogin struct {
	flags.CmdInfo
	emailOrAcctID     string
	stableDeviceID    bool
	passwordlessLogin bool
	deviceName        string
}

func (c *CmdLogin) Init() {
	c.Initialize("login", "Login operation (register this device under your privateLINE account)")
	c.DefaultStringVar(&c.emailOrAcctID, "<account email, or account ID for passwordless login>")
	c.BoolVar(&c.passwordlessLogin, "passwordless", false, "Whether this is a non-SSO, passwordless login by account ID. If so, specify your account ID instead of email, and you won't be prompted for the password.")
	c.StringVar(&c.deviceName, "device_name", "", "<device name>", "Optionally specify device name")
	c.BoolVar(&c.stableDeviceID, "stable_device_id", false, "Generate the device ID as a stable, yet privacy-preserving identifier. By default device ID is generated randomly.")
}

func (c *CmdLogin) Run() error {
	return doLogin(c.emailOrAcctID, c.passwordlessLogin, c.deviceName, c.stableDeviceID)
}

func doLogin(emailOrAcctID string, passwordlessLogin bool, deviceName string, stableDeviceID bool) error {
	// checking if we are logged-in
	_proto.SessionStatus() // do not check error response (could be received 'not logged in' errors)
	helloResp := _proto.GetHelloResponse()
	if len(helloResp.Session.Session) != 0 {
		fmt.Println("Already logged in")
		PrintTips([]TipType{TipLogout})
		return fmt.Errorf("unable to login (please, log out first)")
	}

	// login
	var password string
	if passwordlessLogin {
		password = ""
	} else {
		fmt.Print("Enter your password: ")
		data, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = string(data)
	}

	resp, err := _proto.SessionNew(emailOrAcctID, password, deviceName, stableDeviceID)
	if err != nil {
		// if resp.APIStatus == types.The2FARequired {
		// 	fmt.Println("Account has two-factor authentication enabled.")
		// 	fmt.Print("Please enter TOTP token to login: ")
		// 	reader := bufio.NewReader(os.Stdin)
		// 	topt, _ := reader.ReadString('\n')

		// 	topt = strings.TrimSuffix(topt, "\n")
		// 	topt = strings.TrimSuffix(topt, "\r")

		// 	resp, err = _proto.SessionNew(accountID, force, topt)
		// }

		if resp.APIStatus == types.CodeSessionsLimitReached {
			PrintTips([]TipType{TipForceLogin})

			if !helpers.IsLegacyAccount(emailOrAcctID) && len(resp.Account.DeviceManagementURL) > 0 {
				prefixText := "Visit Device Management"
				if !resp.Account.DeviceManagement {
					prefixText = "Enable Device Management"
				}
				fmt.Println(fmt.Sprintf("%s to manage your devices: '%s'", prefixText, resp.Account.DeviceManagementURL))
			}
		}

		if err != nil {
			return err
		}
	}

	fmt.Println("Logged in")
	PrintTips([]TipType{TipServers, TipConnectHelp})

	return nil
}

//----------------------------------------------------------------------------------------

type CmdAccount struct {
	flags.CmdInfo
}

func (c *CmdAccount) Init() {
	c.Initialize("account", "Get info about current account")
}

func (c *CmdAccount) Run() error {
	return checkStatus()
}

//----------------------------------------------------------------------------------------

func doLogout(disableFirewall bool, resetAppSettingsToDefaults bool) error {
	// checking if we are logged-in
	_proto.SessionStatus() // do not check error response (could be received 'not logged in' errors)
	helloResp := _proto.GetHelloResponse()
	if len(helloResp.Session.Session) == 0 {
		return fmt.Errorf("already logged out")
	}

	// do not allow to logout if VPN connected
	state, _, err := _proto.GetVPNState()
	if err != nil {
		return err
	}
	if state != vpn.DISCONNECTED {
		PrintTips([]TipType{TipDisconnect})
		return fmt.Errorf("unable to log out (please, disconnect VPN first)")
	}

	if disableFirewall == false {
		fwstate, fwerr := _proto.FirewallStatus()
		if fwerr != nil {
			return err
		}
		if fwstate.IsEnabled {
			fmt.Println("The Firewall is enabled.  All network access will be blocked.")
			fmt.Print("Do you want to turn Firewall off? [yes/no]: ")

			reader := bufio.NewReader(os.Stdin)
			yn, _ := reader.ReadString('\n')
			yn = strings.TrimSuffix(yn, "\n")
			yn = strings.TrimSuffix(yn, "\r")
			if yn == "" {
				yn = "yes"
				fmt.Println(yn)
			}
			yn = strings.ToUpper(yn)

			if yn == "Y" || yn == "YES" {
				disableFirewall = true
			}
		}
	}

	// delete session
	isCanDeleteSessionLocally := false
	err = _proto.SessionDelete(disableFirewall, resetAppSettingsToDefaults, isCanDeleteSessionLocally)
	if err != nil {
		fmt.Println("Unable to contact server to log out. Please check Internet connectivity.")
		fmt.Println("If you force log out this device will continue to count towards your device limit.")
		fmt.Print("Do you want to force log out? [yes/no]: ")

		reader := bufio.NewReader(os.Stdin)
		yn, _ := reader.ReadString('\n')
		yn = strings.TrimSuffix(yn, "\n")
		yn = strings.TrimSuffix(yn, "\r")
		if yn == "" {
			yn = "no"
			fmt.Println(yn)
		}
		yn = strings.ToUpper(yn)

		if yn != "Y" && yn != "YES" {
			fmt.Println("Cancelled")
			return nil
		}

		fmt.Println("Force logout...")
		isCanDeleteSessionLocally := true
		err = _proto.SessionDelete(disableFirewall, resetAppSettingsToDefaults, isCanDeleteSessionLocally)
		if err != nil {
			return err
		}
	}

	fmt.Println("Logged out")
	PrintTips([]TipType{TipLogin})

	return nil
}

func checkStatus() error {
	stat, err := _proto.SessionStatus()

	helloResp := _proto.GetHelloResponse()
	if len(helloResp.Command) > 0 && (len(helloResp.Session.Session) == 0) {
		// We received 'hello' response but no session info - print tips to login
		fmt.Printf("Error: Not logged in")

		fmt.Println()
		PrintTips([]TipType{TipLogin})

		return srverrors.ErrorNotLoggedIn{}
	}

	if err != nil {
		return err
	}

	if stat.APIStatus != types.CodeSuccess {
		return fmt.Errorf("API error: %v %v", stat.APIStatus, stat.APIErrorMessage)
	}

	acc := stat.Account
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	fmt.Fprintln(w, fmt.Sprintf("Account ID:\t%v", helloResp.Session.AccountID))

	if len(helloResp.Session.DeviceName) > 0 {
		fmt.Fprintln(w, fmt.Sprintf("Device name:\t%v", helloResp.Session.DeviceName))
	}

	if acc.IsFreeTrial {
		fmt.Fprintln(w, fmt.Sprintf("Plan:\tFree Trial"))
	} else {
		fmt.Fprintln(w, fmt.Sprintf("Plan:\t%v", acc.CurrentPlan))
	}
	fmt.Fprintln(w, fmt.Sprintf("Active until:\t%v", time.Unix(acc.ActiveUntil, 0)))
	if stat.Account.DeviceLimit > 0 {
		fmt.Fprintln(w, fmt.Sprintf("Device limit:\t%v", acc.DeviceLimit))
	}
	if acc.Upgradable == true && len(acc.UpgradeToPlan) > 0 && len(acc.UpgradeToURL) > 0 {
		fmt.Fprintln(w, fmt.Sprintf("Upgrade to:\t%v (%v)", acc.UpgradeToPlan, acc.UpgradeToURL))
	}
	w.Flush()

	return nil
}
