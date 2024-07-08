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

// APIResponse - generic API response
type APIResponse struct {
	Status int `json:"status"` // status code
}

// APIErrorResponse generic IVPN API error
type APIErrorResponse struct {
	APIResponse
	Message string `json:"message,omitempty"` // Text description of the message
}

// ServiceStatusAPIResp account info
type ServiceStatusAPIResp struct {
	Active              bool     `json:"is_active"`
	ActiveUntil         int64    `json:"active_until"`
	CurrentPlan         string   `json:"current_plan"`
	PaymentMethod       string   `json:"payment_method"`
	IsRenewable         bool     `json:"is_renewable"`
	WillAutoRebill      bool     `json:"will_auto_rebill"`
	IsFreeTrial         bool     `json:"is_on_free_trial"`
	Capabilities        []string `json:"capabilities"`
	Upgradable          bool     `json:"upgradable"`
	UpgradeToPlan       string   `json:"upgrade_to_plan"`
	UpgradeToURL        string   `json:"upgrade_to_url"`
	DeviceManagement    bool     `json:"device_management"`
	DeviceManagementURL string   `json:"device_management_url"` // applicable for 'session limit' error
	Limit               int      `json:"limit"`                 // applicable for 'session limit' error
}

// KemCiphers in use for KEM: to exchange WG PresharedKey
type KemCiphers struct {
	KemCipher_Kyber1024             string `json:"kem_cipher1,omitempty"` // (Kyber-1024) in use for KEM: to exchange WG PresharedKey
	KemCipher_ClassicMcEliece348864 string `json:"kem_cipher2,omitempty"` // (Classic-McEliece-348864) in use for KEM: to exchange WG PresharedKey
}

// SessionNewResponse information about created session
// TODO: FIXME: use more appropriate types than string: dates, etc.
type SessionNewResponse struct {
	Status  bool   `json:"status"`            // FIXME: why is the API returning bool here?
	Message string `json:"message,omitempty"` // Text description of the message
	Data    struct {
		ID          int    `json:"id"`
		UserType    string `json:"user_type"`
		Username    string `json:"name"`
		Phone       string `json:"phone"`
		Email       string `json:"email"`
		IsVerified  bool   `json:"isVerified"`
		Profile     string `json:"profile"`
		IsActive    bool   `json:"isActive"`
		IsSuspended bool   `json:"isSuspended"`
		IsDeleted   bool   `json:"isDeleted"`
		LastLogin   string `json:"last_login"`
		TempToken   string `json:"temp_token"`
		Login       int    `json:"login"`
		CreatedAt   string `json:"createdAt"`
		UpdatedAt   string `json:"updatedAt"`
		Token       string `json:"token"`
	}
}

// SessionNewErrorLimitResponse information about session limit error
type SessionNewErrorLimitResponse struct {
	APIErrorResponse
	SessionLimitData ServiceStatusAPIResp `json:"data"`
}

// SessionsWireGuardResponse Sessions WireGuard response
type SessionsWireGuardResponse struct {
	APIErrorResponse
	IPAddress string `json:"ip_address,omitempty"`
	KemCiphers
}

// ConnectDeviceResponse Connect Device response
type ConnectDeviceResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    []struct {
		Interface struct {
			Address string `json:"Address"`
			DNS     string `json:"DNS"`
		} `json:"Interface"`
		Peer struct {
			PublicKey  string `json:"PublicKey"`
			AllowedIPs string `json:"AllowedIPs"`
			Endpoint   string `json:"Endpoint"`
		} `json:"Peer"`
	} `json:"data"`
}

// SessionStatusResponse session status response
type SessionStatusResponse struct {
	APIErrorResponse
	ServiceStatus ServiceStatusAPIResp `json:"service_status"`
	DeviceName    string               `json:"device_name,omitempty"`
}

// GeoLookupResponse geolocation info
type GeoLookupResponse struct {
	//ip_address   string
	//isp          string
	//organization string
	//country      string
	//country_code string
	//city         string

	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`

	//isIvpnServer bool
}
