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
// type APIResponse struct {
// 	Status int `json:"status"` // status code
// }

// The purpose of this interface is to allow copying http.Response.StatusCode to API Response objects
type APIResponse interface {
	SetHttpStatusCode(newHttpStatusCode int)
}

// APIErrorResponse generic PrivateLine API error
// Unmarshal it with unmarshalApiErr(), not with json.Unmarshal() - this is in order to pass the HTTP status code to it
type APIErrorResponse struct {
	Status  bool   `json:"status,omitempty"`
	Message string `json:"message,omitempty"` // Text description of the message

	HttpStatusCode int // manually set by parsers
}

func (resp *APIErrorResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
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
	DeviceLimit         int      `json:"device_limit"`          // applicable for 'session limit' error

	HttpStatusCode int // manually set by parsers
}

func (resp *ServiceStatusAPIResp) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

// KemCiphers in use for KEM: to exchange WG PresharedKey
type KemCiphers struct {
	KemCipher_Kyber1024             string `json:"kem_cipher1,omitempty"` // (Kyber-1024) in use for KEM: to exchange WG PresharedKey
	KemCipher_ClassicMcEliece348864 string `json:"kem_cipher2,omitempty"` // (Classic-McEliece-348864) in use for KEM: to exchange WG PresharedKey
}

// SessionNewResponse information about created session
type SessionNewResponse struct {
	APIErrorResponse
	Data struct {
		AccountType    string `json:"account_type,omitempty"`
		ActivityStatus string `json:"activity_status,omitempty"`
		Affiliatecode  string `json:"affiliate_code,omitempty"`
		CreatedAt      string `json:"createdAt"`
		DeletionDate   string `json:"deletion_date,omitempty"`
		DeviceLimit    int    `json:"device_limit,omitempty"`
		Email          string `json:"email"`
		EmailVerified  bool   `json:"email_verified,omitempty"`
		ID             int    `json:"id"`
		IsActive       bool   `json:"isActive"`
		IsDeleted      bool   `json:"isDeleted"`
		IsSuspended    bool   `json:"isSuspended"`
		IsVerified     bool   `json:"isVerified"`
		LastLogin      string `json:"last_login"`
		Login          int    `json:"login"`
		MFAStatus      int    `json:"mfa_status,omitempty"`
		Name           string `json:"name"`
		ParentID       string `json:"parent_id,omitempty"`
		Phone          string `json:"phone"`
		Profile        string `json:"profile"`
		SSORegistered  int    `json:"sso_registered,omitempty"`
		Tags           string `json:"tags,omitempty"`
		TempToken      string `json:"temp_token"`
		Token          string `json:"token"`
		UpdatedAt      string `json:"updatedAt"`
		Username       string `json:"username,omitempty"`
		UserType       string `json:"user_type"`
		UUID           string `json:"uuid,omitempty"`
	}

	// WireGuard struct {
	// 	Status    int    `json:"status"`
	// 	Message   string `json:"message,omitempty"`
	// 	IPAddress string `json:"ip_address,omitempty"`
	// 	KemCiphers
	// } `json:"wireguard"`
}

func (resp *SessionNewResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

// SessionNewErrorLimitResponse information about session limit error
type SessionNewErrorLimitResponse struct {
	APIErrorResponse
	SessionLimitData ServiceStatusAPIResp `json:"data"`
}

func (resp *SessionNewErrorLimitResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

// SessionsWireGuardResponse Sessions WireGuard response
type SessionsWireGuardResponse struct {
	APIErrorResponse
	IPAddress string `json:"ip_address,omitempty"`
	KemCiphers
}

func (resp *SessionsWireGuardResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

// ConnectDeviceResponse Connect Device response
type ConnectDeviceResponse struct {
	APIErrorResponse
	Data []struct {
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

func (resp *ConnectDeviceResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

type CheckDeviceResponse struct {
	Device string `json:"device"` // Indicates the device status ("deleted" or "active")
}

// SessionStatusResponse session status response
type SessionStatusResponse struct {
	APIErrorResponse
	ServiceStatus ServiceStatusAPIResp `json:"service_status"`
	DeviceName    string               `json:"device_name,omitempty"`
}

func (resp *SessionStatusResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
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
	HttpStatusCode int // manually set by parsers
}

func (resp *GeoLookupResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

type DeviceListResponse struct {
	Message string `json:"message"`
	Data    struct {
		Count int `json:"count"`
		Rows  []struct {
			InternalID          int    `json:"id"`
			UserID              int    `json:"userID"`
			DeviceID            string `json:"device_id"`
			MicrotekID          int    `json:"microtek_id"`
			DeviceName          string `json:"device_name"`
			Type                string `json:"type"`
			DeviceIP            string `json:"device_ip"`
			AllocatedIP         string `json:"allocated_ip"`
			PublicKey           string `json:"public_key"`
			InterfacePublicKey  string `json:"interface_publickey"`
			DNS                 string `json:"DNS"`
			AllowedIPs          string `json:"allowedIPs"`
			Endpoint            string `json:"endpoint"`
			IsDeleted           int    `json:"is_deleted"`
			Status              int    `json:"status"`
			KeepAlive           int    `json:"keep_alive"`
			CreatedAt           string `json:"createdAt"`
			CurrentEndpointAddr string `json:"current_endpoint_address"`
			ActiveTunnel        string `json:"active_tunnel"`
			RX                  string `json:"rx"`
			TX                  string `json:"tx"`
			IsConnected         int    `json:"isConnected"`
			Handshake           string `json:"handshake"`
		} `json:"rows"`
	} `json:"data"`

	HttpStatusCode int // manually set by parsers
}

func (resp *DeviceListResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

type SsoLoginResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `josn:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
	NotBeforePolicy  int    `json:"not-before-policy"`
}

type ProfileDataResponse struct {
	Message string `json:"message"`
	Data    struct {
		Id           int    `json:"id"`
		UserType     string `json:"user_type"`
		Name         string `json:"name"`
		Phone        string `json:"phone"`
		Email        string `json:"email"`
		IsVerified   bool   `json:"isVerified"`
		ProfilePhoto string `json:"profile"`
		IsActive     bool   `json:"isActive"`
		IsSuspended  bool   `json:"isSuspended"`
		IsDeleted    bool   `json:"isDeleted"`
		LastLogin    string `josn:"last_login"`
		TempToken    string `json:"temp_token"`
		Login        int    `json:"login"`
		CreatedAt    string `json:"createdAt"`
		UpdatedAt    string `json:"updatedAt"`
	} `json:"data"`
	HttpStatusCode int // manually set by parsers
}

func (resp *ProfileDataResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

type SubscriptionDataResponse struct {
	StartDate  string `json:"start_date"`
	ExpiryDate string `json:"expire_on"`
	GroupSize  int    `json:"group_size"`
	Plan       struct {
		Name string `json:"name"`
	} `json:"Plan"`
	HttpStatusCode int // manually set by parsers
}

func (resp *SubscriptionDataResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

type MigrateSsoUserResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		// returned username will contained account ID in format XXXX-XXXX-XXXX
		Username string `json:"username"`
		Token    string `json:"token"`
	} `json:"data"`
	HttpStatusCode int // manually set by parsers
}

func (resp *MigrateSsoUserResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}

type RageshakeServerResponse struct {
	ReportUrl      string `json:"report_url"`
	HttpStatusCode int    // manually set by parsers
}

func (resp *RageshakeServerResponse) SetHttpStatusCode(newHttpStatusCode int) {
	resp.HttpStatusCode = newHttpStatusCode
}
