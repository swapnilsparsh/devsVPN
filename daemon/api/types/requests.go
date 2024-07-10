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

type RequestWithSessionToken interface {
	// Returns "" if there's no session token in this request
	GetSessionToken() string
}

type SessionTokenStruct struct {
	// non-serializable vars to pass to httpRequest creation stage
	SessionToken string // bearer token for authorization
}

// KemPublicKeys in use for KEM: to exchange WG PresharedKey
type KemPublicKeys struct {
	KemPublicKey_Kyber1024             string `json:"kem_public_key1,omitempty"`
	KemPublicKey_ClassicMcEliece348864 string `json:"kem_public_key2,omitempty"`
}

// SessionNewRequest request to create new session
type SessionNewRequest struct {
	// AccountID  string `json:"username"`
	// ForceLogin bool   `json:"force"`

	// PublicKey string `json:"wg_public_key"`
	// KemPublicKeys

	// CaptchaID       string `json:"captcha_id,omitempty"`
	// Captcha         string `json:"captcha,omitempty"`
	// Confirmation2FA string `json:"confirmation,omitempty"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (req SessionNewRequest) GetSessionToken() string {
	return ""
}

// SessionDeleteRequest request to delete session
type SessionDeleteRequest struct {
	Session string `json:"session_token"`
}

func (req SessionDeleteRequest) GetSessionToken() string {
	return req.Session
}

// ConnectDeviceRequest request to register device
type ConnectDeviceRequest struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	PublicKey  string `json:"public_key"`
	Platform   string `json:"platform"`

	SessionTokenStruct
}

func (req ConnectDeviceRequest) GetSessionToken() string {
	return req.SessionToken
}

// SessionStatusRequest request to get session status
type SessionStatusRequest struct {
	Session string `json:"session_token"`
}

func (req SessionStatusRequest) GetSessionToken() string {
	return req.Session
}

// SessionWireGuardKeySetRequest request to set new WK key for a session
type SessionWireGuardKeySetRequest struct {
	Session            string `json:"session_token"`
	PublicKey          string `json:"public_key"`
	ConnectedPublicKey string `json:"connected_public_key"`
	KemPublicKeys
}

func (req SessionWireGuardKeySetRequest) GetSessionToken() string {
	return req.Session
}
