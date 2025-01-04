//
//  Daemon for IVPN Client Desktop
//  https://github.com/swapnilsparsh/devsVPN-daemon
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

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	protocolTypes "github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
)

// API URLs
const (
	_defaultRequestTimeout = time.Second * 10 // full request time (for each request)
	_defaultDialTimeout    = time.Second * 5  // time for the dial to the API server (for each request)
	_apiHost               = "deskapi.privateline.io"
	// _apiHost = "api.privateline.dev"

	_ssoTokenUrl = "https://sso.privateline.io/realms/privateLINE/protocol/openid-connect/token"

	// temporarily fetching static servers.json from GitHub
	// _updateHost         = "repo.privateline.io"
	//	_serversPath       = "v5/servers.json"
	_updateHost  = "raw.githubusercontent.com"
	_serversPath = "swapnilsparsh/devsVPN/master/daemon/References/common/etc/servers.json"

	_apiPathPrefix              = "v4"
	_sessionNewPath             = "/user/login"
	_sessionNewPasswordlessPath = "/user/login/quick-auth"
	_connectDevicePath          = "/connection/push-key"
	_checkDevicePath            = "/connection/check-device-id"
	_sessionStatusPath          = "/session/status"
	_sessionDeletePath          = "/user/remove-device"
	_deviceListPath             = "/user/device-list"
	_profileDataPath            = "/user/profile"
	_subscriptionDataPath       = "/user/check-subscription"
	_wgKeySetPath               = _apiPathPrefix + "/session/wg/set"
	_geoLookupPath              = _apiPathPrefix + "/geo-lookup"
)

// Alias - alias description of API request (can be requested by UI client)
type Alias struct {
	host string
	path string
	// If isArcIndependent!=true, the path will be updated: the "_<architecture>" will be added to filename
	// (see 'DoRequestByAlias()' for details)
	// Example:
	//		The "updateInfo_macOS" on arm64 platform will use file "/macos/update_arm64.json" (NOT A "/macos/update.json")
	isArcIndependent bool
}

// APIAliases - aliases of API requests (can be requested by UI client)
// NOTE: the aliases bellow are only for amd64 architecture!!!
// If isArcIndependent!=true: Filename construction for non-amd64 architectures: filename_<architecture>.<extensions>
// (see 'DoRequestByAlias()' for details)
// Example:
//
//	The "updateInfo_macOS" on arm64 platform will use file "/macos/update_arm64.json" (NOT A "/macos/update.json")
const (
	GeoLookupApiAlias string = "geo-lookup"
)

var APIAliases = map[string]Alias{
	GeoLookupApiAlias: {host: _apiHost, path: _geoLookupPath},

	"updateInfo_Linux":   {host: _updateHost, path: "/stable/_update_info/update.json"},
	"updateSign_Linux":   {host: _updateHost, path: "/stable/_update_info/update.json.sign.sha256.base64"},
	"updateInfo_macOS":   {host: _updateHost, path: "/macos/update.json"},
	"updateSign_macOS":   {host: _updateHost, path: "/macos/update.json.sign.sha256.base64"},
	"updateInfo_Windows": {host: _updateHost, path: "/windows/update.json"},
	"updateSign_Windows": {host: _updateHost, path: "/windows/update.json.sign.sha256.base64"},

	"updateInfo_manual_Linux":   {host: _updateHost, path: "/stable/_update_info/update_manual.json"},
	"updateSign_manual_Linux":   {host: _updateHost, path: "/stable/_update_info/update_manual.json.sign.sha256.base64"},
	"updateInfo_manual_macOS":   {host: _updateHost, path: "/macos/update_manual.json"},
	"updateSign_manual_macOS":   {host: _updateHost, path: "/macos/update_manual.json.sign.sha256.base64"},
	"updateInfo_manual_Windows": {host: _updateHost, path: "/windows/update_manual.json"},
	"updateSign_manual_Windows": {host: _updateHost, path: "/windows/update_manual.json.sign.sha256.base64"},

	"updateInfo_beta_Linux":   {host: _updateHost, path: "/stable/_update_info/update_beta.json"},
	"updateSign_beta_Linux":   {host: _updateHost, path: "/stable/_update_info/update_beta.json.sign.sha256.base64"},
	"updateInfo_beta_macOS":   {host: _updateHost, path: "/macos/update_beta.json"},
	"updateSign_beta_macOS":   {host: _updateHost, path: "/macos/update_beta.json.sign.sha256.base64"},
	"updateInfo_beta_Windows": {host: _updateHost, path: "/windows/update_beta.json"},
	"updateSign_beta_Windows": {host: _updateHost, path: "/windows/update_beta.json.sign.sha256.base64"},
}

var log *logger.Logger

func init() {
	log = logger.NewLogger("api")
}

// IConnectivityInfo information about connectivity
type IConnectivityInfo interface {
	// IsConnectivityBlocked - returns nil if connectivity NOT blocked
	IsConnectivityBlocked() (err error)
}

type geolookup struct {
	mutex     sync.Mutex
	isRunning bool
	done      chan struct{}

	location types.GeoLookupResponse
	response []byte
	err      error
}

// API contains data about IVPN API servers
type API struct {
	mutex                 sync.Mutex
	alternateIPsV4        []net.IP
	lastGoodAlternateIPv4 net.IP
	alternateIPsV6        []net.IP
	lastGoodAlternateIPv6 net.IP
	connectivityChecker   IConnectivityInfo

	// last geolookups result
	geolookupV4 geolookup
	geolookupV6 geolookup
}

// CreateAPI creates new API object
func CreateAPI() (*API, error) {
	return &API{}, nil
}

func (a *API) SetConnectivityChecker(connectivityChecker IConnectivityInfo) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.connectivityChecker = connectivityChecker
}

// IsAlternateIPsInitialized - checks if the alternate IP initialized
func (a *API) IsAlternateIPsInitialized(IPv6 bool) bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if IPv6 {
		return len(a.alternateIPsV6) > 0
	}
	return len(a.alternateIPsV4) > 0
}

func (a *API) GetLastGoodAlternateIP(IPv6 bool) net.IP {
	if IPv6 {
		if a.lastGoodAlternateIPv6.To4() != nil {
			return nil // something wrong here: lastGoodAlternateIPv6 must be IPv6 address
		}
		return a.lastGoodAlternateIPv6
	}
	return a.lastGoodAlternateIPv4.To4()
}

// SetLastGoodAlternateIP - save last good alternate IP address of API server
// It keeps IPv4 and IPv6 addresses separately
func (a *API) SetLastGoodAlternateIP(ip net.IP) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	isIp6Addr := ip.To4() == nil
	if isIp6Addr {
		a.lastGoodAlternateIPv6 = ip
		return
	}
	a.lastGoodAlternateIPv4 = ip
}

func (a *API) getAlternateIPs(IPv6 bool) []net.IP {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if IPv6 {
		return a.alternateIPsV6
	}
	return a.alternateIPsV4
}

// SetAlternateIPs save info about alternate servers IP addresses
func (a *API) SetAlternateIPs(IPv4List []string, IPv6List []string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.doSetAlternateIPs(false, IPv4List)
	a.doSetAlternateIPs(true, IPv6List)
	return nil
}

func (a *API) doSetAlternateIPs(IPv6 bool, IPs []string) error {
	if len(IPs) == 0 {
		log.Warning("Unable to set alternate API IP list. List is empty")
	}

	lastGoodIP := a.GetLastGoodAlternateIP(IPv6)

	ipList := make([]net.IP, 0, len(IPs))

	isLastIPExists := false
	for _, ipStr := range IPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		ipList = append(ipList, ip)

		if ip.Equal(lastGoodIP) {
			isLastIPExists = true
		}
	}

	if !isLastIPExists {
		if IPv6 {
			a.lastGoodAlternateIPv6 = nil
		} else {
			a.lastGoodAlternateIPv4 = nil
		}
	}

	// set new alternate IP list
	if IPv6 {
		a.alternateIPsV6 = ipList
	} else {
		a.alternateIPsV4 = ipList
	}

	return nil
}

// DownloadServersList - download servers list form API IVPN server
func (a *API) DownloadServersList() (*types.ServersInfoResponse, error) {
	servers := new(types.ServersInfoResponse)
	// if err := a.request(_apiHost, _serversPath, "GET", "", nil, servers); err != nil {
	if err := a.request(_updateHost, _serversPath, "GET", "", nil, servers); err != nil {
		return nil, err
	}

	// save info about alternate API hosts
	a.SetAlternateIPs(servers.Config.API.IPAddresses, servers.Config.API.IPv6Addresses)
	return servers, nil
}

// DoRequestByAlias do API request (by API endpoint alias). Returns raw data of response
func (a *API) DoRequestByAlias(apiAlias string, ipTypeRequired protocolTypes.RequiredIPProtocol) (responseData []byte, err error) {
	// For geolookup requests we have specific function
	if apiAlias == GeoLookupApiAlias {
		if ipTypeRequired != protocolTypes.IPv4 && ipTypeRequired != protocolTypes.IPv6 {
			return nil, fmt.Errorf("geolookup request failed: IP version not defined")
		}
		_, responseData, err = a.GeoLookup(0, ipTypeRequired)
		return responseData, err
	}

	// get connection info by API alias
	alias, ok := APIAliases[apiAlias]
	if !ok {
		return nil, fmt.Errorf("unexpected request alias")
	}

	if !alias.isArcIndependent {
		// If isArcIndependent!=true, the path will be updated: the "_<architecture>" will be added to filename
		// Example:
		//		The "updateInfo_macOS" on arm64 platform will use file "/macos/update_arm64.json" (NOT A "/macos/update.json"!)
		if runtime.GOARCH != "amd64" {
			extIdx := strings.Index(alias.path, ".")
			if extIdx > 0 {
				newPath := alias.path[:extIdx] + "_" + runtime.GOARCH + alias.path[extIdx:]
				alias.path = newPath
			}
		}
	}

	responseData, _, err = a.requestRaw(ipTypeRequired, alias.host, alias.path, "", "", nil, 0, 0)
	return responseData, err
}

// SessionNew - try to register new session
func (a *API) SessionNew(emailOrAcctID string, password string) (
	*types.SessionNewResponse,
	*types.SessionNewErrorLimitResponse,
	*types.APIErrorResponse,
	string, // RAW response
	error) {

	var (
		successResp    types.SessionNewResponse
		errorLimitResp types.SessionNewErrorLimitResponse
		apiErr         types.APIErrorResponse
		request        *types.SessionNewRequest
		apiPath        string
		data           []byte
		httpResp       *http.Response
		err            error
	)

	rawResponse := ""

	if password != "" { // email/password login
		request = &types.SessionNewRequest{
			Email:    emailOrAcctID,
			Password: password,
			SsoLogin: true,
		}
		apiPath = _sessionNewPath
	} else { // passwordless login
		request = &types.SessionNewRequest{
			AccountID: emailOrAcctID,
		}
		apiPath = _sessionNewPasswordlessPath
	}

	data, httpResp, err = a.requestRaw(protocolTypes.IPvAny, _apiHost, apiPath, "POST", "application/json", request, 0, 0)
	if err != nil {
		return nil, nil, nil, rawResponse, err
	}

	rawResponse = string(data)

	// Check is it API error
	if err := unmarshalAPIErrorResponse(data, httpResp, &apiErr); err != nil {
		return nil, nil, nil, rawResponse, fmt.Errorf("failed to deserialize API response: %w", err)
	}

	// if !apiErr.Status {
	// 	log.Debug("apiErr.Status=false apiErr.Message='" + apiErr.Message + "'")
	// 	return nil, nil, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
	// }

	// success
	if apiErr.HttpStatusCode == types.CodeSuccess {
		err := json.Unmarshal(data, &successResp)
		successResp.SetHttpStatusCode(apiErr.HttpStatusCode)
		if err != nil {
			return nil, nil, &apiErr, rawResponse, fmt.Errorf("failed to deserialize API response: %w", err)
		}

		return &successResp, nil, &apiErr, rawResponse, nil
	}

	// Session limit check
	if apiErr.HttpStatusCode == types.CodeSessionsLimitReached {
		err := json.Unmarshal(data, &errorLimitResp)
		errorLimitResp.SetHttpStatusCode(apiErr.HttpStatusCode)
		if err != nil {
			return nil, nil, &apiErr, rawResponse, fmt.Errorf("failed to deserialize API response: %w", err)
		}
		return nil, &errorLimitResp, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
	}

	return nil, nil, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
}

// SsoLogin - try to register new session
func (a *API) SsoLogin(code string, sessionCode string) (
	resp *types.SsoLoginResponse,
	err error) {

	resp = &types.SsoLoginResponse{}
	httpClient := &http.Client{}

	// Step 1: Exchange code for token by hitting the Keycloak token endpoint
	// TODO FIXME: Vlad - clean up, refactor into the same convention as other api.go calls
	payload := url.Values{}
	payload.Set("grant_type", "authorization_code")
	payload.Set("code", code)
	payload.Set("redirect_uri", "privateline://auth") //registered redirect_uri on cloak
	payload.Set("client_id", "pl-connect-desktop")
	payload.Set("client_secret", "0azvyAE6YtHryCgATkP4RcIx5HUprqgl") //prod client secret
	// payload.Set("client_secret", "YKJ6aBMCMhJfzH9RtClcBFFNGrh5ystc") //dev client secret

	// Send the POST request to get the token
	tokenResp, err := httpClient.PostForm(_ssoTokenUrl, payload)
	if err != nil {
		return resp, fmt.Errorf("failed to request token: %w", err)
	}
	defer tokenResp.Body.Close()

	// Read the token response
	tokenBody, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		return resp, fmt.Errorf("failed to read token response: %w", err)
	}

	err = json.Unmarshal(tokenBody, resp)
	// Parse the token response
	var tokenData map[string]interface{}
	err = json.Unmarshal(tokenBody, &tokenData)
	if err != nil {
		return resp, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Check if the token response contains an error
	if _, ok := tokenData["error"]; ok {
		return resp, fmt.Errorf("error in token response: %v", tokenData["error_description"])
	}

	return resp, err
}

func (a *API) ConnectDevice(deviceID string, deviceName string, publicKey string, sessionToken string) (
	*types.ConnectDeviceResponse,
	*types.APIErrorResponse,
	string, // RAW response
	error) {

	var successResp types.ConnectDeviceResponse
	var apiErr types.APIErrorResponse

	rawResponse := ""

	request := &types.ConnectDeviceRequest{
		DeviceID:           deviceID,
		DeviceName:         deviceName,
		PublicKey:          publicKey,
		Platform:           runtime.GOOS,
		SessionTokenStruct: types.SessionTokenStruct{SessionToken: sessionToken},
	}

	data, httpResp, err := a.requestRaw(protocolTypes.IPvAny, _apiHost, _connectDevicePath, "POST", "application/json", request, 0, 0)

	if err != nil {
		return nil, nil, rawResponse, err
	}

	rawResponse = string(data)

	// Check is it API error
	if err := unmarshalAPIErrorResponse(data, httpResp, &apiErr); err != nil {
		return nil, nil, rawResponse, fmt.Errorf("failed to deserialize API response: %w", err)
	}

	if !apiErr.Status {
		return nil, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
	}

	// success
	if apiErr.HttpStatusCode == types.CodeSuccess {
		err := json.Unmarshal(data, &successResp)
		successResp.SetHttpStatusCode(apiErr.HttpStatusCode)
		if err != nil {
			return nil, &apiErr, rawResponse, fmt.Errorf("failed to deserialize API response: %w", err)
		}

		return &successResp, &apiErr, rawResponse, nil
	}

	return nil, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
}

// CheckDeviceID - TODO: temporary implementation by checking our WG public key against the list
func (a *API) CheckDeviceID(session, deviceWGPublicKey string) (deviceFound bool, err error) {
	deviceList, err := a.DeviceList(session)
	if err != nil {
		return false, log.ErrorE(fmt.Errorf("failed to fetch device list: %w", err), 0)
	}

	for _, dev := range deviceList.Data.Rows {
		if dev.PublicKey == deviceWGPublicKey {
			return true, nil
		}
	}

	return false, nil
}

// TODO FIXME: Vlad - use the below CheckDeviceID() implementation once the client knows its internal device ID
/*
func (a *API) CheckDeviceID(InternalID int, sessionToken string) (
	*types.CheckDeviceResponse,
	*types.APIErrorResponse,
	string, // RAW response
	error,
) {
	var successResp types.CheckDeviceResponse
	var apiErr types.APIErrorResponse

	rawResponse := ""

	// Construct the endpoint URL
	endpoint := fmt.Sprintf("%s/%d", _checkDevicePath, InternalID)

	request := &types.DeviceListRequest{
		SessionTokenStruct: types.SessionTokenStruct{SessionToken: sessionToken},
	}

	// Send the GET request
	data, httpResp, err := a.requestRaw(protocolTypes.IPvAny, _apiHost, endpoint, "GET", "application/json", request, 0, 0)

	if err != nil {
		return nil, nil, rawResponse, err
	}

	rawResponse = string(data)

	// Check if the response contains an API error
	if err := unmarshalAPIErrorResponse(data, httpResp, &apiErr); err != nil {
		return nil, nil, rawResponse, fmt.Errorf("failed to deserialize API error response: %w", err)
	}

	if !apiErr.Status {
		return nil, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
	}

	// Success case
	if apiErr.HttpStatusCode == types.CodeSuccess {
		err := json.Unmarshal(data, &successResp)
		if err != nil {
			return nil, &apiErr, rawResponse, fmt.Errorf("failed to deserialize API success response: %w", err)
		}
		return &successResp, &apiErr, rawResponse, nil
	}

	return nil, &apiErr, rawResponse, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
}
*/

// SessionStatus - get session status
func (a *API) SessionStatus(session string) (
	*types.SessionStatusResponse,
	*types.APIErrorResponse,
	error) {

	var resp types.SessionStatusResponse
	var apiErr types.APIErrorResponse

	request := &types.SessionStatusRequest{Session: session}

	data, httpResp, err := a.requestRaw(protocolTypes.IPvAny, _apiHost, _sessionStatusPath, "POST", "application/json", request, 0, 0)
	if err != nil {
		return nil, nil, err
	}

	// Check is it API error
	if err := unmarshalAPIErrorResponse(data, httpResp, &apiErr); err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize API response: %w", err)
	}

	if !apiErr.Status {
		return nil, &apiErr, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
	}

	// success
	if apiErr.HttpStatusCode == types.CodeSuccess {
		err := json.Unmarshal(data, &resp)
		resp.SetHttpStatusCode(apiErr.HttpStatusCode)
		if err != nil {
			return nil, &apiErr, fmt.Errorf("failed to deserialize API response: %w", err)
		}
		return &resp, &apiErr, nil
	}

	return nil, &apiErr, types.CreateAPIError(apiErr.HttpStatusCode, apiErr.Message)
}

func (a *API) DeviceList(session string) (deviceList *types.DeviceListResponse, err error) {
	request := &types.DeviceListRequest{SessionTokenStruct: types.SessionTokenStruct{SessionToken: session}}
	device := runtime.GOOS
	resp := &types.DeviceListResponse{}
	if err := a.request(_apiHost, _deviceListPath+"?search="+device+"&page=1&limit=100", "GET", "application/json", request, resp); err != nil {
		return nil, err
	}
	if resp.HttpStatusCode != types.CodeSuccess {
		return nil, types.CreateAPIError(resp.HttpStatusCode, resp.Message)
	}
	return resp, nil
}

func (a *API) ProfileData(session string) (
	resp *types.ProfileDataResponse,
	httpStatusCode int,
	err error,
) {
	request := &types.DeviceListRequest{SessionTokenStruct: types.SessionTokenStruct{SessionToken: session}}

	resp = &types.ProfileDataResponse{}
	if err := a.request(_apiHost, _profileDataPath, "GET", "application/json", request, resp); err != nil {
		return nil, 0, err
	}
	if resp.HttpStatusCode != types.CodeSuccess {
		return nil, resp.HttpStatusCode, types.CreateAPIError(resp.HttpStatusCode, resp.Message)
	}
	return resp, resp.HttpStatusCode, nil
}

func (a *API) SubscriptionData(session string) (
	resp *types.SubscriptionDataResponse,
	httpStatusCode int,
	err error,
) {
	request := &types.DeviceListRequest{SessionTokenStruct: types.SessionTokenStruct{SessionToken: session}}

	resp = &types.SubscriptionDataResponse{}
	if err := a.request(_apiHost, _subscriptionDataPath, "GET", "application/json", request, resp); err != nil {
		return nil, 0, err
	}
	if resp.HttpStatusCode != types.CodeSuccess {
		return nil, resp.HttpStatusCode, types.CreateAPIError(resp.HttpStatusCode, "Error fetching SubscriptionData API")
	}
	return resp, resp.HttpStatusCode, nil
}

// SessionDelete - remove session
func (a *API) SessionDelete(session string, deviceWGPublicKey string) error {

	// lookup internal device ID by the device Wireguard public key
	var deviceList *types.DeviceListResponse
	var err error
	if deviceList, err = a.DeviceList(session); err != nil {
		return fmt.Errorf("error fetching device list: %w", err)
	}

	internalDeviceID := 0
	for _, dev := range deviceList.Data.Rows {
		if dev.PublicKey == deviceWGPublicKey {
			internalDeviceID = dev.InternalID
			break
		}
	}
	if internalDeviceID == 0 {
		return errors.New("error - no devices with the given WG public key found under the current user")
	}

	request := &types.SessionDeleteRequest{Session: session}
	resp := &types.APIErrorResponse{}
	urlPath := fmt.Sprintf("%s/%d", _sessionDeletePath, internalDeviceID)
	if err := a.request(_apiHost, urlPath, "DELETE", "application/json", request, resp); err != nil {
		return err
	}
	if resp.HttpStatusCode != types.CodeSuccess {
		return types.CreateAPIError(resp.HttpStatusCode, resp.Message)
	}
	return nil
}

// WireGuardKeySet - update WG key
func (a *API) WireGuardKeySet(session string, newPublicWgKey string, activePublicWgKey string, kemKeys types.KemPublicKeys) (responseObj types.SessionsWireGuardResponse, err error) {
	request := &types.SessionWireGuardKeySetRequest{
		Session:            session,
		PublicKey:          newPublicWgKey,
		ConnectedPublicKey: activePublicWgKey,
		KemPublicKeys:      kemKeys,
	}

	resp := types.SessionsWireGuardResponse{}

	if err := a.request(_apiHost, _wgKeySetPath, "POST", "application/json", request, &resp); err != nil {
		return resp, err
	}

	if resp.HttpStatusCode != types.CodeSuccess {
		return resp, types.CreateAPIError(resp.HttpStatusCode, resp.Message)
	}

	return resp, nil
}

// GeoLookup gets geolocation
func (a *API) GeoLookup(timeoutMs int, ipTypeRequired protocolTypes.RequiredIPProtocol) (location *types.GeoLookupResponse, rawData []byte, retErr error) {
	// TODO: Vlad - disabled in MVP 1.0
	return nil, []byte{}, nil

	// There could be multiple Geolookup requests at the same time.
	// It doesn't make sense to make multiple requests to the API.
	// The internal function below reduces the number of similar API calls.
	singletonFunc := func(ipType protocolTypes.RequiredIPProtocol) (*types.GeoLookupResponse, []byte, error) {
		// Each IP protocol has separate request
		var gl *geolookup
		var httpResp *http.Response
		if ipType == protocolTypes.IPv4 {
			gl = &a.geolookupV4
		} else if ipType == protocolTypes.IPv6 {
			gl = &a.geolookupV6
		} else {
			return nil, nil, fmt.Errorf("geolookup request failed: IP version not defined")
		}
		// Try to make API request (if not started yet). Only one API request allowed in the same time.
		func() {
			gl.mutex.Lock()
			defer gl.mutex.Unlock()
			// if API call is already running - do nosing, just wait for results
			if gl.isRunning {
				return
			}
			// mark: call is already running
			gl.isRunning = true
			gl.done = make(chan struct{})
			// do API call in routine
			go func() {
				defer func() {
					// API call finished
					gl.isRunning = false
					close(gl.done)
				}()
				gl.response, httpResp, gl.err = a.requestRaw(ipType, _apiHost, _geoLookupPath, "GET", "", nil, timeoutMs, 0)
				err := json.Unmarshal(gl.response, &gl.location)
				if httpResp != nil {
					gl.location.SetHttpStatusCode(httpResp.StatusCode)
				}
				if err != nil {
					gl.err = fmt.Errorf("failed to deserialize API response: %w", err)
				}
			}()
		}()
		// wait for API call result (for routine stop)
		<-gl.done
		return &gl.location, gl.response, gl.err
	}

	// request Geolocation info
	if ipTypeRequired != protocolTypes.IPvAny {
		location, rawData, retErr = singletonFunc(ipTypeRequired)
	} else {
		location, rawData, retErr = singletonFunc(protocolTypes.IPv4)
		if retErr != nil {
			location, rawData, retErr = singletonFunc(protocolTypes.IPv6)
		}
	}

	if retErr != nil {
		return nil, nil, retErr
	}
	return location, rawData, nil
}
