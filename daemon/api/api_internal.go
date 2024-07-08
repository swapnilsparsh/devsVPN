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

package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"time"

	api_types "github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
)

type Response struct {
	Status        int                    `json:"status"`
	Token         string                 `json:"token"`
	VPNUsername   string                 `json:"vpn_username"`
	VPNPassword   string                 `json:"vpn_password"`
	ServiceStatus ServiceStatus          `json:"service_status"`
	Wireguard     map[string]interface{} `json:"wireguard"`
	DeviceName    string                 `json:"device_name"`
}

type ErrResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// ServiceStatus represents the structure of the service status object
type ServiceStatus struct {
	IsActive         bool     `json:"is_active"`
	ActiveUntil      int64    `json:"active_until"`
	CurrentPlan      string   `json:"current_plan"`
	PaymentMethod    string   `json:"payment_method"`
	IsRenewable      bool     `json:"is_renewable"`
	WillAutoRebill   bool     `json:"will_auto_rebill"`
	IsOnFreeTrial    bool     `json:"is_on_free_trial"`
	Capabilities     []string `json:"capabilities"`
	Upgradable       bool     `json:"upgradable"`
	UpgradeToPlan    string   `json:"upgrade_to_plan"`
	UpgradeToURL     string   `json:"upgrade_to_url"`
	DeviceManagement bool     `json:"device_management"`
}

func init() {
	log = logger.NewLogger("api-internal")
}

func getURL(host string, urlpath string) string {
	return "https://" + path.Join(host, urlpath)
}

func getURL_IPHost(ip net.IP, isIPv6 bool, urlpath string) string {
	if isIPv6 {
		return "https://" + path.Join("["+ip.String()+"]", urlpath)
	}
	return "https://" + path.Join(ip.String(), urlpath)
}

func newRequest(urlPath string, method string, contentType string, body io.Reader) (*http.Request, error) {
	if len(method) == 0 {
		method = "GET"
	}

	req, err := http.NewRequest(method, urlPath, body)
	if err != nil {
		return nil, err
	}

	if len(contentType) > 0 {
		req.Header.Add("Content-type", contentType)
	}

	return req, nil
}

func findPinnedKey(certHashes []string, certBase64hash256 string) bool {
	for _, hash := range certHashes {
		if hash == certBase64hash256 {
			return true
		}
	}
	return false
}

type dialer func(network, addr string) (net.Conn, error)

func makeDialer(certHashes []string, serverName string, dialTimeout time.Duration) dialer {
	if len(certHashes) == 0 {
		log.Warning("No pinned certificates for ", _apiHost)
		return nil
	}

	return func(network, addr string) (net.Conn, error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC (API request): ", r)
				if err, ok := r.(error); ok {
					log.ErrorTrace(err)
				}
			}
		}()

		tlsConfig := &tls.Config{
			// NOTE: Can't use SSLv3 because of POODLE and BEAST
			// NOTE: Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
			// NOTE: Can't use TLSv1.1 because of RC4 cipher usage
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		}

		c, err := tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, network, addr, tlsConfig)

		if err != nil {
			return c, err
		}

		return c, nil
		// connstate := c.ConnectionState()
		// var lastErr error = nil
		// for _, peercert := range connstate.PeerCertificates {
		// 	der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		// 	if err != nil {
		// 		lastErr = err
		// 		continue
		// 	}

		// 	hash := sha256.Sum256(der)
		// 	certBase64hash := base64.StdEncoding.EncodeToString(hash[:])

		// 	if err != nil {
		// 		log.Error(err)
		// 	}

		// 	if findPinnedKey(certHashes, certBase64hash) {
		// 		return c, nil // Pinned Key found
		// 	}

		// }
		// if lastErr != nil {
		// 	return nil, fmt.Errorf("certificate check error: pinned certificate key not found: %w", lastErr)
		// }
		// return nil, fmt.Errorf("certificate check error: pinned certificate key not found")
	}
}

func (a *API) doRequest(ipTypeRequired types.RequiredIPProtocol, host string, urlPath string, method string, contentType string, request api_types.RequestWithAuthorization, timeoutMs int, timeoutDialMs int) (resp []byte, err error) {
	connectivityChecker := a.connectivityChecker
	if connectivityChecker != nil {
		if err := connectivityChecker.IsConnectivityBlocked(); err != nil {
			return nil, err
		}
	}

	if len(host) == 0 || host == _apiHost {
		if ipTypeRequired != types.IPvAny {
			// The specific IP version required to use
			return a.doRequestAPIHost(ipTypeRequired, false, urlPath, method, contentType, request, timeoutMs, timeoutDialMs)
		} else {
			// No specific IP version required to use
			// Trying first to use IPv4, as fallback - try to use IPv6
			canUseDNS := true
			resp4, err4 := a.doRequestAPIHost(types.IPv4, canUseDNS, urlPath, method, contentType, request, timeoutMs, timeoutDialMs)
			if err4 != nil {
				// checking if IPv6 connectivity exists
				_, errIPv6 := netinfo.GetOutboundIP(true)
				if errIPv6 == nil && len(a.getAlternateIPs(true)) >= 0 {
					log.Info("Failed to access API server using IPv4. Trying IPv6 ...")
					canUseDNS = false // we already tried to access using DNS. No sense to try it again
					resp6, err6 := a.doRequestAPIHost(types.IPv6, canUseDNS, urlPath, method, contentType, request, timeoutMs, timeoutDialMs)
					if err6 == nil {
						return resp6, err6
					}
				}
			}
			return resp4, err4
		}

		// } else if host == _updateHost {
		// 	return a.doRequestUpdateHost(urlPath, method, contentType, request, timeoutMs)
	}
	return nil, fmt.Errorf("unknown host type")
}

func (a *API) doRequestUpdateHost(urlPath string, method string, contentType string, request interface{}, timeoutMs int) (resp *http.Response, err error) {
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // seems, it is redundant (since we use custom DialTLS)
			ServerName: _updateHost,      // despite, we using custom DialTLS, we have to define ServerName (this avoids certificate verification problems, for example, when the request is going through a proxy server)
		},

		// using certificate key pinning
		DialTLS: makeDialer(UpdateIvpnHashes, _updateHost, 0),
	}

	// configure http-client with preconfigured TLS transport
	timeout := _defaultRequestTimeout
	if timeoutMs > 0 {
		timeout = time.Millisecond * time.Duration(timeoutMs)
	}
	client := &http.Client{Transport: transCfg, Timeout: timeout}

	data := []byte{}
	if request != nil {
		data, err = json.Marshal(request)
		if err != nil {
			return nil, err
		}
	}

	bodyBuffer := bytes.NewBuffer(data)

	// try to access API server by host DNS
	req, err := newRequest(getURL(_updateHost, urlPath), method, contentType, bodyBuffer)
	if err != nil {
		return nil, err
	}

	resp, e := client.Do(req)
	if e != nil {
		log.Warning("Failed to access " + _updateHost)
		return resp, fmt.Errorf("unable to access IVPN repo server: %w", e)
	}

	return resp, nil
}

func setAuthTokenIfPresent(clientReq api_types.RequestWithAuthorization, httpReq *http.Request) {
	if clientReq != nil && clientReq.GetAuthenticationToken() != "" {
		authorizationToken := "Bearer " + clientReq.GetAuthenticationToken()
		//httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", authorizationToken)
	}
}

func (a *API) doRequestAPIHost(ipTypeRequired types.RequiredIPProtocol, isCanUseDNS bool, urlPath string, method string, contentType string, request api_types.RequestWithAuthorization, timeoutMs int, timeoutDialMs int) (resp []byte, err error) {
	isIPv6 := ipTypeRequired == types.IPv6

	// timeout time for full request
	timeout := _defaultRequestTimeout
	if timeoutMs > 0 {
		timeout = time.Millisecond * time.Duration(timeoutMs)
	}
	// timeout for the dial
	timeoutDial := _defaultDialTimeout
	if timeoutDialMs > 0 {
		timeoutDial = time.Millisecond * time.Duration(timeoutDialMs)
	}
	if timeoutDial > timeout {
		timeoutDial = 0
	}

	// When trying to access API server by alternate IPs (not by DNS name)
	// we need to configure TLS to use api.ivpn.net hostname
	// (to avoid certificate errors)
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // seems, it is redundant (since we use custom DialTLS)
			ServerName: _apiHost,         // despite, we using custom DialTLS, we have to define ServerName (this avoids certificate verification problems, for example, when the request is going through a proxy server)
		},

		// using certificate key pinning
		DialTLS: makeDialer(APIIvpnHashes, _apiHost, timeoutDial),
	}

	// configure http-client with preconfigured TLS transport
	client := &http.Client{Transport: transCfg, Timeout: timeout}

	data := []byte{}
	if request != nil {
		data, err = json.Marshal(request)
		if err != nil {
			return nil, err
		}
	}

	bodyBuffer := bytes.NewBuffer(data)

	// access API by last good IP (if defined)
	lastGoodIP := a.GetLastGoodAlternateIP(isIPv6)
	if lastGoodIP != nil {
		req, err := newRequest(getURL_IPHost(lastGoodIP, isIPv6, urlPath), method, contentType, bodyBuffer)
		if err != nil {
			return nil, err
		}
		setAuthTokenIfPresent(request, req)

		resp, err := client.Do(req)
		if err == nil {
			// return resp, nil
			responseBody, _ := io.ReadAll(resp.Body)
			return responseBody, nil
		}
		log.Debug(fmt.Sprintf("Bad API response for req %s: %v", req.URL, err))
	}

	// try to access API server by host DNS
	var firstResp *http.Response
	var firstErr error
	if isCanUseDNS {
		// req, err := newRequest(getURL(_apiHost, urlPath), method, contentType, bodyBuffer)
		var data map[string]string
		err := json.NewDecoder(bodyBuffer).Decode(&data)
		if err != nil {
			fmt.Println("Error decoding bodyBuffer:", err)
		}
		payload := map[string]string{
			"email":       data["email"],
			"password":    data["password"],
			"device_id":   data["device_id"],
			"device_name": data["device_name"],
			"public_key":  data["public_key"],
			"platform":    data["platform"],
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		// Create a bytes.Reader from the JSON bytes
		reader := bytes.NewReader(payloadBytes)
		req, err := newRequest(getURL(_apiHost, urlPath), method, contentType, reader)
		if err != nil {
			return nil, err
		}
		setAuthTokenIfPresent(request, req)

		firstResp, firstErr = client.Do(req)
		if firstErr == nil {
			// return firstResp, firstErr
			responseBody, _ := io.ReadAll(firstResp.Body)
			// Fixing not needed - instead we should parse the returned JSON in the normal parsing pipeline
			// reqResponseBody := fix_response_body(responseBody, firstResp.StatusCode)
			// return reqResponseBody, firstErr
			return responseBody, firstErr
		}
		log.Warning(fmt.Sprintf("Failed to access %s: %v", _apiHost, err))
	}

	isLogNotificationPrinted := false

	// try to access API server by alternate IP
	ips := a.getAlternateIPs(isIPv6)
	for _, ip := range ips {
		if ip.Equal(lastGoodIP) {
			continue
		}
		if firstErr != nil && !isLogNotificationPrinted {
			isLogNotificationPrinted = true

			ipVerStr := ""
			if ipTypeRequired == types.IPv6 {
				ipVerStr = "(IPv6)"
			}
			log.Info(fmt.Sprintf("Trying to use alternate API IPs %s...", ipVerStr))
		}

		req, err := newRequest(getURL_IPHost(ip, isIPv6, urlPath), method, contentType, bodyBuffer)
		if err != nil {
			return nil, err
		}
		setAuthTokenIfPresent(request, req)

		resp, err := client.Do(req)
		if err != nil {
			log.Debug(fmt.Sprintf("Bad API response for req %s: %v", req.URL, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		// save last good IP
		a.SetLastGoodAlternateIP(ip)

		log.Info("Success!")
		// return resp, err
		responseBody, err := io.ReadAll(resp.Body)
		return responseBody, err
	}

	return nil, fmt.Errorf("unable to access IVPN API server: %w", firstErr)
}

func fix_response_body(responseBody []byte, statusCode int) (reqResponseBody []byte) {
	jsonResponse := string(responseBody)

	// Unmarshal the provided JSON response into a map[string]interface{}
	var responseData map[string]interface{}
	err := json.Unmarshal([]byte(jsonResponse), &responseData)
	if err != nil {
		logger.Warning(fmt.Sprintf("fix_response_body: %s", err))
		return
	}

	// Extract necessary data from the response
	if statusCode == 200 {
		token := responseData["data"].(map[string]interface{})["token"].(string)
		logger.Debug("Session token: " + token)
		// Define the desired response structure
		response := Response{
			Status:      statusCode,
			Token:       token,
			VPNUsername: "sfHTNIU3n1p",
			VPNPassword: "6mmXcXRI6g",
			ServiceStatus: ServiceStatus{
				IsActive:         true,
				ActiveUntil:      1718508918,
				CurrentPlan:      "IVPN Pro",
				PaymentMethod:    "prepaid",
				IsRenewable:      true,
				WillAutoRebill:   false,
				IsOnFreeTrial:    false,
				Capabilities:     []string{"multihop", "port-forwarding"},
				Upgradable:       false,
				UpgradeToPlan:    "N.A.",
				UpgradeToURL:     "N.A.",
				DeviceManagement: false,
			},
			// TODO FIXME addr 172.24.237.187
			Wireguard: map[string]interface{}{
				"status":      200,
				"ip_address":  "172.24.237.187",
				"kem_cipher1": "T1VdW9PIBbTBArahADGQzi+ac1+d/XxKyY+K0tJMgkppNNLmgx3ox9bgks1pIDsGsWrn/6nM8peIvxQfaO+0KI64FyYZiZsoeQUyIjlYZddcCSO9eMYoHoB7i/98Q+0KVXDd6YfkprbdYCZ08IRPeSz170T2Nwd0pnQCdk7I/XYVTp26KsLkKHAnKmkZkpeyT6ydA+7/Pd/utHwe0o1cLziRmo6B7LGMsXPiVm3xAr2QesB9jDBvDngAHdMNL2hIQHYS",
			},
			DeviceName: "",
		}
		// Marshal the response into JSON byte slice
		responseJSON, err := json.Marshal(response)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		// Print the JSON byte slice
		return responseJSON
	} else {
		response := ErrResponse{
			Status:  statusCode,
			Message: responseData["message"].(string),
		}
		// Marshal the response into JSON byte slice
		responseJSON, err := json.Marshal(response)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		return responseJSON
	}
}

func (a *API) requestRaw(ipTypeRequired types.RequiredIPProtocol, host string, urlPath string, method string, contentType string, requestObject api_types.RequestWithAuthorization, timeoutMs int, timeoutDialMs int) (responseData []byte, err error) {
	resp, err := a.doRequest(ipTypeRequired, host, urlPath, method, contentType, requestObject, timeoutMs, timeoutDialMs)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	// if resp.StatusCode != 200 {
	// 	log.Debug(fmt.Sprintf("API response: (HTTP status code %d); status=%s", resp.StatusCode, resp.Status))
	// }
	return resp, nil
}

func (a *API) request(host string, urlPath string, method string, contentType string, requestObject api_types.RequestWithAuthorization, responseObject interface{}) error {
	return a.requestEx(host, urlPath, method, contentType, requestObject, responseObject, 0, 0)
}

func (a *API) requestEx(host string, urlPath string, method string, contentType string, requestObject api_types.RequestWithAuthorization, responseObject interface{}, timeoutMs int, timeoutDialMs int) error {
	body, err := a.requestRaw(types.IPvAny, host, urlPath, method, contentType, requestObject, timeoutMs, timeoutDialMs)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, responseObject); err != nil {
		return fmt.Errorf("failed to deserialize API response: %w", err)
	}

	return nil
}
