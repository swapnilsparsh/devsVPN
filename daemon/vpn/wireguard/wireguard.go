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

package wireguard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/dns"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
)

var log *logger.Logger

func init() {
	log = logger.NewLogger("wg")
}

// ConnectionParams contains all information to make new connection
type ConnectionParams struct {
	bearerToken          string
	clientLocalIP        net.IP
	clientPrivateKey     string
	clientPublicKey      string
	presharedKey         string
	hostPort             int
	hostIP               net.IP
	hostPublicKey        string
	hostLocalIP          net.IP
	ipv6Prefix           string
	multihopExitHostname string // (e.g.: "nl4.wg.ivpn.net") we need it only for informing clients about connection status
	mtu                  int    // Set 0 to use default MTU value
}

func (cp *ConnectionParams) GetIPv6ClientLocalIP() net.IP {
	if len(cp.ipv6Prefix) <= 0 {
		return nil
	}
	return net.ParseIP(cp.ipv6Prefix + cp.clientLocalIP.String())
}
func (cp *ConnectionParams) GetIPv6HostLocalIP() net.IP {
	if len(cp.ipv6Prefix) <= 0 {
		return nil
	}
	return net.ParseIP(cp.ipv6Prefix + cp.hostLocalIP.String())
}

// SetCredentials update WG credentials
func (cp *ConnectionParams) SetCredentials(sessionToken string, privateKey string, publicKey string, presharedKey string, localIP net.IP) {
	cp.bearerToken = sessionToken
	cp.clientPrivateKey = privateKey
	cp.clientPublicKey = publicKey
	cp.presharedKey = presharedKey
	cp.clientLocalIP = localIP
}

// CreateConnectionParams initializing connection parameters object
func CreateConnectionParams(
	multihopExitHostName string,
	hostPort int,
	hostIP net.IP,
	hostPublicKey string,
	hostLocalIP net.IP,
	ipv6Prefix string,
	mtu int) ConnectionParams {

	return ConnectionParams{
		multihopExitHostname: multihopExitHostName,
		hostPort:             hostPort,
		hostIP:               hostIP,
		hostPublicKey:        hostPublicKey,
		hostLocalIP:          hostLocalIP,
		ipv6Prefix:           ipv6Prefix,
		mtu:                  mtu,
	}
}

// WireGuard structure represents all data of wireguard connection
type WireGuard struct {
	binaryPath     string
	toolBinaryPath string
	configFilePath string
	connectParams  ConnectionParams
	localPort      int

	isDisconnected        bool
	isDisconnectRequested bool

	// Must be implemented (AND USED) in correspond file for concrete platform. Must contain platform-specified properties (or can be empty struct)
	internals internalVariables
}

// NewWireGuardObject creates new wireguard structure
func NewWireGuardObject(wgBinaryPath string, wgToolBinaryPath string, wgConfigFilePath string, connectionParams ConnectionParams) (*WireGuard, error) {
	if connectionParams.clientLocalIP == nil || len(connectionParams.clientPrivateKey) == 0 {
		return nil, fmt.Errorf("WireGuard local credentials not defined")
	}

	return &WireGuard{
		binaryPath:     wgBinaryPath,
		toolBinaryPath: wgToolBinaryPath,
		configFilePath: wgConfigFilePath,
		connectParams:  connectionParams}, nil
}

func (wg *WireGuard) GetTunnelName() string {
	return wg.getTunnelName()
}

// DestinationIP -  Get destination IP (VPN host server or proxy server IP address)
// This information if required, for example, to allow this address in firewall
func (wg *WireGuard) DestinationIP() net.IP {
	return wg.connectParams.hostIP
}
func (wg *WireGuard) DefaultDNS() net.IP {
	if wg.isDisconnected {
		return nil
	}

	return wg.internals.manualDNS.Ip()
}

// Type just returns VPN type
func (wg *WireGuard) Type() vpn.Type { return vpn.WireGuard }

// Init performs basic initializations before connection
// It is useful, for example:
//   - for WireGuard(Windows) - to ensure that WG service is fully uninstalled
//   - for OpenVPN(Linux) - to ensure that OpenVPN has correct version
func (wg *WireGuard) Init() error {
	return wg.init()
}

// Connect - SYNCHRONOUSLY execute openvpn process (wait until it finished)
func (wg *WireGuard) Connect(stateChan chan<- vpn.StateInfo) error {

	disconnectDescription := ""
	wg.isDisconnected = false
	wg.isDisconnectRequested = false
	stateChan <- vpn.NewStateInfo(vpn.CONNECTING, "")
	defer func() {
		wg.isDisconnected = true
		stateChan <- vpn.NewStateInfo(vpn.DISCONNECTED, disconnectDescription)
	}()

	err := func() error {
		// Check custom MTU value
		if wg.connectParams.mtu > 0 {
			// According to Windows specification: "... For IPv4 the minimum value is 576 bytes. For IPv6 the minimum is value is 1280 bytes... "
			// Using the same limitations for all platforms
			if wg.connectParams.mtu < 1280 || wg.connectParams.mtu > 65535 {
				return fmt.Errorf("bad MTU value (acceptable interval is: [1280 - 65535])")
			}
		}

		return wg.connect(stateChan)
	}()

	if err != nil {
		disconnectDescription = err.Error()
	}

	return err
}

// Disconnect stops the connection
func (wg *WireGuard) Disconnect() error {
	wg.isDisconnectRequested = true
	return wg.disconnect()
}

// IsPaused checking if we are in paused state
func (wg *WireGuard) IsPaused() bool {
	return wg.isPaused()
}

// Pause doing required operation for Pause (temporary restoring default DNS)
func (wg *WireGuard) Pause() error {
	// IMPORTANT! When the WG keys regenerated (see service.WireGuardSaveNewKeys()):
	// WireGuard 'pause/resume' state is based on complete VPN disconnection and restoring connection back (on all platforms)
	// If this will be changed (e.g. just changing routing) - it will be necessary to implement reconnection even in 'pause' state (when keys were regenerated)
	if ret := wg.pause(); ret != nil {
		return ret
	}

	// make this method synchronous: waiting until paused (until WG connection disappear)
	return <-WaitForDisconnectChan(wg.GetTunnelName(), []*bool{&wg.isDisconnectRequested, &wg.isDisconnected})
}

// Resume doing required operation for Resume (restores DNS configuration before Pause)
func (wg *WireGuard) Resume() error {
	if ret := wg.resume(); ret != nil {
		return ret
	}

	// make this method synchronous: waiting until paused (until WG connection disappear)
	return <-WaitForConnectChan(wg.GetTunnelName(), []*bool{&wg.isDisconnectRequested, &wg.isDisconnected})
}

// SetManualDNS changes DNS to manual IP
func (wg *WireGuard) SetManualDNS(dnsCfg dns.DnsSettings) error {
	return wg.setManualDNS(dnsCfg)
}

// ResetManualDNS restores DNS
func (wg *WireGuard) ResetManualDNS() error {
	return wg.resetManualDNS()
}

func (wg *WireGuard) generateAndSaveConfigFile(cfgFilePath string) error {
	cfg, err := wg.generateConfig()
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard configuration: %w", err)
	}

	// write configuration into temporary file
	configText := strings.Join(cfg, "\n")

	err = os.WriteFile(cfgFilePath, []byte(configText), 0600)
	if err != nil {
		return fmt.Errorf("failed to save WireGuard configuration into a file: %w", err)
	}

	configToLog := strings.ReplaceAll(configText, wg.connectParams.clientPrivateKey, "***")
	if len(wg.connectParams.presharedKey) > 0 {
		configToLog = strings.ReplaceAll(configToLog, wg.connectParams.presharedKey, "***")
	}
	log.Info("WireGuard  configuration:",
		"\n=====================\n",
		configToLog,
		"\n=====================\n")

	return nil
}

func Random64HexStr() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}

var ip4AddrRegex *regexp.Regexp = nil

func (wg *WireGuard) generateConfig() ([]string, error) {
	logger.Debug("================= generateConfig logs =======================")
	localPort, err := netinfo.GetFreeUDPPort()
	if err != nil {
		return nil, fmt.Errorf("unable to obtain free local port: %w", err)
	}

	wg.localPort = localPort

	// prevent user-defined data injection: ensure that nothing except the base64 public key will be stored in the configuration
	// if !helpers.ValidateBase64(wg.connectParams.hostPublicKey) {
	// 	return nil, fmt.Errorf("WG public key is not base64 string")
	// }
	// if !helpers.ValidateBase64(wg.connectParams.clientPrivateKey) {
	// 	return nil, fmt.Errorf("WG private key is not base64 string")
	// }
	// if len(wg.connectParams.presharedKey) > 0 && !helpers.ValidateBase64(wg.connectParams.presharedKey) {
	// 	return nil, fmt.Errorf("WG PresharedKey is not base64 string")
	// }

	// API call to Privateline to get connection parameters
	url := "https://api.privateline.io/connection/push-key"
	method := "POST"

	// Define the payload as a struct
	type Payload struct {
		DeviceID   string `json:"device_id"`
		DeviceName string `json:"device_name"`
		PublicKey  string `json:"public_key"`
		Platform   string `json:"platform"`
	}

	payload := Payload{
		DeviceID:   Random64HexStr(),
		DeviceName: "PL Connect - " + Random64HexStr(),
		PublicKey:  wg.connectParams.clientPublicKey,
		Platform:   runtime.GOOS,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create API request: %w", err)
	}
	// ++++++ Bearer token ++++
	authorizationToken := "Bearer " + wg.connectParams.bearerToken
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorizationToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute API request: %w", err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response: %w", err)
	}

	var response struct {
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

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("%s. Failed to parse API response: %w", res.Status, err)
	}

	logger.Debug(response.Status)
	log.Info("\n ++++++++++ Response data Connect API Start ( BUILD 02072024 0046) +++++++++++++++++ \n")
	logger.Debug(response.Data)
	log.Info("\n ++++++++++ Response data Connect API End +++++++++++++++++ \n")
	logger.Debug(response.Message)

	if !response.Status {
		return nil, fmt.Errorf("API error: %s", response.Message)
	}

	if len(response.Data) < 2 {
		return nil, fmt.Errorf("unexpected API response format")
	}

	interfaceAddress := response.Data[0].Interface.Address
	dnsServers := response.Data[0].Interface.DNS
	publicKey := response.Data[1].Peer.PublicKey
	// allowedIPs := response.Data[1].Peer.AllowedIPs
	endpoint := response.Data[1].Peer.Endpoint

	interfaceCfg := []string{
		"[Interface]",
		"PrivateKey = " + wg.connectParams.clientPrivateKey,
		"ListenPort = " + strconv.Itoa(wg.localPort),
		"Address = " + interfaceAddress,
		"DNS = " + dnsServers,
	}

	peerCfg := []string{
		"[Peer]",
		"PublicKey = " + publicKey,
		"Endpoint = " + endpoint,
		"AllowedIPs = " + "0.0.0.0/0",
		"PersistentKeepalive = 25",
	}

	logger.Debug("\n====================== Sandeep Interface and Peers Config Start =================\n")

	interfaceCfgPrivkeyStarred := []string{
		"[Interface]",
		"PrivateKey = ***",
		"ListenPort = " + strconv.Itoa(wg.localPort),
		"Address = " + interfaceAddress,
		"DNS = " + dnsServers,
	}
	logger.Debug(interfaceCfgPrivkeyStarred)

	logger.Debug(peerCfg)
	logger.Debug("\n====================== Sandeep Interface and Peers Config End ===================\n")

	// if len(wg.connectParams.presharedKey) > 0 {
	// 	peerCfg = append(peerCfg, "PresharedKey = "+wg.connectParams.presharedKey)
	// }
	// add some OS-specific configurations (if necessary)
	// iCfg, pCfg := wg.getOSSpecificConfigParams()
	// interfaceCfg = append(interfaceCfg, iCfg...)
	// peerCfg = append(peerCfg, pCfg...)

	logger.Debug("============== generateConfig logs end =======================")

	if ip4AddrRegex == nil {
		ip4AddrRegex, _ = regexp.Compile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	}
	if ip4AddrRegex != nil {
		// TODO FIXME: setting client local IP here for now
		interfaceAddressOnly := ip4AddrRegex.FindString(interfaceAddress)
		if interfaceAddressOnly != "" {
			wg.connectParams.clientLocalIP = net.ParseIP(interfaceAddressOnly)
		}

		// TODO FIXME: setting manual DNS to the 1st returned DNS
		firstDnsSrv := ip4AddrRegex.FindString(dnsServers)
		if firstDnsSrv != "" {
			wg.setManualDNS(dns.DnsSettings{DnsHost: firstDnsSrv})
		}
	}

	return append(interfaceCfg, peerCfg...), nil
}

func (wg *WireGuard) waitHandshakeAndNotifyConnected(stateChan chan<- vpn.StateInfo) error {
	log.Info("Initialised")

	// Notify: interface initialised
	wg.notifyInitialisedStat(stateChan)

	// Check connectivity: wait for first handshake
	// function returns only when handshake received or wg.isDisconnectRequested == true
	err := <-WaitForWireguardFirstHanshakeChan(wg.GetTunnelName(), []*bool{&wg.isDisconnectRequested, &wg.isDisconnected}, func(mes string) { log.Info(mes) })
	if err != nil {
		return err
	}

	if !wg.isDisconnectRequested && !wg.isDisconnected {
		log.Info("Connected")
		wg.notifyConnectedStat(stateChan)
	}

	return nil
}

func (wg *WireGuard) newStateInfoConnected() vpn.StateInfo {
	const isTCP = false

	si := vpn.NewStateInfoConnected(
		isTCP,
		wg.connectParams.clientLocalIP,
		wg.connectParams.GetIPv6ClientLocalIP(),
		wg.localPort,
		wg.connectParams.hostIP,
		wg.connectParams.hostPort,
		wg.connectParams.mtu)

	si.ExitHostname = wg.connectParams.multihopExitHostname
	return si
}

func (wg *WireGuard) notifyConnectedStat(stateChan chan<- vpn.StateInfo) {
	stateChan <- wg.newStateInfoConnected()
}

func (wg *WireGuard) notifyInitialisedStat(stateChan chan<- vpn.StateInfo) {
	si := wg.newStateInfoConnected()
	si.State = vpn.INITIALISED
	stateChan <- si
}

func (wg *WireGuard) OnRoutingChanged() error {
	return wg.onRoutingChanged()
}

func (wg *WireGuard) IsIPv6InTunnel() bool {
	return len(wg.connectParams.GetIPv6ClientLocalIP()) > 0
}
